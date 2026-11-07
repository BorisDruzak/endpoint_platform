"""Console discovery is provider evidence, never a user-supplied OS label."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from endpoint_server.auth.admin_sessions import require_admin
from endpoint_server.context.models import ContextSnapshot
from tests.contracts.test_support_access import key
from tests.server.test_linux_support_lifecycle import sessions, identity, registration
from tests.server.test_update_agent_api import _settings


@pytest.mark.parametrize('platform', ['linux', 'windows'])
async def test_platform_discovery_requires_agreeing_persisted_evidence(sessions, tmp_path, platform):
    from endpoint_server.support_access.discovery import router
    async with sessions() as session:
        principal = await identity(session, platform)
        await session.commit()
    app = FastAPI()
    app.include_router(router)
    app.state.session_provider = sessions
    path = f'/api/admin/support-access/devices/{principal.device.id}/platform'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://test') as client:
        assert (await client.get(path)).status_code == 401
        app.dependency_overrides[require_admin] = lambda: SimpleNamespace()
        response = await client.get(path)
        assert response.status_code == 200, response.text
        assert response.headers['cache-control'] == 'no-store'
        assert response.json() == {'device_id': str(principal.device.id), 'platform': platform + '_amd64'}
        async with sessions() as session:
            snapshot = await session.scalar(select(ContextSnapshot))
            snapshot.normalized_projection = {**snapshot.normalized_projection, 'sections': {
                **snapshot.normalized_projection['sections'], 'system': {
                    'platform': 'windows' if platform == 'linux' else 'linux', 'architecture': 'x86_64'}}}
            await session.commit()
        assert (await client.get(path)).json()['platform'] is None


def test_linux_staging_gateway_is_explicit_and_same_environment(tmp_path):
    settings = _settings(tmp_path)
    staging = dict(public_base_url='https://endpoint-staging.sosnadmin.local',
                   support_gateway_host='endpoint-staging.sosnadmin.local',
                   support_linux_staging_gateway_enabled=True)
    assert replace(settings, **staging).linux_support_gateway_configured()
    for change in ({'public_base_url': 'https://endpoint.sosnadmin.local'},
                   {'support_gateway_host': 'endpoint.sosnadmin.local'},
                   {'support_gateway_host': 'other.example'}, {'support_gateway_port': 2223},
                   {'support_linux_staging_gateway_enabled': 'true'}):
        with pytest.raises(ValueError):
            replace(settings, **(staging | change))
    assert not replace(settings, **(staging | {'support_linux_staging_gateway_enabled': False})).linux_support_gateway_configured()
    # A staging origin must never advertise the production gateway, including
    # when the positive staging opt-in was accidentally omitted.
    mixed = replace(settings, public_base_url='https://endpoint-staging.sosnadmin.local')
    assert not mixed.linux_support_gateway_configured()
    with pytest.raises(ValueError):
        replace(settings, **staging, support_install_auto_enable=True,
                support_install_operator_public_keys=(key(50),), support_install_windows_admin_username='admin',
                support_gateway_host_public_key=key(51))


async def test_linux_admin_distinguishes_stored_intent_and_effective_disabled_policy(sessions, tmp_path):
    from endpoint_server.support_access.linux_routes import admin_router
    from endpoint_server.support_access.service import register
    async with sessions() as session:
        principal = await identity(session)
        row = await register(session, principal.device.id, principal.credential.id, registration(), platform='linux_amd64')
        row.enabled = True
        row.expires_at = datetime.now(UTC) + timedelta(hours=1)
        row.linux_admin_username = 'root'; row.linux_admin_uid = 0; row.operator_public_keys = [key(50)]
        await session.commit()
    app = FastAPI()
    app.include_router(admin_router)
    app.state.session_provider = sessions
    app.state.settings = replace(_settings(tmp_path), support_gateway_host_public_key=key(51))
    app.dependency_overrides[require_admin] = lambda: SimpleNamespace()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://test') as client:
        response = await client.get(f'/api/admin/support-access/linux/devices/{principal.device.id}')
        assert response.status_code == 200, response.text
        body = response.json()
        assert body['policy']['enabled'] is False
        assert body['policy']['linux_admin_uid'] is None
        assert body['configured_policy']['enabled'] is True
        assert body['configured_policy']['linux_admin_uid'] == 0
        assert body['configured_policy']['operator_public_keys'] == [key(50)]
        assert not {'support_token', 'source_credential_id', 'generation', 'windows_admin_username'} & body.keys()


def test_gateway_environment_loader_retains_all_original_staging_gates(tmp_path):
    from endpoint_server.config import Settings
    from tests.server.test_config import _environment
    values = _environment(tmp_path)
    values.update(PUBLIC_BASE_URL='https://endpoint-staging.sosnadmin.local',
                  ENDPOINT_DEPLOYMENT_ENVIRONMENT='staging', CANARY_ENVIRONMENT='staging', CANARY_APPROVED='true',
                  SUPPORT_GATEWAY_HOST='endpoint-staging.sosnadmin.local', SUPPORT_LINUX_STAGING_GATEWAY_ENABLED='true')
    assert Settings.from_environment(values).linux_support_gateway_configured()
    for gate in ('CANARY_ENVIRONMENT', 'CANARY_APPROVED', 'ENDPOINT_DEPLOYMENT_ENVIRONMENT'):
        with pytest.raises(ValueError):
            Settings.from_environment({name: value for name, value in values.items() if name != gate})


async def test_staging_opt_in_only_enables_linux_projection_and_keeps_gateway_key_roles(sessions, tmp_path):
    from endpoint_server.support_access.linux_routes import policy as linux_policy
    from endpoint_server.support_access.routes import policy as windows_policy
    from endpoint_server.support_access.service import register, SupportConflict, record_runtime_status
    from endpoint_contracts.linux_support_access import LinuxSupportStatusReport
    from endpoint_contracts.support_access import SupportRegistration
    settings = replace(_settings(tmp_path), public_base_url='https://endpoint-staging.sosnadmin.local',
        support_gateway_host='endpoint-staging.sosnadmin.local', support_gateway_host_public_key=key(51),
        support_linux_staging_gateway_enabled=True)
    async with sessions() as session:
        principal = await identity(session)
        for role in ('tunnel_public_key', 'host_public_key'):
            with pytest.raises(SupportConflict):
                await register(session, principal.device.id, principal.credential.id,
                    registration().model_copy(update={role: key(51)}), platform='linux_amd64', settings=settings)
        row = await register(session, principal.device.id, principal.credential.id, registration(), platform='linux_amd64', settings=settings)
        row.enabled = True; row.expires_at = datetime.now(UTC) + timedelta(hours=1)
        row.linux_admin_username = 'root'; row.linux_admin_uid = 0; row.operator_public_keys = [key(50)]
        record_runtime_status(row, LinuxSupportStatusReport(installed=True, tunnel_connected=True, component_version='1.0.0'), datetime.now(UTC))
        assert (await linux_policy(session, row, settings)).enabled
        assert not (await linux_policy(session, row, replace(settings, support_linux_staging_gateway_enabled=False))).enabled
        win = await identity(session, 'windows')
        windows = await register(session, win.device.id, win.credential.id,
            SupportRegistration(tunnel_public_key=key(11), host_public_key=key(12), component_version='1.0.1'), settings=settings)
        windows.enabled = True; windows.expires_at = row.expires_at
        windows.windows_admin_username = 'admin'; windows.operator_public_keys = [key(50)]
        assert not (await windows_policy(session, windows, settings)).enabled
    with pytest.raises(ValueError):
        replace(settings, support_linux_install_operator_public_keys=(key(51),))
