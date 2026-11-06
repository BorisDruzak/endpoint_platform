"""Installation defaults are a one-shot intent, never a runtime assertion."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_contracts.support_access import SupportRegistration, SupportStatusReport
from endpoint_server.config import Settings
from endpoint_server.db.models import AuditEvent, Device, DeviceCredential
from endpoint_server.support_access.models import SupportAccess
from endpoint_server.support_access import service
from tests.contracts.test_support_access import key
from tests.server.test_config import _environment
from tests.server.test_support_access import identity
from tests.server.test_update_agent_api import _settings


def configured(tmp_path, **changes):
    return replace(_settings(tmp_path), support_install_auto_enable=True,
        support_install_operator_public_keys=(key(50),),
        support_install_windows_admin_username=r'SOSNADM\admin-2',
        support_install_access_hours=8, support_gateway_host_public_key=key(51), **changes)


def test_environment_explicit_install_defaults_and_disabled_default(tmp_path):
    values = _environment(tmp_path)
    assert getattr(Settings.from_environment(values), 'support_install_auto_enable', False) is False
    values.update(SUPPORT_INSTALL_AUTO_ENABLE='true', SUPPORT_INSTALL_OPERATOR_PUBLIC_KEYS=key(50),
        SUPPORT_INSTALL_WINDOWS_ADMIN_USERNAME=r'SOSNADM\admin-2', SUPPORT_INSTALL_ACCESS_HOURS='8',
        SUPPORT_GATEWAY_HOST_PUBLIC_KEY=key(51))
    settings = Settings.from_environment(values)
    assert getattr(settings, 'support_install_auto_enable', False) is True
    assert settings.support_install_windows_admin_username == r'sosnadm\admin-2'
    assert settings.support_install_operator_public_keys == (key(50),)


@pytest.mark.parametrize('changes', [
    {'support_install_operator_public_keys': ()},
    {'support_install_operator_public_keys': (key(50), key(50))},
    {'support_install_operator_public_keys': ('invalid',)},
    {'support_install_operator_public_keys': (key(51),)},
    {'support_install_windows_admin_username': ''},
    {'support_install_windows_admin_username': 'admin@example.test'},
    {'support_install_access_hours': 0}, {'support_install_access_hours': 8.01},
    {'support_install_access_hours': float('nan')}, {'support_install_access_hours': float('inf')},
    {'support_install_access_hours': True}, {'support_gateway_host': 'other.example'},
    {'support_gateway_port': 22}, {'support_gateway_host_public_key': ''},
    {'support_install_auto_enable': 'true'},
])
def test_direct_configuration_rejects_invalid_automatic_authority(tmp_path, changes):
    base = configured(tmp_path)
    with pytest.raises(ValueError):
        replace(base, **changes)


@pytest.fixture
async def sessions():
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    async with engine.begin() as conn:
        await conn.run_sync(lambda sync: Device.metadata.create_all(sync, tables=[
            Device.__table__, DeviceCredential.__table__, SupportAccess.__table__, AuditEvent.__table__]))
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def registration(a=1):
    return SupportRegistration(tunnel_public_key=key(a), host_public_key=key(a+1), component_version='1.0.1')


@pytest.mark.asyncio
async def test_real_registration_queues_disabled_then_runtime_consumes_once(sessions, tmp_path):
    settings = configured(tmp_path)
    now = datetime.now(UTC)
    async with sessions() as s:
        d, c = await identity(s)
        row = await service.register(s, d.id, c.id, registration(), settings=settings, now=now)
        assert row.enabled is False and row.component_version == '1.0.0' and row.installed is False
        assert row.installation_access_pending_until == now + timedelta(minutes=15)
        assert row.operator_public_keys == [key(50)] and row.windows_admin_username == r'sosnadm\admin-2'
        await service.register(s, d.id, c.id, registration(), settings=settings, now=now+timedelta(minutes=2))
        assert row.installation_access_pending_until == now + timedelta(minutes=15)
        at = now + timedelta(minutes=3)
        service.record_runtime_status(row, SupportStatusReport(installed=True, tunnel_connected=False, component_version='1.0.1'), at)
        await service.consume_installation_access(s, row, settings, at)
        assert row.enabled and row.revision == 2 and row.expires_at == at+timedelta(hours=8)
        assert row.installation_access_pending_until is None
        await service.consume_installation_access(s, row, settings, at+timedelta(minutes=4))
        await service.register(s, d.id, c.id, registration(), settings=settings, now=at+timedelta(minutes=4))
        assert row.expires_at == at+timedelta(hours=8)
        actions = (await s.scalars(select(AuditEvent.action))).all()
        assert actions.count('support_access.installation_access_pending') == 1
        assert actions.count('support_access.installation_access_granted') == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('report', [
    SupportStatusReport(installed=True, tunnel_connected=False),
    SupportStatusReport(installed=False, tunnel_connected=False, component_version='1.0.1'),
    SupportStatusReport(installed=True, tunnel_connected=False, component_version='1.0.1', last_error_code='service_failed'),
])
async def test_legacy_uninstalled_and_error_status_never_grant(sessions, tmp_path, report):
    now = datetime.now(UTC)
    async with sessions() as s:
        d, c = await identity(s)
        settings = configured(tmp_path)
        row = await service.register(s, d.id, c.id, registration(), settings=settings, now=now)
        service.record_runtime_status(row, report, now)
        await service.consume_installation_access(s, row, settings, now)
        assert not row.enabled and row.installation_access_pending_until is not None


@pytest.mark.asyncio
@pytest.mark.parametrize('changed', ['expired', 'disabled', 'keys', 'principal', 'duration', 'gateway', 'source'])
async def test_expired_or_changed_authority_disarms_permanently(sessions, tmp_path, changed):
    now = datetime.now(UTC)
    async with sessions() as s:
        d, c = await identity(s)
        settings = configured(tmp_path)
        row = await service.register(s, d.id, c.id, registration(), settings=settings, now=now)
        if changed == 'disabled': settings = replace(settings, support_install_auto_enable=False)
        if changed == 'keys': settings = replace(settings, support_install_operator_public_keys=(key(52),))
        if changed == 'principal': settings = replace(settings, support_install_windows_admin_username='localadmin')
        if changed == 'duration': settings = replace(settings, support_install_access_hours=1)
        if changed == 'gateway': settings = replace(settings, support_gateway_host_public_key=key(53))
        if changed == 'source': c.revoked_at = now
        at = now+timedelta(minutes=16) if changed == 'expired' else now
        service.record_runtime_status(row, SupportStatusReport(installed=True, tunnel_connected=False, component_version='1.0.1'), at)
        await service.consume_installation_access(s, row, settings, at)
        assert not row.enabled and row.installation_access_pending_until is None and row.revision > 1
        if changed != 'source':
            await service.register(s, d.id, c.id, registration(), settings=configured(tmp_path), now=at)
            assert row.installation_access_pending_until is None
        actions = (await s.scalars(select(AuditEvent.action))).all()
        assert any(a in actions for a in ['support_access.installation_access_expired', 'support_access.installation_access_cancelled'])


@pytest.mark.asyncio
@pytest.mark.parametrize('manual', ['revision', 'keys', 'principal', 'expiry', 'revoked', 'reset'])
async def test_nonpristine_registration_never_arms_defaults(sessions, tmp_path, manual):
    now = datetime.now(UTC)
    async with sessions() as s:
        d, c = await identity(s)
        row = await service.register(s, d.id, c.id, registration())
        if manual == 'revision': row.revision = 2
        if manual == 'keys': row.operator_public_keys = [key(55)]
        if manual == 'principal': row.windows_admin_username = 'localadmin'
        if manual == 'expiry': row.expires_at = now+timedelta(hours=1)
        if manual == 'revoked': row.revoked_at = now
        if manual == 'reset': row.reset_registration_allowed = True
        if manual in ('revoked', 'reset'):
            with pytest.raises(service.SupportConflict):
                await service.register(s, d.id, c.id, registration(), settings=configured(tmp_path), now=now)
        else:
            await service.register(s, d.id, c.id, registration(), settings=configured(tmp_path), now=now)
        assert row.installation_access_pending_until is None


@pytest.mark.asyncio
@pytest.mark.parametrize('role', ['operator', 'gateway'])
async def test_configured_roles_reserved_from_registration(sessions, tmp_path, role):
    async with sessions() as s:
        d, c = await identity(s)
        body = SupportRegistration(tunnel_public_key=key(50 if role=='operator' else 51), host_public_key=key(2), component_version='1.0.1')
        with pytest.raises(service.SupportConflict):
            await service.register(s, d.id, c.id, body, settings=configured(tmp_path))


@pytest.mark.asyncio
async def test_existing_device_key_blocks_default_queue_without_failing_registration(sessions, tmp_path):
    async with sessions() as s:
        d, c = await identity(s)
        await service.register(s, d.id, c.id, registration(50))
        other, oc = await identity(s)
        row = await service.register(s, other.id, oc.id, registration(3), settings=configured(tmp_path))
        assert not row.enabled and row.installation_access_pending_until is None and row.revision > 1
        assert 'support_access.installation_access_default_conflict' in (await s.scalars(select(AuditEvent.action))).all()


@pytest.mark.asyncio
async def test_authenticated_routes_queue_then_grant_and_unregister_cancels(sessions, tmp_path):
    import httpx
    from endpoint_server.db.models import DeviceBindingThrottle
    from endpoint_server.enrollment.credentials import device_token_digest
    from endpoint_server.main import create_app
    settings = configured(tmp_path)
    async with sessions() as s:
        await (await s.connection()).run_sync(lambda conn: DeviceBindingThrottle.__table__.create(conn))
        d, c = await identity(s)
        c.token_digest = device_token_digest('x'*43, settings.device_token_pepper)
        await s.commit()
        device_id = d.id
    app = create_app(settings, sessions)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('127.0.0.1', 12345)), base_url=settings.public_base_url) as client:
        registered = await client.post('/agent/v1/support-access/register', headers={'Authorization': 'Bearer '+'x'*43}, json=registration().model_dump())
        assert registered.status_code == 200, registered.text
        assert not registered.json()['policy']['enabled']
        async with sessions() as s:
            row = await s.scalar(select(SupportAccess).where(SupportAccess.device_id == device_id))
            assert row.installation_access_pending_until is not None
            assert row.component_version == '1.0.0' and not row.installed
        headers = {'Authorization': 'Bearer '+registered.json()['support_token']}
        legacy = await client.post('/agent/v1/support-access/status', headers=headers, json={'installed': True, 'tunnel_connected': False})
        assert legacy.status_code == 200 and not legacy.json()['enabled']
        healthy = await client.post('/agent/v1/support-access/status', headers=headers, json={'installed': True, 'tunnel_connected': False, 'component_version': '1.0.1'})
        assert healthy.status_code == 200 and healthy.json()['enabled']
        expiry = healthy.json()['expires_at']
        replay = await client.post('/agent/v1/support-access/status', headers=headers, json={'installed': True, 'tunnel_connected': False, 'component_version': '1.0.1'})
        assert service.utc(datetime.fromisoformat(replay.json()['expires_at'])) == datetime.fromisoformat(expiry)
        assert (await client.post('/agent/v1/support-access/unregister', headers=headers)).status_code == 204
        async with sessions() as s:
            row = await s.scalar(select(SupportAccess).where(SupportAccess.device_id == device_id))
            assert row.revoked_at is not None and not row.enabled and row.installation_access_pending_until is None


@pytest.mark.asyncio
@pytest.mark.parametrize('fault', ['missing', 'duplicate', 'revision', 'deadline'])
async def test_unbound_or_ambiguous_pending_audit_fails_closed(sessions, tmp_path, fault):
    from endpoint_server.support_access.installation import installation_audit
    now = datetime.now(UTC)
    async with sessions() as s:
        d, c = await identity(s)
        settings = configured(tmp_path)
        row = await service.register(s, d.id, c.id, registration(), settings=settings, now=now)
        if fault == 'missing':
            # Discard the uncommitted audit, emulating missing binding evidence.
            for obj in tuple(s.new):
                if isinstance(obj, AuditEvent): s.expunge(obj)
        if fault == 'duplicate':
            event = next(obj for obj in s.new if isinstance(obj, AuditEvent))
            await installation_audit(s, row, 'pending', details=event.details)
        if fault == 'revision': row.revision += 1
        if fault == 'deadline': row.installation_access_pending_until += timedelta(seconds=1)
        service.record_runtime_status(row, SupportStatusReport(installed=True, tunnel_connected=False, component_version='1.0.1'), now)
        await service.consume_installation_access(s, row, settings, now)
        assert not row.enabled and row.installation_access_pending_until is None


@pytest.mark.asyncio
async def test_old_status_and_heartbeat_cannot_arm_or_consume_intent(sessions, tmp_path):
    now = datetime.now(UTC)
    async with sessions() as s:
        d, c = await identity(s)
        settings = configured(tmp_path)
        row = await service.register(s, d.id, c.id, registration())
        service.record_runtime_status(row, SupportStatusReport(installed=True, tunnel_connected=False, component_version='1.0.1'), now)
        await service.consume_installation_access(s, row, settings, now)
        assert not row.enabled and row.installation_access_pending_until is None
        await service.register(s, d.id, c.id, registration(), settings=settings, now=now)
        row.reported_at = now-timedelta(seconds=91)
        await service.consume_installation_access(s, row, settings, now)
        assert not row.enabled and row.installation_access_pending_until is not None
