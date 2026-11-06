"""Real PostgreSQL route transactions, row races and additive migration evidence."""
import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from alembic import command
from sqlalchemy import select, text

from endpoint_server.auth.admin_sessions import ADMIN_SESSION_COOKIE, issue_admin_session
from endpoint_server.db.models import AdminUser, AuditEvent, Device, DeviceCredential
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.enrollment.credentials import device_token_digest
from endpoint_server.main import create_app
from endpoint_server.support_access.models import SupportAccess
from tests.server.test_support_install_access import configured, registration
from tests.server.test_update_postgresql import update_migration_database_urls, _alembic_config

pytestmark = pytest.mark.usefixtures('preserve_migration_loggers')


async def seed(provider, settings):
    async with provider() as s:
        device = Device(device_identifier=uuid4().hex)
        s.add(device)
        await s.flush()
        token = uuid4().hex + uuid4().hex
        s.add(DeviceCredential(device_id=device.id, credential_identifier='initial',
            token_digest=device_token_digest(token, settings.device_token_pepper)))
        admin = AdminUser(username=uuid4().hex, password_digest='test-only', scopes=['updates:write'])
        s.add(admin)
        await s.flush()
        issued = issue_admin_session(admin.id, settings.session_secret)
        s.add(issued.record)
        await s.commit()
        return device.id, token, issued


def test_actual_registration_and_two_independent_status_transactions_grant_once(update_migration_database_urls, tmp_path):
    url, _ = update_migration_database_urls
    command.upgrade(_alembic_config(url), 'head')

    async def scenario():
        provider = AsyncSessionProvider(url)
        try:
            settings = configured(tmp_path)
            device_id, token, _ = await seed(provider, settings)
            app = create_app(settings, provider)
            transport = httpx.ASGITransport(app=app, client=('127.0.0.1', 12345))
            async with httpx.AsyncClient(transport=transport, base_url=settings.public_base_url) as client:
                auth = {'Authorization': 'Bearer '+token}
                result = await client.post('/agent/v1/support-access/register', headers=auth, json=registration(60).model_dump())
                assert result.status_code == 200, result.text
                assert not result.json()['policy']['enabled']
                headers = {'Authorization': 'Bearer '+result.json()['support_token']}
                async with provider() as s:
                    row = await s.scalar(select(SupportAccess).where(SupportAccess.device_id == device_id))
                    deadline = row.installation_access_pending_until
                    assert deadline is not None and not row.installed and row.component_version == '1.0.0'
                retry = await client.post('/agent/v1/support-access/register', headers=auth, json=registration(60).model_dump())
                assert retry.status_code == 200
                async with provider() as s:
                    row = await s.scalar(select(SupportAccess).where(SupportAccess.device_id == device_id))
                    assert row.installation_access_pending_until == deadline
                assert (await client.post('/agent/v1/support-access/status', headers=auth,
                    json={'installed': True, 'tunnel_connected': False, 'component_version': '1.0.1'})).status_code == 401
                body = {'installed': True, 'tunnel_connected': False, 'component_version': '1.0.1'}
                # Every HTTP request opens its own AsyncSession; both compete on
                # the actual row lock and share no mutable transaction/session.
                reports = await asyncio.gather(*(client.post('/agent/v1/support-access/status', headers=headers, json=body) for _ in range(2)))
                assert all(r.status_code == 200 and r.json()['enabled'] for r in reports)
                expiry = reports[0].json()['expires_at']
                assert reports[1].json()['expires_at'] == expiry
                replay = await client.post('/agent/v1/support-access/status', headers=headers, json=body)
                assert replay.json()['expires_at'] == expiry
                async with provider() as s:
                    row = await s.scalar(select(SupportAccess).where(SupportAccess.device_id == device_id))
                    assert row.revision == 2 and row.enabled and row.installation_access_pending_until is None
                    assert datetime.now(UTC) < row.expires_at <= datetime.now(UTC)+timedelta(hours=8)
                    actions = (await s.scalars(select(AuditEvent.action).where(AuditEvent.object_identifier == str(row.id)))).all()
                    assert actions.count('support_access.installation_access_pending') == 1
                    assert actions.count('support_access.installation_access_granted') == 1
        finally:
            await provider.close()
    asyncio.run(scenario())


@pytest.mark.parametrize('operation', ['disable', 'revoke', 'reset-registration', 'unregister'])
def test_manual_cancellation_races_status_and_cannot_be_rearmed(update_migration_database_urls, tmp_path, operation):
    url, _ = update_migration_database_urls
    command.upgrade(_alembic_config(url), 'head')

    async def scenario():
        provider = AsyncSessionProvider(url)
        try:
            settings = configured(tmp_path)
            device_id, token, issued = await seed(provider, settings)
            app = create_app(settings, provider)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('127.0.0.1', 12345)), base_url=settings.public_base_url) as client:
                auth = {'Authorization': 'Bearer '+token}
                index = {'disable': 70, 'revoke': 72, 'reset-registration': 74, 'unregister': 76}[operation]
                result = await client.post('/agent/v1/support-access/register', headers=auth, json=registration(index).model_dump())
                assert result.status_code == 200, result.text
                headers = {'Authorization': 'Bearer '+result.json()['support_token']}
                client.cookies.set(ADMIN_SESSION_COOKIE, issued.token)
                csrf = {'X-CSRF-Token': issued.csrf_token}
                body = {'installed': True, 'tunnel_connected': False, 'component_version': '1.0.1'}
                endpoint = f'/api/admin/support-access/devices/{device_id}'
                if operation == 'disable':
                    manual = client.put(endpoint+'/policy', headers=csrf, json={'enabled': False, 'reason': 'Explicit isolated disable'})
                elif operation == 'unregister':
                    manual = client.post('/agent/v1/support-access/unregister', headers=headers)
                else:
                    manual = client.post(endpoint+'/'+operation, headers=csrf, json={'reason': 'Explicit isolated cancellation'})
                status, cancellation = await asyncio.gather(client.post('/agent/v1/support-access/status', headers=headers, json=body), manual)
                assert status.status_code in (200, 401), status.text
                assert cancellation.status_code == (200 if operation == 'disable' else 204), cancellation.text
                async with provider() as s:
                    row = await s.scalar(select(SupportAccess).where(SupportAccess.device_id == device_id))
                    revision = row.revision
                    assert revision >= 2 and not row.enabled and row.installation_access_pending_until is None
                replay = await client.post('/agent/v1/support-access/status', headers=headers, json=body)
                assert replay.status_code in (200, 401)
                if operation == 'disable':
                    retried = await client.post('/agent/v1/support-access/register', headers=auth, json=registration(index).model_dump())
                    assert retried.status_code == 200 and not retried.json()['policy']['enabled']
                async with provider() as s:
                    row = await s.scalar(select(SupportAccess).where(SupportAccess.device_id == device_id))
                    assert row.revision == revision and not row.enabled and row.installation_access_pending_until is None
        finally:
            await provider.close()
    asyncio.run(scenario())


def test_nullable_migration_roundtrip_preserves_existing_rows(update_migration_database_urls):
    url, _ = update_migration_database_urls
    cfg = _alembic_config(url)
    command.upgrade(cfg, 'head')

    async def populate():
        from endpoint_server.support_access.service import register
        provider = AsyncSessionProvider(url)
        try:
            async with provider() as s:
                d = Device(device_identifier=uuid4().hex)
                s.add(d)
                await s.flush()
                c = DeviceCredential(device_id=d.id, credential_identifier='initial', token_digest=uuid4().hex)
                s.add(c)
                await s.flush()
                row = await register(s, d.id, c.id, registration(88))
                row.enabled = True
                row.windows_admin_username = 'explicitlocal'
                row.operator_public_keys = [registration(90).host_public_key]
                row.expires_at = datetime.now(UTC)+timedelta(hours=1)
                await s.commit()
        finally:
            await provider.close()
    asyncio.run(populate())

    async def snapshot():
        provider = AsyncSessionProvider(url)
        try:
            async with provider() as s:
                return (await s.execute(text("SELECT id, to_jsonb(s)-'installation_access_pending_until' FROM support_access s ORDER BY id"))).all()
        finally:
            await provider.close()
    before = asyncio.run(snapshot())
    assert before
    command.downgrade(cfg, '0046_support_access')
    command.upgrade(cfg, '0047_support_install_access')
    assert asyncio.run(snapshot()) == before

    async def check_null():
        provider = AsyncSessionProvider(url)
        try:
            async with provider() as s:
                assert (await s.execute(text('SELECT count(*) FROM support_access WHERE installation_access_pending_until IS NOT NULL'))).scalar_one() == 0
        finally:
            await provider.close()
    asyncio.run(check_null())


def test_pending_manual_disable_records_administrator_and_never_rearms(update_migration_database_urls, tmp_path):
    url, _ = update_migration_database_urls
    command.upgrade(_alembic_config(url), 'head')

    async def scenario():
        provider = AsyncSessionProvider(url)
        try:
            settings = configured(tmp_path)
            device_id, token, issued = await seed(provider, settings)
            app = create_app(settings, provider)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('127.0.0.1', 12345)), base_url=settings.public_base_url) as client:
                auth = {'Authorization': 'Bearer '+token}
                result = await client.post('/agent/v1/support-access/register', headers=auth, json=registration(80).model_dump())
                assert result.status_code == 200
                client.cookies.set(ADMIN_SESSION_COOKIE, issued.token)
                disabled = await client.put(f'/api/admin/support-access/devices/{device_id}/policy', headers={'X-CSRF-Token': issued.csrf_token},
                    json={'enabled': False, 'reason': 'Explicit isolated administrator disable'})
                assert disabled.status_code == 200 and not disabled.json()['enabled']
                async with provider() as s:
                    event = await s.scalar(select(AuditEvent).where(AuditEvent.action == 'support_access.installation_access_cancelled',
                        AuditEvent.actor_identifier == str(issued.record.admin_user_id)))
                    assert event is not None and event.actor_kind == 'admin'
                report = await client.post('/agent/v1/support-access/status', headers={'Authorization': 'Bearer '+result.json()['support_token']},
                    json={'installed': True, 'tunnel_connected': False, 'component_version': '1.0.1'})
                assert report.status_code == 200 and not report.json()['enabled']
                again = await client.post('/agent/v1/support-access/register', headers=auth, json=registration(80).model_dump())
                assert again.status_code == 200 and not again.json()['policy']['enabled']
        finally:
            await provider.close()
    asyncio.run(scenario())


def test_source_revocation_race_removes_effective_authority_preserving_identity(update_migration_database_urls, tmp_path):
    url, _ = update_migration_database_urls
    command.upgrade(_alembic_config(url), 'head')

    async def scenario():
        from endpoint_server.support_access.routes import policy
        from endpoint_server.support_access.service import get_broker_leases
        provider = AsyncSessionProvider(url)
        try:
            settings = configured(tmp_path)
            device_id, token, _ = await seed(provider, settings)
            app = create_app(settings, provider)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('127.0.0.1', 12345)), base_url=settings.public_base_url) as client:
                result = await client.post('/agent/v1/support-access/register', headers={'Authorization': 'Bearer '+token}, json=registration(82).model_dump())
                assert result.status_code == 200, result.text
                headers = {'Authorization': 'Bearer '+result.json()['support_token']}
                async with provider() as s:
                    row = await s.scalar(select(SupportAccess).where(SupportAccess.device_id == device_id))
                    identity = (row.source_credential_id, row.tunnel_public_key, row.host_public_key, row.generation)
                async def revoke_source():
                    async with provider() as s:
                        credential = await s.get(DeviceCredential, identity[0])
                        credential.revoked_at = datetime.now(UTC)
                        await s.commit()
                report, _ = await asyncio.gather(client.post('/agent/v1/support-access/status', headers=headers,
                    json={'installed': True, 'tunnel_connected': False, 'component_version': '1.0.1'}), revoke_source())
                assert report.status_code in (200, 401), report.text
                assert (await client.get('/agent/v1/support-access/policy', headers=headers)).status_code == 401
                assert (await client.post('/agent/v1/support-access/status', headers=headers,
                    json={'installed': True, 'tunnel_connected': False, 'component_version': '1.0.1'})).status_code == 401
                async with provider() as s:
                    row = await s.scalar(select(SupportAccess).where(SupportAccess.device_id == device_id))
                    assert (row.source_credential_id, row.tunnel_public_key, row.host_public_key, row.generation) == identity
                    assert not (await policy(s, row, settings)).enabled
                    assert all(lease.device_id != device_id for lease in await get_broker_leases(s, datetime.now(UTC)))
        finally:
            await provider.close()
    asyncio.run(scenario())
