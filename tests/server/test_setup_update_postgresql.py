"""Additive migration and serialization on real disposable PostgreSQL."""
import asyncio
from uuid import uuid4

from alembic import command
from sqlalchemy import text
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.setup_updates.models import SetupRelease, SetupAssignment
from endpoint_server.setup_updates.service import lock_device
from endpoint_server.db.models import Device
from tests.server.test_update_postgresql import update_migration_database_urls, _alembic_config, _fetch


def test_setup_migration_preserves_populated_previous_revision_and_downgrades(update_migration_database_urls):
    url, plain = update_migration_database_urls
    config = _alembic_config(url)
    command.upgrade(config, '0042_worktime_companion')
    async def seed():
        provider = AsyncSessionProvider(url)
        async with provider() as session:
            device = Device(id=uuid4(), device_identifier='setup-migration-preserved')
            session.add(device); await session.commit()
        await provider.close()
    asyncio.run(seed())
    command.upgrade(config, 'head')
    rows = asyncio.run(_fetch(plain, "SELECT device_identifier FROM devices WHERE device_identifier='setup-migration-preserved'"))
    assert len(rows) == 1
    assert asyncio.run(_fetch(plain, "SELECT to_regclass('setup_update_preparations') AS t"))[0]['t'] is not None
    command.downgrade(config, '0042_worktime_companion')
    assert len(asyncio.run(_fetch(plain, "SELECT device_identifier FROM devices WHERE device_identifier='setup-migration-preserved'"))) == 1
    assert asyncio.run(_fetch(plain, "SELECT to_regclass('setup_update_assignments') AS t"))[0]['t'] is None
    command.upgrade(config, 'head')


def test_device_update_lock_serializes_competing_owners(update_migration_database_urls):
    url, _ = update_migration_database_urls
    async def scenario():
        provider = AsyncSessionProvider(url)
        identity = uuid4()
        async with provider() as first:
            first.add(Device(id=identity, device_identifier='lock-'+identity.hex))
            await first.commit()
            await lock_device(first, identity)
            started, acquired = asyncio.Event(), asyncio.Event()
            async def waiter():
                async with provider() as second:
                    started.set()
                    await lock_device(second, identity)
                    acquired.set()
                    await second.rollback()
            task = asyncio.create_task(waiter())
            await started.wait()
            await asyncio.sleep(.1)
            assert not acquired.is_set()
            await first.commit()
            await asyncio.wait_for(task, 3)
            assert acquired.is_set()
        await provider.close()
    asyncio.run(scenario())


def test_real_admin_cookie_csrf_and_persisted_scope_protect_setup_assignment(update_migration_database_urls, tmp_path):
    from datetime import UTC, datetime
    from dataclasses import replace
    import httpx
    from endpoint_server.auth.admin_sessions import issue_admin_session, ADMIN_SESSION_COOKIE
    from endpoint_server.db.models import AdminUser
    from endpoint_server.setup_updates.service import record_presence
    from endpoint_server.main import create_app
    from tests.server.test_update_agent_api import _settings
    url, _ = update_migration_database_urls
    async def scenario():
        provider = AsyncSessionProvider(url)
        settings = replace(_settings(tmp_path), database_url=url)
        device_id, release_id, user_id = uuid4(), uuid4(), uuid4()
        async with provider() as session:
            session.add_all([Device(id=device_id, device_identifier='auth-'+device_id.hex),
                AdminUser(id=user_id, username='setup-'+user_id.hex, password_digest='test-only', scopes=['updates:write']),
                SetupRelease(id=release_id, release_identifier='setup-'+release_id.hex, version='3.2.158',
                    artifact_name='Setup-'+release_id.hex+'.exe', size=10, sha256='a'*64,
                    source_revision='b'*40, msi_sha256='c'*64, tray_sha256='d'*64, sensor_sha256='e'*64)])
            await session.flush()
            issued = issue_admin_session(user_id, settings.session_secret)
            session.add(issued.record)
            await session.flush()
            await record_presence(session, device_id, dict(client_version='1.0.0', ready=True, core_version='3.2.156'))
            await session.commit()
        app = create_app(settings, provider)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('127.0.0.1',12345)),
            base_url=settings.public_base_url, cookies={ADMIN_SESSION_COOKIE: issued.token}) as client:
            body=dict(device_id=str(device_id), release_id=str(release_id), reason='Real isolated HTTP acceptance')
            denied=await client.post('/api/admin/setup-updates/assignments', json=body)
            assert denied.status_code == 403
            accepted=await client.post('/api/admin/setup-updates/assignments', json=body, headers={'X-CSRF-Token':issued.csrf_token})
            assert accepted.status_code == 201, accepted.text
            job_id=accepted.json()['data']['id']
            async with provider() as session:
                user=await session.get(AdminUser,user_id);user.scopes=[];await session.commit()
            denied=await client.post(f'/api/admin/setup-updates/assignments/{job_id}/cancel', headers={'X-CSRF-Token':issued.csrf_token,'X-Scope':'updates:write'})
            assert denied.status_code == 403
        await provider.close()
    asyncio.run(scenario())
