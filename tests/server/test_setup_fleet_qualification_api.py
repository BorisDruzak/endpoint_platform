"""Console qualification exercises real PostgreSQL, cookie authority and native proof."""
import asyncio
from datetime import timedelta
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select

from endpoint_server.auth.admin_sessions import ADMIN_SESSION_COOKIE, issue_admin_session
from endpoint_server.db.models import AdminUser, AuditEvent, DeviceInstance
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.main import create_app
from endpoint_server.setup_updates.models import SetupFleetQualification
from tests.server.test_setup_fleet_postgresql import fleet_database, seed, update_migration_database_urls
from tests.server.test_update_agent_api import _settings
from tests.server import test_setup_fleet_policy as evidence_fixtures

pytestmark = pytest.mark.usefixtures('preserve_migration_loggers')


@pytest.mark.parametrize('fault', ['none', 'missing', 'foreign', 'stale', 'sensor', 'browser_proof', 'revoked_after_wait'])
def test_console_qualification_native_proof_and_transactional_authority(fleet_database, tmp_path, monkeypatch, fault):
    async def scenario():
        provider = AsyncSessionProvider(fleet_database[0])
        from dataclasses import replace
        settings = replace(_settings(tmp_path), database_url=fleet_database[0])
        try:
            async with provider() as db:
                release, devices, policy, now = await seed(db, count=1)
                policy.enabled = False
                instance = await db.scalar(select(DeviceInstance).where(DeviceInstance.device_id == devices[0].id))
                monkeypatch.setattr(evidence_fixtures, 'NOW', now)
                job, health = await evidence_fixtures.qualification_evidence(db, (devices[0], release, policy, instance))
                user = AdminUser(id=uuid4(), username='qualification-'+uuid4().hex, password_digest='fixture', scopes=['updates:write'])
                db.add(user); await db.flush()
                issued = issue_admin_session(user.id, settings.session_secret)
                db.add(issued.record)
                body = dict(release_id=str(release.id), evidence_assignment_id=str(job.id))
                if fault == 'missing': body['evidence_assignment_id'] = str(uuid4())
                if fault == 'foreign': body['release_id'] = str((await evidence_fixtures.same_artifact_alias(db, release)).id)
                if fault == 'stale': job.finished_at = now-timedelta(days=2)
                if fault == 'sensor': health.user_sensor_last_seen_at = now-timedelta(minutes=10)
                if fault == 'browser_proof': body['proof'] = {'native_verified': True}
                await db.commit()
                release_id, evidence_id, user_id = release.id, job.id, user.id
            app = create_app(settings, provider)
            if fault == 'revoked_after_wait':
                import endpoint_server.setup_updates.fleet_routes as routes
                real = routes.qualify_release
                async def revoked_after_wait(session, *args, **kwargs):
                    result = await real(session, *args, **kwargs)
                    # A separate committed identity change during the domain wait.
                    async with provider() as authority:
                        user = await authority.get(AdminUser, user_id)
                        user.scopes = []; await authority.commit()
                    return result
                monkeypatch.setattr(routes, 'qualify_release', revoked_after_wait)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('127.0.0.1', 12345)),
                base_url=settings.public_base_url, cookies={ADMIN_SESSION_COOKIE: issued.token}) as client:
                path = '/api/admin/setup-updates/fleet/qualifications'
                response = await client.post(path, json=body, headers={'X-CSRF-Token': issued.csrf_token})
            expected = 200 if fault == 'none' else 422 if fault == 'browser_proof' else 403 if fault == 'revoked_after_wait' else 409
            assert response.status_code == expected, response.text
            async with provider() as db:
                qualification = await db.scalar(select(SetupFleetQualification).where(SetupFleetQualification.evidence_assignment_id == evidence_id))
                audit = await db.scalar(select(AuditEvent).where(AuditEvent.action == 'setup_updates.fleet_release_qualified', AuditEvent.actor_identifier == str(user_id)))
                if fault == 'none':
                    assert response.json()['data']['evidence_assignment_id'] == str(evidence_id)
                    assert qualification is not None and qualification.release_id == release_id and qualification.qualified_by == str(user_id)
                    assert audit.details['evidence_assignment_id'] == str(evidence_id)
                else:
                    assert qualification is None and audit is None
                from endpoint_server.setup_updates.models import SetupFleetPolicy
                assert (await db.scalar(select(SetupFleetPolicy))).enabled is False
        finally:
            await provider.close()
    asyncio.run(scenario())


def test_console_qualification_requires_real_cookie_csrf_and_persisted_scope(fleet_database, tmp_path):
    async def scenario():
        provider = AsyncSessionProvider(fleet_database[0])
        from dataclasses import replace
        settings = replace(_settings(tmp_path), database_url=fleet_database[0])
        try:
            async with provider() as db:
                release, *_ = await seed(db, count=1)
                user = AdminUser(id=uuid4(), username='qualification-read-'+uuid4().hex, password_digest='fixture', scopes=['updates:write'])
                db.add(user); await db.flush()
                issued = issue_admin_session(user.id, settings.session_secret); db.add(issued.record)
                await db.commit(); user_id = user.id
            app = create_app(settings, provider)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('127.0.0.1', 12345)),
                base_url=settings.public_base_url, cookies={ADMIN_SESSION_COOKIE: issued.token}) as client:
                path = '/api/admin/setup-updates/fleet/qualifications'
                body = dict(release_id=str(release.id), evidence_assignment_id=str(uuid4()))
                assert (await client.post(path, json=body)).status_code == 403
                async with provider() as db:
                    user = await db.get(AdminUser, user_id); user.scopes = []; await db.commit()
                assert (await client.post(path, json=body, headers={'X-CSRF-Token': issued.csrf_token, 'X-Scope': 'updates:write'})).status_code == 403
                client.cookies.clear()
                assert (await client.post(path, json=body)).status_code == 401
        finally:
            await provider.close()
    asyncio.run(scenario())
