from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest

from endpoint_server.main import create_app
from endpoint_server.db.models import Device, DeviceCredential
from endpoint_server.enrollment.credentials import device_token_digest
from endpoint_server.setup_updates.routes import agent_router
from endpoint_server.setup_updates.service import record_presence, assign_setup
from tests.server.test_update_agent_api import _settings
from tests.server.test_setup_update_service import db, state


async def test_setup_mutation_requires_persisted_update_scope_and_cannot_be_header_granted(db, state):
    from endpoint_server.auth.admin_sessions import require_admin
    from tests.server.test_update_admin_api import _principal
    app, _ = await boundary(db, state)
    app.dependency_overrides[require_admin] = lambda: _principal([])
    device, release, *_ = state
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('127.0.0.1', 12345)), base_url='https://endpoint.sosnadmin.local') as client:
        for path, body in [('/api/admin/setup-updates/assignments', dict(device_id=str(device.id), release_id=str(release.id), reason='Canary')),
                           (f'/api/admin/setup-updates/assignments/{uuid4()}/cancel', None)]:
            result = await client.post(path, json=body, headers={'X-Scope': 'updates:write'})
            assert result.status_code == 403


async def boundary(db, state):
    device, release, _, root = state
    settings = _settings(root)
    token = 's' * 43
    db.add(DeviceCredential(id=uuid4(), device_id=device.id, credential_identifier='setup-client',
                           token_digest=device_token_digest(token, settings.device_token_pepper)))
    await db.commit()
    @asynccontextmanager
    async def provider():
        yield db
    app = create_app(settings, provider)
    return app, token


async def test_new_device_channel_requires_existing_credential(db, state):
    app, token = await boundary(db, state)
    transport = httpx.ASGITransport(app=app, client=('127.0.0.1', 12345))
    async with httpx.AsyncClient(transport=transport, base_url='https://endpoint.sosnadmin.local') as client:
        for auth in ({}, {'Authorization': 'Bearer invalid'}):
            assert (await client.get('/agent/v1/setup-updates/recommendation', headers=auth)).status_code == 401
        headers = {'Authorization': 'Bearer ' + token}
        assert (await client.get('/agent/v1/setup-updates/recommendation', headers=headers)).status_code == 204


async def test_full_setup_is_never_returned_to_old_core_recommendation(db, state):
    app, token = await boundary(db, state)
    device, release, *_ = state
    await record_presence(db, device.id, dict(client_version='1.0.3', ready=True), now=datetime.now(UTC))
    job = await assign_setup(db, device.id, release.id, 'full Setup canary', actor='test-admin', request_id='assign')
    await db.commit()
    transport = httpx.ASGITransport(app=app, client=('127.0.0.1', 12345))
    async with httpx.AsyncClient(transport=transport, base_url='https://endpoint.sosnadmin.local',
                                headers={'Authorization': 'Bearer ' + token}) as client:
        old = await client.get('/agent/v1/updates/recommendation?platform=windows_amd64&channel=canary')
        assert old.status_code == 204
        full = await client.get('/agent/v1/setup-updates/recommendation')
        assert full.status_code == 200 and full.json()['assignment_id'] == str(job.id)
        artifact = await client.get(f'/agent/v1/setup-updates/assignments/{job.id}/artifact')
        assert artifact.status_code == 200 and artifact.content == b'published immutable full Setup fixture'


async def test_another_authenticated_device_cannot_read_assignment_artifact(db, state):
    app, token = await boundary(db, state)
    device, release, *_ = state
    await record_presence(db, device.id, dict(client_version='1.0.3', ready=True), now=datetime.now(UTC))
    job = await assign_setup(db, device.id, release.id, 'full Setup canary', actor='test-admin', request_id='assign')
    other = Device(id=uuid4(), device_identifier='another-device')
    db.add(other)
    await db.flush()
    other_token = 'z' * 43
    db.add(DeviceCredential(id=uuid4(), device_id=other.id, credential_identifier='other',
        token_digest=device_token_digest(other_token, _settings().device_token_pepper)))
    await db.commit()
    transport = httpx.ASGITransport(app=app, client=('127.0.0.1', 12345))
    async with httpx.AsyncClient(transport=transport, base_url='https://endpoint.sosnadmin.local',
                                headers={'Authorization': 'Bearer ' + other_token}) as client:
        assert (await client.get(f'/agent/v1/setup-updates/assignments/{job.id}/artifact')).status_code == 404
        assert (await client.get('/agent/v1/setup-updates/recommendation')).status_code == 204


async def test_progress_revalidates_bearer_after_domain_lock_and_rolls_back_on_revocation(db, state, monkeypatch):
    from fastapi import HTTPException
    import endpoint_server.setup_updates.routes as routes
    from endpoint_server.setup_updates.models import SetupAssignment
    app, token = await boundary(db, state)
    device, release, *_ = state
    await record_presence(db, device.id, dict(client_version='1.0.3', ready=True))
    job = await assign_setup(db, device.id, release.id, 'full Setup canary', actor='test-admin', request_id='assign')
    job_id = job.id
    await db.commit()
    calls = []
    real = routes.record_progress
    async def domain(*args, **kwargs):
        calls.append('domain')
        return await real(*args, **kwargs)
    async def revoked(*args, **kwargs):
        assert calls == ['domain']
        calls.append('revalidate')
        raise HTTPException(401, 'revoked fixture')
    monkeypatch.setattr(routes, 'record_progress', domain)
    monkeypatch.setattr(routes, '_revalidate_device_principal', revoked)
    transport = httpx.ASGITransport(app=app, client=('127.0.0.1', 12345))
    async with httpx.AsyncClient(transport=transport, base_url='https://endpoint.sosnadmin.local',
                                headers={'Authorization': 'Bearer ' + token}) as client:
        response = await client.post(f'/agent/v1/setup-updates/assignments/{job_id}/progress',
                                     json={'attempt_id': str(uuid4()), 'phase': 'downloading'})
        assert response.status_code == 401
    await db.refresh(await db.get(SetupAssignment, job_id))
    assert (await db.get(SetupAssignment, job_id)).status == 'assigned'
    assert calls == ['domain', 'revalidate']
