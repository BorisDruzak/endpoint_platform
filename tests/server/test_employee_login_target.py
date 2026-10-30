"""Companion navigation survives SSO without accepting redirect URLs."""
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI

from endpoint_server.auth import oidc
from endpoint_server.auth.oidc_config import OIDCSettings

REQUEST_ID = '00000000-0000-4000-8000-000000000002'
TARGET = f'/employee?day=2026-10-27&request_id={REQUEST_ID}'


@pytest.mark.parametrize(('query', 'expected'), [
    (TARGET.split('?', 1)[1], TARGET),
    ('', '/employee'),
    (f'day=2026-02-30&request_id={REQUEST_ID}', '/employee'),
    (f'day=2026-10-27&day=2026-10-28&request_id={REQUEST_ID}', '/employee'),
    ('day=2026-10-27&request_id=https://foreign.example', '/employee'),
    ('return_to=https://foreign.example', '/employee'),
])
async def test_employee_callback_uses_only_flow_bound_companion_target(monkeypatch, query, expected):
    settings = OIDCSettings(enabled=True, issuer='https://sso.example/realms/org', encryption_key=Fernet.generate_key(),
        employee_client_id='employee', admin_client_id='admin', employee_client_secret='fixture', admin_client_secret='fixture',
        admin_required_acr='mfa', helpdesk_base_url='https://helpdesk.example', helpdesk_credential='a'*48)
    person, guid = uuid4(), uuid4()
    identity = SimpleNamespace(id=uuid4(), person_id=person, ad_object_guid=guid, state='active', revoked_at=None)
    added = []
    session = SimpleNamespace(add=added.append, commit=AsyncMock(), flush=AsyncMock(),
        scalar=AsyncMock(return_value=identity), scalars=AsyncMock(return_value=SimpleNamespace(all=lambda: [])))

    @asynccontextmanager
    async def provider():
        yield session

    app = FastAPI()
    app.include_router(oidc.router)
    app.state.settings = SimpleNamespace(oidc=settings, public_base_url='https://endpoint.example', session_secret=b'test-secret')
    app.state.session_provider = provider
    app.state.oidc_provider = SimpleNamespace(authorize=AsyncMock(return_value='https://sso.example/login'),
        exchange=AsyncMock(return_value=({}, dict(iss=settings.issuer, sub='employee', ad_object_guid=str(guid), sid='test-sid'), None)))
    app.state.helpdesk_identity_client = SimpleNamespace(resolve=AsyncMock(return_value=SimpleNamespace(person_id=person, department_id=None)))
    monkeypatch.setattr('endpoint_server.audit.service.append_audit_event', AsyncMock())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='https://endpoint.example') as client:
        started = await client.get('/auth/employee/login?' + query)
        assert started.status_code == 303
        flow = added[0]
        monkeypatch.setattr(oidc, 'consume_flow', AsyncMock(return_value=flow))
        # Neither a new target nor an arbitrary URL on callback overrides the flow.
        completed = await client.get('/auth/employee/callback?state=test&code=test&day=2026-10-28&return_to=https://foreign.example')
        assert completed.status_code == 303
        assert completed.headers['location'] == expected
        assert completed.headers['referrer-policy'] == 'no-referrer'
