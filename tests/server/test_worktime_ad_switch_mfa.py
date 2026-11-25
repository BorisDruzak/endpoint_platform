"""An AD switch retains its authority choice through automatic MFA."""
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import httpx
from cryptography.fernet import Fernet
from fastapi import FastAPI

from endpoint_server.auth import oidc
from endpoint_server.auth.oidc_config import OIDCSettings
from endpoint_server.auth.worktime_protocol import WORKTIME_COOKIE


async def test_worktime_ad_switch_survives_low_assurance_then_mfa(monkeypatch):
    settings = OIDCSettings(enabled=True, issuer='https://sso.example/realms/org',
        encryption_key=Fernet.generate_key(), employee_client_id='employee',
        admin_client_id='admin', employee_client_secret='fixture',
        admin_client_secret='fixture', admin_required_acr='mfa',
        helpdesk_base_url='https://helpdesk.example', helpdesk_credential='a'*48)
    person, guid = uuid4(), uuid4()
    identity = SimpleNamespace(id=uuid4(), person_id=person, ad_object_guid=guid,
        state='active', revoked_at=None, authority_kind='oidc',
        issuer=settings.issuer, subject='employee')
    added = []
    session = SimpleNamespace(add=added.append, commit=AsyncMock(), flush=AsyncMock(),
        execute=AsyncMock(), scalar=AsyncMock(return_value=identity),
        scalars=AsyncMock(return_value=SimpleNamespace(all=lambda: [SimpleNamespace(role='hr')])))

    @asynccontextmanager
    async def provider():
        yield session

    app = FastAPI(); app.include_router(oidc.router)
    app.state.settings = SimpleNamespace(oidc=settings,
        public_base_url='https://endpoint.example', session_secret=b'fixture-secret')
    app.state.session_provider = provider
    claims = dict(iss=settings.issuer, sub='employee', ad_object_guid=str(guid), sid='fixture-sid')
    app.state.oidc_provider = SimpleNamespace(authorize=AsyncMock(return_value='https://sso.example/login'),
        exchange=AsyncMock(side_effect=[({}, claims, None), ({}, dict(claims, acr='mfa'), None)]))
    app.state.helpdesk_identity_client = SimpleNamespace(resolve=AsyncMock(
        return_value=SimpleNamespace(person_id=person, department_id=None)))
    monkeypatch.setattr('endpoint_server.audit.service.append_audit_event', AsyncMock())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app),
            base_url='https://endpoint.example', follow_redirects=False) as client:
        client.cookies.set(WORKTIME_COOKIE, 'h'*43, domain='endpoint.example', path='/')
        assert (await client.get('/auth/employee/login?worktime=1')).status_code == 303
        consume = AsyncMock(return_value=added[0]); monkeypatch.setattr(oidc, 'consume_flow', consume)
        first = await client.get('/auth/employee/callback?state=first&code=first')
        assert first.status_code == 303
        target = urlsplit(first.headers['location'])
        assert target.path == '/auth/employee/step-up'
        assert parse_qs(target.query)['worktime'] == ['1']
        assert not any(isinstance(row, oidc.EmployeeSession) for row in added)
        assert (await client.get(first.headers['location'])).status_code == 303
        flow = next(row for row in reversed(added) if isinstance(row, oidc.OIDCFlow))
        assert oidc.unseal(settings, flow.encrypted_material)['worktime_ad_switch'] is True
        consume.return_value = flow
        second = await client.get('/auth/employee/callback?state=second&code=second')
        assert second.status_code == 303 and second.headers['location'] == '/employee'
        assert WORKTIME_COOKIE not in client.cookies
        assert any(isinstance(row, oidc.EmployeeSession) for row in added)
