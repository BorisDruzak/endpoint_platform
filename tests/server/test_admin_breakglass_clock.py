"""Emergency sessions must remain inside their exact administrator deadline."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from endpoint_server.auth import admin_sessions
from endpoint_server.config import OIDCSettings
from endpoint_server.main import create_app
from tests.server.test_admin_auth import _admin_user, _AuthSession, _AuthSessionProvider, _settings


@pytest.mark.asyncio
@pytest.mark.parametrize('deadline_minutes', [20, 120])
async def test_breakglass_issuance_uses_one_clock_for_deadline_and_hour_cap(monkeypatch, deadline_minutes):
    anchor = datetime.now(UTC)
    calls = []

    class AdvancingClock(datetime):
        @classmethod
        def now(cls, tz=None):
            value = anchor + timedelta(microseconds=10 * len(calls))
            calls.append(value)
            return value

    monkeypatch.setattr(admin_sessions, 'datetime', AdvancingClock)
    user = _admin_user('test-password')
    user.sso_migrated_at = anchor - timedelta(days=1)
    session = _AuthSession(user=user)
    until = anchor + timedelta(minutes=deadline_minutes)
    settings = replace(_settings(b's' * 32), oidc=OIDCSettings(
        breakglass_usernames=(user.username,), breakglass_until=until))
    app = create_app(settings, session_provider=_AuthSessionProvider(session))
    async with AsyncClient(transport=ASGITransport(app), base_url=settings.public_base_url) as client:
        response = await client.post('/api/admin/session', json={'username': user.username, 'password': 'test-password'})
    assert response.status_code == 201
    record, audit = session.added
    assert record.auth_method == 'breakglass'
    assert record.expires_at == min(until, calls[1] + timedelta(hours=1))
    assert record.expires_at <= until
    assert audit.action == 'admin_breakglass_session.created'
    assert session.commit_calls == 1


@pytest.mark.asyncio
async def test_breakglass_deadline_passing_after_policy_check_rejects_without_session(monkeypatch):
    anchor = datetime.now(UTC)
    ticks = iter([anchor, anchor + timedelta(seconds=2), anchor + timedelta(seconds=3)])

    class DeadlineClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return next(ticks)

    monkeypatch.setattr(admin_sessions, 'datetime', DeadlineClock)
    user = _admin_user('test-password')
    user.sso_migrated_at = anchor - timedelta(days=1)
    session = _AuthSession(user=user)
    settings = replace(_settings(b's' * 32), oidc=OIDCSettings(
        breakglass_usernames=(user.username,), breakglass_until=anchor + timedelta(seconds=1)))
    app = create_app(settings, session_provider=_AuthSessionProvider(session))
    async with AsyncClient(transport=ASGITransport(app, raise_app_exceptions=False), base_url=settings.public_base_url) as client:
        response = await client.post('/api/admin/session', json={'username': user.username, 'password': 'test-password'})
    assert response.status_code == 401
    assert not session.added
    assert session.commit_calls == 0
    assert 'set-cookie' not in response.headers
