"""Emergency session issuance must share its clock sample with its expiry cap."""
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

from fastapi import Request, Response
import pytest

from endpoint_server.auth import admin_sessions
from endpoint_server.auth.oidc_config import OIDCSettings
from endpoint_server.auth.passwords import hash_password
from endpoint_server.db.models import AdminUser


@pytest.mark.asyncio
async def test_breakglass_login_keeps_expiry_within_bound_when_clock_advances(monkeypatch):
    start = datetime(2026, 10, 27, 6, tzinfo=UTC)

    class AdvancingClock:
        calls = 0

        @classmethod
        def now(cls, tz=None):
            cls.calls += 1
            return start + timedelta(microseconds=100 * cls.calls)

    monkeypatch.setattr(admin_sessions, "datetime", AdvancingClock)
    until = start + timedelta(minutes=20)
    user = AdminUser(
        id=uuid4(), username="bounded-emergency",
        password_digest=hash_password("synthetic-clock-test-password"),
        scopes=[], sso_migrated_at=start,
    )
    settings = SimpleNamespace(
        oidc=OIDCSettings(breakglass_usernames=(user.username,), breakglass_until=until),
        session_secret=b"synthetic-test-only-secret" * 2,
    )
    records = []
    session = SimpleNamespace(
        scalar=AsyncMock(return_value=user), add=records.append,
        commit=AsyncMock(), rollback=AsyncMock(),
    )

    @asynccontextmanager
    async def provider():
        yield session

    audit = AsyncMock()
    monkeypatch.setattr(admin_sessions, "append_audit_event", audit)
    request = Request({
        "type": "http", "headers": [],
        "app": SimpleNamespace(state=SimpleNamespace(settings=settings, session_provider=provider)),
    })
    response = Response()
    await admin_sessions.login_admin(
        admin_sessions.AdminLoginRequest(username=user.username, password="synthetic-clock-test-password"),
        request, response,
    )
    assert len(records) == 1
    record = records[0]
    assert record.auth_method == "breakglass"
    assert record.expires_at == until
    assert await admin_sessions.local_password_policy(session, user, settings, record=record) == (True, True)
    assert audit.await_count == 1
    assert audit.await_args.kwargs["action"] == "admin_breakglass_session.created"
    session.commit.assert_awaited_once()
    assert "endpoint_admin_session=" in response.headers["set-cookie"]

    # The boundary stays strict: neither an old local session nor an overrun
    # becomes valid merely because emergency login has been enabled.
    for invalid in (
        SimpleNamespace(auth_method="local", expires_at=until),
        SimpleNamespace(auth_method="breakglass", expires_at=until + timedelta(microseconds=1)),
    ):
        assert await admin_sessions.local_password_policy(session, user, settings, record=invalid) == (False, False)
    AdvancingClock.calls = 20 * 60 * 10_000
    assert await admin_sessions.local_password_policy(session, user, settings, record=record) == (False, False)
