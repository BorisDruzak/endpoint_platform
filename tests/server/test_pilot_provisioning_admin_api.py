"""Administrator API tests for the one-time ALT test-pilot provisioner."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.db.models import (
    AdminSession,
    AdminUser,
    AuditEvent,
    ServiceClient,
    ServiceCredential,
)
from endpoint_server.main import create_app


NOW = datetime.now(UTC)


def _settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"pilot-device-pepper",
        service_token_pepper=b"pilot-service-pepper",
        session_secret=b"pilot-session-secret",
        allowed_agent_cidrs=(),
        allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"),
    )


class _PilotSession:
    def __init__(self) -> None:
        self.client: ServiceClient | None = None
        self.credential: ServiceCredential | None = None
        self.added: list[object] = []
        self.commit_calls = 0
        self.rollback_calls = 0

    async def scalar(self, statement: object) -> object | None:
        entity = statement.column_descriptions[0]["entity"]
        if entity is ServiceClient:
            return self.client
        if entity is ServiceCredential:
            return self.credential
        raise AssertionError(f"unexpected scalar entity: {entity}")

    def add(self, value: object) -> None:
        self.added.append(value)
        if isinstance(value, ServiceClient):
            self.client = value
        if isinstance(value, ServiceCredential):
            self.credential = value

    async def commit(self) -> None:
        self.commit_calls += 1

    async def rollback(self) -> None:
        self.rollback_calls += 1


class _Provider:
    def __init__(self, session: _PilotSession) -> None:
        self.session = session

    @asynccontextmanager
    async def __call__(self):
        yield self.session


def _principal() -> AdminPrincipal:
    user_id = uuid4()
    return AdminPrincipal(
        user=AdminUser(
            id=user_id,
            username="pilot-admin",
            password_digest="unused",
            scopes=["updates:write"],
            disabled_at=None,
        ),
        session=AdminSession(
            id=uuid4(),
            admin_user_id=user_id,
            session_digest="unused",
            expires_at=NOW + timedelta(hours=1),
            revoked_at=None,
        ),
    )


@pytest.mark.asyncio
async def test_admin_pilot_credential_is_show_once_scoped_and_redacted() -> None:
    session = _PilotSession()
    app = create_app(_settings(), session_provider=_Provider(session))
    app.dependency_overrides[require_admin] = _principal

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/api/admin/provisioning/test-pilot/credentials",
            headers={"X-Request-ID": "pilot-request-marker"},
            json={"install_session_id": "alt-test-agent-001"},
        )

    assert response.status_code == 201
    payload = response.json()
    assert UUID(payload["credential_id"])
    assert payload["token"].startswith("svc_")
    assert datetime.fromisoformat(payload["expires_at"]).astimezone(UTC) > NOW
    assert session.client is not None
    assert session.client.client_identifier == "alt-test-pilot"
    assert session.credential is not None
    assert session.credential.scopes == ["provisioning.install-claims.issue"]
    assert session.credential.expires_at is not None
    assert session.credential.expires_at <= datetime.now(UTC) + timedelta(minutes=16)
    audits = [value for value in session.added if isinstance(value, AuditEvent)]
    assert [audit.action for audit in audits] == [
        "service_credential.created",
        "provisioning_test_pilot_credential.issued",
    ]
    assert all(payload["token"] not in repr(audit) for audit in audits)
    assert all("pilot-request-marker" not in repr(audit) for audit in audits)
    assert audits[-1].details == {
        "expires_at": session.credential.expires_at.isoformat(),
        "installation_id": "alt-test-agent-001",
        "scope": "provisioning.install-claims.issue",
    }
    assert session.commit_calls == 1


@pytest.mark.asyncio
async def test_pilot_credential_revoke_is_idempotent_and_never_returns_token() -> None:
    session = _PilotSession()
    app = create_app(_settings(), session_provider=_Provider(session))
    app.dependency_overrides[require_admin] = _principal

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        issued = await client.post(
            "/api/admin/provisioning/test-pilot/credentials",
            json={"install_session_id": "alt-test-agent-001"},
        )
        credential_id = issued.json()["credential_id"]
        token = issued.json()["token"]
        revoked = await client.post(
            f"/api/admin/provisioning/test-pilot/credentials/{credential_id}/revoke"
        )
        repeated = await client.post(
            f"/api/admin/provisioning/test-pilot/credentials/{credential_id}/revoke"
        )

    assert revoked.status_code == 204
    assert repeated.status_code == 204
    assert token not in revoked.text + repeated.text
    assert session.credential is not None
    assert session.credential.revoked_at is not None
    audits = [value for value in session.added if isinstance(value, AuditEvent)]
    assert [audit.action for audit in audits].count(
        "provisioning_test_pilot_credential.revoked"
    ) == 1


@pytest.mark.asyncio
async def test_pilot_credential_requires_administrator_session() -> None:
    app = create_app(_settings(), session_provider=_Provider(_PilotSession()))

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/api/admin/provisioning/test-pilot/credentials",
            json={"install_session_id": "alt-test-agent-001"},
        )

    assert response.status_code == 401
