"""Administrator API tests for enrollment campaigns and install claims."""

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
    EnrollmentCampaign,
    EnrollmentClaim,
)
from endpoint_server.enrollment.campaigns import issue_campaign
from endpoint_server.main import create_app


NOW = datetime.now(UTC)
PEPPER = b"admin-api-device-pepper-for-testing"


def _settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=PEPPER,
        service_token_pepper=b"service-token-pepper",
        session_secret=b"session-secret",
        allowed_agent_cidrs=(),
        allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"),
    )


class _Result:
    def __init__(self, value: object | None) -> None:
        self.value = value

    def scalar_one_or_none(self) -> object | None:
        return self.value


class _AdminEnrollmentSession:
    def __init__(
        self,
        *,
        campaign: EnrollmentCampaign | None = None,
        fail_audit: bool = False,
    ) -> None:
        self.campaign = campaign
        self.fail_audit = fail_audit
        self.added: list[object] = []
        self.commit_calls = 0
        self.rollback_calls = 0

    def add(self, value: object) -> None:
        if self.fail_audit and isinstance(value, AuditEvent):
            raise RuntimeError("injected audit failure")
        self.added.append(value)

    async def execute(self, statement: object) -> _Result:
        return _Result(self.campaign)

    async def commit(self) -> None:
        self.commit_calls += 1

    async def rollback(self) -> None:
        self.rollback_calls += 1


class _Provider:
    def __init__(self, session: _AdminEnrollmentSession) -> None:
        self.session = session

    @asynccontextmanager
    async def __call__(self):
        yield self.session


def _principal() -> AdminPrincipal:
    user_id = uuid4()
    return AdminPrincipal(
        user=AdminUser(
            id=user_id,
            username="first-admin",
            password_digest="unused",
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
async def test_admin_creates_show_once_campaign_and_audits_safely() -> None:
    """A campaign create response may expose the bearer once, but persistence/audit may not."""
    request_marker = "Bearer campaign-request-secret-marker"
    session = _AdminEnrollmentSession()
    app = create_app(_settings(), session_provider=_Provider(session))
    app.dependency_overrides[require_admin] = _principal

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/api/admin/enrollment/campaigns",
            headers={"X-Request-ID": request_marker},
            json={
                "expires_at": (NOW + timedelta(hours=1)).isoformat(),
                "max_uses": 2,
                "allowed_cidrs": ["192.168.100.0/24"],
                "target_platform": "linux",
                "policy": {"channel": "stable"},
                "label": "Office Linux",
                "site": "hq",
            },
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["token"].startswith("ec_")
    assert UUID(payload["id"])
    campaign = next(
        value for value in session.added if isinstance(value, EnrollmentCampaign)
    )
    audit = next(value for value in session.added if isinstance(value, AuditEvent))
    assert payload["token"] not in repr(campaign)
    assert payload["token"] not in repr(audit.details)
    assert request_marker not in repr(audit)
    assert audit.request_id.startswith("external_")
    assert audit.action == "enrollment_campaign.created"
    assert audit.details == {
        "allowed_cidrs": ["192.168.100.0/24"],
        "expires_at": campaign.expires_at.isoformat(),
        "label": "Office Linux",
        "max_uses": 2,
        "site": "hq",
        "target_platform": "linux",
    }
    assert session.commit_calls == 1
    assert session.rollback_calls == 0


@pytest.mark.asyncio
async def test_admin_claim_url_is_retired_but_campaign_revocation_remains_available() -> (
    None
):
    """A browser admin must not obtain a raw install claim from the legacy route."""
    claim_request_marker = "claim-token-request-marker"
    revoke_request_marker = "campaign-token-request-marker"
    campaign = issue_campaign(
        PEPPER,
        expires_at=NOW + timedelta(hours=1),
        max_uses=2,
        allowed_cidrs=("192.168.100.0/24",),
        target_platform="linux",
        policy={},
        now=NOW,
    ).record
    session = _AdminEnrollmentSession(campaign=campaign)
    app = create_app(_settings(), session_provider=_Provider(session))
    app.dependency_overrides[require_admin] = _principal

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        claim_response = await client.post(
            f"/api/admin/enrollment/campaigns/{campaign.id}/claims",
            headers={"X-Request-ID": claim_request_marker},
            json={
                "installation_session": "install-session-a",
                "hardware_fingerprint": "sha256:device-a",
                "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
            },
        )
        revoke_response = await client.post(
            f"/api/admin/enrollment/campaigns/{campaign.id}/revoke",
            headers={"X-Request-ID": revoke_request_marker},
        )

    assert claim_response.status_code == 404
    assert claim_request_marker not in claim_response.text
    assert not any(isinstance(value, EnrollmentClaim) for value in session.added)
    assert revoke_response.status_code == 204
    assert campaign.revoked_at is not None
    actions = [value.action for value in session.added if isinstance(value, AuditEvent)]
    assert actions == ["enrollment_campaign.revoked"]
    audits = [value for value in session.added if isinstance(value, AuditEvent)]
    assert all(audit.request_id.startswith("external_") for audit in audits)
    assert claim_request_marker not in repr(audits)
    assert revoke_request_marker not in repr(audits)
    assert session.commit_calls == 1


@pytest.mark.asyncio
async def test_admin_campaign_mutation_rolls_back_when_audit_fails() -> None:
    """No campaign may commit if its required audit append fails."""
    session = _AdminEnrollmentSession(fail_audit=True)
    app = create_app(_settings(), session_provider=_Provider(session))
    app.dependency_overrides[require_admin] = _principal

    with pytest.raises(RuntimeError, match="injected audit failure"):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="https://endpoint.sosnadmin.local",
        ) as client:
            await client.post(
                "/api/admin/enrollment/campaigns",
                headers={"X-Request-ID": "campaign-audit-failure"},
                json={
                    "expires_at": (NOW + timedelta(hours=1)).isoformat(),
                    "max_uses": 1,
                    "allowed_cidrs": ["192.168.100.0/24"],
                    "target_platform": "linux",
                    "policy": {},
                },
            )

    assert session.commit_calls == 0
    assert session.rollback_calls == 1


@pytest.mark.asyncio
async def test_invalid_campaign_constraints_return_bounded_validation_error() -> None:
    """Invalid CIDR input must not escape as an internal exception or echo its value."""
    invalid_marker = "not-a-cidr-secret-marker"
    session = _AdminEnrollmentSession()
    app = create_app(_settings(), session_provider=_Provider(session))
    app.dependency_overrides[require_admin] = _principal

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/api/admin/enrollment/campaigns",
            json={
                "expires_at": (NOW + timedelta(hours=1)).isoformat(),
                "max_uses": 1,
                "allowed_cidrs": [invalid_marker],
                "target_platform": "linux",
                "policy": {},
            },
        )

    assert response.status_code == 422
    assert invalid_marker not in response.text
    assert session.added == []


@pytest.mark.asyncio
async def test_admin_rejects_policy_outside_agent_delivery_contract() -> None:
    """An administrator must not persist policy the agent route cannot deliver."""
    session = _AdminEnrollmentSession()
    app = create_app(_settings(), session_provider=_Provider(session))
    app.dependency_overrides[require_admin] = _principal

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/api/admin/enrollment/campaigns",
            json={
                "expires_at": (NOW + timedelta(hours=1)).isoformat(),
                "max_uses": 1,
                "allowed_cidrs": ["192.168.100.0/24"],
                "target_platform": "linux",
                "policy": {f"key-{index}": "value" for index in range(33)},
            },
        )

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid enrollment campaign"}
    assert session.added == []
    assert session.commit_calls == 0
