"""Administrator request-queue tests for universal Windows enrollment."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.db.models import AdminSession, AdminUser, AuditEvent, EnrollmentCampaign, EnrollmentRequest
from endpoint_server.enrollment.campaigns import issue_campaign
from endpoint_server.enrollment.requests import CampaignSelection, build_enrollment_request
from endpoint_server.main import create_app


NOW = datetime(2026, 9, 19, tzinfo=UTC)
PEPPER = b"admin-request-api-device-pepper-for-testing"


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


def _campaign() -> EnrollmentCampaign:
    return issue_campaign(
        PEPPER,
        expires_at=NOW + timedelta(days=3650),
        max_uses=2,
        allowed_cidrs=("192.168.100.0/24",),
        target_platform="windows",
        policy={
            "policy_id": "windows-office-v1",
            "enrollment_mode": "manual",
            "allowed_installer_releases": ["1.0.0"],
        },
        now=NOW,
    ).record


def _request(campaign: EnrollmentCampaign) -> EnrollmentRequest:
    return build_enrollment_request(
        installation_id="win-00112233-4455-6677-8899-aabbccddeeff",
        hardware_fingerprint="sha256:windows-fingerprint-v1",
        request_capability="a" * 43,
        source_address=IPv4Address("192.168.100.10"),
        installer_version="1.0.0",
        installer_release_id="1.0.0",
        hostname="office-pc-01",
        selection=CampaignSelection("waiting_approval", campaign, "MANUAL_POLICY"),
        pepper=PEPPER,
        now=NOW,
        serial="serial-must-not-leak",
        manufacturer="Contoso",
        model="Workstation 17",
        macs=("00:11:22:33:44:55",),
    )


class _Result:
    def __init__(self, values: list[object]) -> None:
        self.values = values

    def scalar_one_or_none(self) -> object | None:
        return self.values[0] if self.values else None

    def scalars(self) -> _Result:
        return self

    def all(self) -> list[object]:
        return self.values


class _Session:
    def __init__(self, campaign: EnrollmentCampaign, record: EnrollmentRequest) -> None:
        self.campaign = campaign
        self.record = record
        self.added: list[object] = []
        self.commit_calls = 0
        self.rollback_calls = 0

    async def execute(self, statement: object) -> _Result:
        entity = statement.column_descriptions[0]["entity"]
        if entity is EnrollmentRequest:
            return _Result([self.record])
        if entity is EnrollmentCampaign:
            return _Result([self.campaign])
        raise AssertionError(f"unexpected query entity: {entity}")

    def add(self, value: object) -> None:
        self.added.append(value)

    async def commit(self) -> None:
        self.commit_calls += 1

    async def rollback(self) -> None:
        self.rollback_calls += 1


class _Provider:
    def __init__(self, session: _Session) -> None:
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
async def test_admin_queue_redacts_bindings_and_approval_is_audited() -> None:
    campaign = _campaign()
    record = _request(campaign)
    session = _Session(campaign, record)
    app = create_app(_settings(), session_provider=_Provider(session))
    principal = _principal()
    app.dependency_overrides[require_admin] = lambda: principal

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local"
    ) as client:
        queue = await client.get("/api/admin/enrollment/requests")
        approval = await client.post(
            f"/api/admin/enrollment/requests/{record.id}/approve",
            headers={"X-Request-ID": "admin-request-approval"},
        )

    assert queue.status_code == 200
    assert queue.json()["requests"] == [
        {
            "id": str(record.id),
            "status": "waiting_approval",
            "reason": "MANUAL_POLICY",
            "platform": "windows",
            "hostname": "office-pc-01",
            "manufacturer": "Contoso",
            "model": "Workstation 17",
            "serial": "serial-must-not-leak",
            "macs": ["00:11:22:33:44:55"],
            "source_address": "192.168.100.10",
            "installer_release_id": "1.0.0",
            "selected_campaign_id": str(campaign.id),
            "created_at": NOW.isoformat().replace("+00:00", "Z"),
            "expires_at": (NOW + timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
        }
    ]
    assert "fingerprint" not in queue.text
    assert "sha256:windows-fingerprint-v1" not in queue.text
    assert approval.status_code == 204
    assert record.status == "approved"
    assert record.decided_by == principal.user.id
    audit = next(value for value in session.added if isinstance(value, AuditEvent))
    assert audit.action == "enrollment_request.approved"
    assert audit.actor_identifier == str(principal.user.id)
    assert session.commit_calls == 1


@pytest.mark.asyncio
async def test_admin_can_deny_once_without_claim_or_secret_data() -> None:
    campaign = _campaign()
    record = _request(campaign)
    session = _Session(campaign, record)
    app = create_app(_settings(), session_provider=_Provider(session))
    app.dependency_overrides[require_admin] = _principal

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local"
    ) as client:
        response = await client.post(
            f"/api/admin/enrollment/requests/{record.id}/deny",
            json={"reason": "OPERATOR_DENIED"},
        )

    assert response.status_code == 204
    assert record.status == "denied"
    audit = next(value for value in session.added if isinstance(value, AuditEvent))
    assert audit.details == {"reason": "OPERATOR_DENIED", "status": "denied"}
    assert "ic_" not in repr(audit)
