from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

from endpoint_server.config import Settings
from endpoint_server.db.models import (
    EnrollmentCampaign,
    EnrollmentClaim,
    EnrollmentRequest,
    EnrollmentRequestClaimEnvelope,
)
from endpoint_server.enrollment.campaigns import issue_campaign
from endpoint_server.main import create_app


NOW = datetime.now(UTC)
PEPPER = b"enrollment-request-api-test-pepper-with-enough-entropy"


class _Result:
    def __init__(self, campaigns: list[EnrollmentCampaign]) -> None:
        self._campaigns = campaigns

    def scalars(self) -> "_Result":
        return self

    def all(self) -> list[EnrollmentCampaign]:
        return self._campaigns

    def scalar_one_or_none(self) -> object | None:
        return self._campaigns[0] if self._campaigns else None


class _Session:
    def __init__(self, campaigns: list[EnrollmentCampaign]) -> None:
        self.campaigns = campaigns
        self.added: list[object] = []
        self.commit_calls = 0

    async def execute(self, _statement: object) -> _Result:
        entity = _statement.column_descriptions[0]["entity"]
        if entity is EnrollmentCampaign:
            return _Result(self.campaigns)
        if entity is EnrollmentRequest:
            return _Result(
                [value for value in self.added if isinstance(value, EnrollmentRequest)]
            )
        if entity is EnrollmentRequestClaimEnvelope:
            return _Result(
                [
                    value
                    for value in self.added
                    if isinstance(value, EnrollmentRequestClaimEnvelope)
                ]
            )
        raise AssertionError(f"unexpected query entity: {entity}")

    def add(self, value: object) -> None:
        self.added.append(value)

    def add_all(self, values: tuple[object, ...]) -> None:
        self.added.extend(values)

    async def commit(self) -> None:
        self.commit_calls += 1

    async def rollback(self) -> None:
        return None


class _Provider:
    def __init__(self, session: _Session) -> None:
        self.session = session

    @asynccontextmanager
    async def __call__(self) -> AsyncIterator[_Session]:
        yield self.session


def _settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=PEPPER,
        service_token_pepper=b"service-pepper",
        session_secret=b"enrollment-request-api-session-secret",
        allowed_agent_cidrs=(),
        allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"),
    )


def _campaign() -> EnrollmentCampaign:
    return issue_campaign(
        PEPPER,
        expires_at=NOW + timedelta(days=3650),
        max_uses=2,
        allowed_cidrs=("127.0.0.0/8",),
        target_platform="windows",
        policy={
            "policy_id": "windows-office-v1",
            "enrollment_mode": "auto",
            "allowed_installer_releases": ["1.0.0"],
        },
        now=NOW,
    ).record


@pytest.mark.asyncio
async def test_create_request_selects_the_single_server_campaign_without_bearer() -> None:
    session = _Session([_campaign()])
    app = create_app(_settings(), session_provider=_Provider(session))
    body = {
        "schema_version": "pre_enrollment_request_create_v1",
        "platform": "windows",
        "installation_id": "win-00112233-4455-6677-8899-aabbccddeeff",
        "hardware_fingerprint": "sha256:windows-fingerprint-v1",
        "request_capability": "a" * 43,
        "installer_version": "1.0.0",
        "installer_release_id": "1.0.0",
        "requested_at": NOW.isoformat(),
        "hostname": "office-pc-01",
        "macs": ["aabbccddeeff"],
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        response = await client.post("/api/v1/enrollment/requests", json=body)

    assert response.status_code == 201
    assert response.json()["status"] == "auto_approved"
    assert "campaign_id" not in response.json()
    assert session.commit_calls == 1


@pytest.mark.asyncio
async def test_status_requires_capability_and_never_returns_a_claim() -> None:
    session = _Session([_campaign()])
    app = create_app(_settings(), session_provider=_Provider(session))
    create_body = {
        "schema_version": "pre_enrollment_request_create_v1",
        "platform": "windows",
        "installation_id": "win-00112233-4455-6677-8899-aabbccddeeff",
        "hardware_fingerprint": "sha256:windows-fingerprint-v1",
        "request_capability": "a" * 43,
        "installer_version": "1.0.0",
        "installer_release_id": "1.0.0",
        "requested_at": NOW.isoformat(),
        "hostname": "office-pc-01",
        "macs": [],
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        created = await client.post("/api/v1/enrollment/requests", json=create_body)
        request_id = created.json()["request_id"]
        allowed = await client.post(
            f"/api/v1/enrollment/requests/{request_id}/status",
            json={"request_capability": "a" * 43},
        )
        denied = await client.post(
            f"/api/v1/enrollment/requests/{request_id}/status",
            json={"request_capability": "b" * 43},
        )

    assert allowed.status_code == 200
    assert allowed.json()["status"] == "auto_approved"
    assert "claim" not in allowed.text
    assert denied.status_code == 404


@pytest.mark.asyncio
async def test_approved_request_claim_is_bound_and_recoverable_after_dropped_response() -> None:
    session = _Session([_campaign()])
    app = create_app(_settings(), session_provider=_Provider(session))
    create_body = {
        "schema_version": "pre_enrollment_request_create_v1",
        "platform": "windows",
        "installation_id": "win-00112233-4455-6677-8899-aabbccddeeff",
        "hardware_fingerprint": "sha256:windows-fingerprint-v1",
        "request_capability": "a" * 43,
        "installer_version": "1.0.0",
        "installer_release_id": "1.0.0",
        "requested_at": NOW.isoformat(),
        "hostname": "office-pc-01",
        "macs": [],
    }
    claim_proof = {
        "request_capability": "a" * 43,
        "installation_id": create_body["installation_id"],
        "hardware_fingerprint": create_body["hardware_fingerprint"],
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        created = await client.post("/api/v1/enrollment/requests", json=create_body)
        request_id = created.json()["request_id"]
        first = await client.post(
            f"/api/v1/enrollment/requests/{request_id}/claim", json=claim_proof
        )
        retry = await client.post(
            f"/api/v1/enrollment/requests/{request_id}/claim", json=claim_proof
        )

    assert first.status_code == 200
    assert first.json()["claim"].startswith("ic_")
    assert retry.json() == first.json()
    record = next(value for value in session.added if isinstance(value, EnrollmentRequest))
    claim = next(value for value in session.added if isinstance(value, EnrollmentClaim))
    envelope = next(
        value
        for value in session.added
        if isinstance(value, EnrollmentRequestClaimEnvelope)
    )
    assert record.status == "claim_issued"
    assert claim.enrollment_request_id == record.id
    assert first.json()["claim"].encode("ascii") not in envelope.encrypted_token
