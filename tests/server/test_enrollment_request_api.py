from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

from endpoint_server.config import Settings
from endpoint_server.db.models import EnrollmentCampaign
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


class _Session:
    def __init__(self, campaigns: list[EnrollmentCampaign]) -> None:
        self.campaigns = campaigns
        self.added: list[object] = []
        self.commit_calls = 0

    async def execute(self, _statement: object) -> _Result:
        return _Result(self.campaigns)

    def add(self, value: object) -> None:
        self.added.append(value)

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
        expires_at=NOW + timedelta(hours=1),
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
