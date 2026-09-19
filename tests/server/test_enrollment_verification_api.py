"""Capability-protected completion verification for universal enrollment."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from endpoint_server.config import Settings
from endpoint_server.db.models import Device, DeviceSession, EnrollmentRequest
from endpoint_server.context.models import ContextSnapshot
from endpoint_server.enrollment.requests import request_capability_digest
from endpoint_server.main import create_app


NOW = datetime.now(UTC)
PEPPER = b"verification-request-pepper"


class _Result:
    def __init__(self, value: object | None) -> None:
        self.value = value

    def scalar_one_or_none(self) -> object | None:
        return self.value


class _Session:
    def __init__(self, record: EnrollmentRequest, device: Device) -> None:
        self.record = record
        self.device = device
        self.added: list[object] = []

    async def execute(self, statement: object) -> _Result:
        entity = statement.column_descriptions[0]["entity"]
        if entity is EnrollmentRequest:
            return _Result(self.record)
        if entity is DeviceSession:
            return _Result(DeviceSession(
                id=uuid4(), device_id=self.device.id, session_identifier="gateway", expires_at=NOW + timedelta(minutes=1), closed_at=None, last_seen_at=NOW, source_address="192.168.100.10"
            ))
        if entity is ContextSnapshot:
            return _Result(ContextSnapshot(id=uuid4(), device_id=self.device.id, profile="baseline_v1", collected_at=NOW, normalized_projection={"profile": "baseline_v1"}, semantic_hash=None))
        raise AssertionError(f"unexpected query entity: {entity}")

    def add(self, value: object) -> None:
        self.added.append(value)

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


class _Provider:
    def __init__(self, session: _Session) -> None:
        self.session = session

    @asynccontextmanager
    async def __call__(self):
        yield self.session


@pytest.mark.asyncio
async def test_verification_completes_only_after_fresh_wss_and_baseline() -> None:
    device = Device(id=uuid4(), device_identifier="device-a", display_name="Office", retired_at=None)
    record = EnrollmentRequest(
        id=uuid4(), installation_id_digest="i", fingerprint_digest="f", request_capability_digest=request_capability_digest("a" * 43, PEPPER), platform="windows", hostname="office-pc", manufacturer=None, model=None, serial=None, product_uuid=None, macs=[], source_address="192.168.100.10", installer_version="1.0.0", installer_release_id="1.0.0", selected_campaign_id=uuid4(), status="device_registered", decision_reason=None, decided_at=None, decided_by=None, device_id=device.id, updated_at=NOW, expires_at=NOW + timedelta(hours=1)
    )
    app = create_app(Settings(database_url="postgresql+asyncpg://unused@localhost/unused", public_base_url="https://endpoint.sosnadmin.local", device_token_pepper=PEPPER, service_token_pepper=b"service", session_secret=b"secret", allowed_agent_cidrs=(), allowed_admin_cidrs=(), artifact_root=Path("artifacts")), session_provider=_Provider(_Session(record, device)))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        response = await client.post(f"/api/v1/enrollment/requests/{record.id}/verify", json={"request_capability": "a" * 43})

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert record.status == "completed"


@pytest.mark.asyncio
async def test_verification_reports_pending_device_registration_without_error() -> None:
    device = Device(id=uuid4(), device_identifier="device-a", display_name="Office", retired_at=None)
    record = EnrollmentRequest(
        id=uuid4(), installation_id_digest="i", fingerprint_digest="f", request_capability_digest=request_capability_digest("a" * 43, PEPPER), platform="windows", hostname="office-pc", manufacturer=None, model=None, serial=None, product_uuid=None, macs=[], source_address="192.168.100.10", installer_version="1.0.0", installer_release_id="1.0.0", selected_campaign_id=uuid4(), status="claim_issued", decision_reason=None, decided_at=None, decided_by=None, device_id=None, updated_at=NOW, expires_at=NOW + timedelta(hours=1)
    )
    app = create_app(Settings(database_url="postgresql+asyncpg://unused@localhost/unused", public_base_url="https://endpoint.sosnadmin.local", device_token_pepper=PEPPER, service_token_pepper=b"service", session_secret=b"secret", allowed_agent_cidrs=(), allowed_admin_cidrs=(), artifact_root=Path("artifacts")), session_provider=_Provider(_Session(record, device)))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        response = await client.post(f"/api/v1/enrollment/requests/{record.id}/verify", json={"request_capability": "a" * 43})

    assert response.status_code == 200
    assert response.json()["status"] == "claim_issued"
    assert response.json()["reason"] == "WAITING_DEVICE_REGISTRATION"
