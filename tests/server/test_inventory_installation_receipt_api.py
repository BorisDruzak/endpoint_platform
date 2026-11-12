"""Service-scoped lookup of enrollment and heartbeat evidence."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from endpoint_server.auth import scopes
from endpoint_server.config import Settings
from endpoint_server.db.base import Base
from endpoint_server.db.models import (
    Device, DeviceInstance, DeviceSession, EnrollmentCampaign, EnrollmentClaim, EnrollmentRequest,
)
from endpoint_server.enrollment.campaigns import issue_install_claim
from endpoint_server.enrollment.requests import CampaignSelection, build_enrollment_request
from endpoint_server.main import create_app


PATH = "/api/v1/enrollment/installation-receipts/lookup"
SCOPE = "enrollment.installation-receipts.read"
PEPPER = b"test-device-pepper"
FINGERPRINT = "sha256:synthetic-hardware-fingerprint"


@pytest.fixture
def receipt_app(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[
        model.__table__ for model in (
            Device, DeviceInstance, DeviceSession, EnrollmentClaim, EnrollmentRequest,
        )
    ])
    with Session(engine) as db:
        @asynccontextmanager
        async def provider():
            class Adapter:
                async def execute(self, statement):
                    return db.execute(statement)
            yield Adapter()

        async def principal(session, token, pepper):
            if token not in ("fixture-receipt-reader", "fixture-device-reader"):
                return None
            scope = SCOPE if token == "fixture-receipt-reader" else "devices.read"
            return SimpleNamespace(credential=SimpleNamespace(scopes=(scope,)))

        monkeypatch.setattr(scopes, "_load_service_principal", principal)
        settings = Settings(
            database_url="postgresql+asyncpg://unused@localhost/unused",
            public_base_url="https://endpoint-staging.example.test",
            device_token_pepper=PEPPER, service_token_pepper=b"test-service-pepper",
            session_secret=b"test-session-secret", allowed_agent_cidrs=(), allowed_admin_cidrs=(),
            artifact_root=Path("artifacts"),
        )
        yield create_app(settings, session_provider=provider), db
    engine.dispose()


def assignment(db, *, platform, connection, installation=None):
    now = datetime.now(UTC)
    issued = now - timedelta(minutes=10)
    registered = now - timedelta(minutes=4)
    expires = issued + timedelta(minutes=30)
    installation = installation or f"inventory-{uuid4()}-{uuid4()}-" + "a" * 32
    campaign = EnrollmentCampaign(
        id=uuid4(), expires_at=now + timedelta(hours=1), max_uses=2, use_count=0,
        target_platform=platform,
    )
    request = build_enrollment_request(
        installation_id=installation, hardware_fingerprint=FINGERPRINT,
        request_capability="a" * 43, source_address=ip_address("192.0.2.1"),
        installer_version="3.2.0", installer_release_id="fixture", hostname="fixture-device",
        selection=CampaignSelection("auto_approved", campaign, "AUTO_POLICY"),
        pepper=PEPPER, now=issued + timedelta(minutes=1),
    )
    claim = issue_install_claim(
        campaign, PEPPER, installation_session=installation, hardware_fingerprint=FINGERPRINT,
        expires_at=expires, now=issued + timedelta(minutes=2),
    ).record
    device = Device(id=uuid4(), device_identifier=f"fixture-device-{uuid4()}")
    instance = DeviceInstance(id=uuid4(), device_id=device.id, instance_identifier="fixture-instance",
                              agent_version="3.2.0", platform=f"{platform}_amd64")
    request.platform = platform
    request.status = "device_registered"
    request.device_id = device.id
    claim.enrollment_request_id = request.id
    claim.device_id = device.id
    claim.claimed_at = registered
    db.add_all((request, claim, device, instance))
    if connection != "missing":
        created = registered + timedelta(seconds=1)
        heartbeat = now - timedelta(seconds=1)
        if connection == "previous":
            created = registered - timedelta(minutes=1)
        elif connection == "hello-only":
            heartbeat = created
        elif connection == "stale":
            heartbeat = now - timedelta(minutes=2)
        db.add(DeviceSession(
            device_id=device.id, device_instance_id=instance.id, session_identifier=f"fixture-gateway-{uuid4()}",
            created_at=created, last_seen_at=heartbeat,
            expires_at=now + timedelta(minutes=1),
            closed_at=now if connection == "closed" else None,
        ))
    db.flush()
    return {
        "installation_id": installation, "hardware_fingerprint": FINGERPRINT,
        "platform": platform, "issued_at": issued.isoformat(), "expires_at": expires.isoformat(),
    }, device.id


@pytest.mark.asyncio
async def test_receipt_requires_separate_service_scope(receipt_app):
    app, _ = receipt_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint-staging.example.test") as client:
        assert (await client.post(PATH, json={})).status_code == 401
        response = await client.post(PATH, json={}, headers={"Authorization": "Bearer fixture-device-reader"})
    assert response.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize(("platform", "connection", "expected"), [
    ("linux", "heartbeat", "connected"),
    ("windows", "heartbeat", "connected"),
    ("linux", "missing", "waiting_connection"),
    ("linux", "previous", "waiting_connection"),
    ("windows", "hello-only", "waiting_connection"),
    ("windows", "stale", "waiting_connection"),
    ("windows", "closed", "waiting_connection"),
])
async def test_receipt_releases_uuid_only_for_current_connection(receipt_app, platform, connection, expected):
    app, db = receipt_app
    body, device_id = assignment(db, platform=platform, connection=connection)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint-staging.example.test") as client:
        headers = {"Authorization": "Bearer fixture-receipt-reader"}
        response = await client.post(PATH, json=body, headers=headers)
        wrong = await client.post(PATH, json={**body, "hardware_fingerprint": "sha256:wrong-hardware"}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    result = response.json()
    assert result["state"] == expected
    if expected == "connected":
        assert result["device_id"] == str(device_id)
    else:
        assert result == {"state": expected}
    assert wrong.status_code == 409
    assert str(device_id) not in wrong.text
    assert FINGERPRINT not in response.text
    assert body["installation_id"] not in response.text


@pytest.mark.asyncio
async def test_receipt_does_not_use_a_claim_outside_assignment_window(receipt_app):
    app, db = receipt_app
    body, _ = assignment(db, platform="linux", connection="heartbeat")
    now = datetime.now(UTC)
    old = {**body, "issued_at": (now - timedelta(minutes=45)).isoformat(),
           "expires_at": (now - timedelta(minutes=15)).isoformat()}
    too_long = {**body, "expires_at": (now + timedelta(hours=1)).isoformat()}
    recent = {**body, "issued_at": (now - timedelta(minutes=3)).isoformat()}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint-staging.example.test") as client:
        headers = {"Authorization": "Bearer fixture-receipt-reader"}
        expired = await client.post(PATH, json=old, headers=headers)
        invalid = await client.post(PATH, json=too_long, headers=headers)
        outside_window = await client.post(PATH, json=recent, headers=headers)
        malformed = await client.post(PATH, json={**body, body["installation_id"]: FINGERPRINT}, headers=headers)
    assert malformed.status_code == 422
    assert malformed.headers["cache-control"] == "no-store"
    assert body["installation_id"] not in malformed.text
    assert FINGERPRINT not in malformed.text
    assert outside_window.status_code == 200
    assert outside_window.json() == {"state": "waiting_registration"}
    assert expired.status_code == 200
    assert expired.json() == {"state": "expired"}
    assert invalid.status_code == 422
    assert body["installation_id"] not in invalid.text


@pytest.mark.asyncio
@pytest.mark.parametrize("conflict", ["claim_binding", "retired_device"])
async def test_receipt_rejects_inconsistent_registration_evidence(receipt_app, conflict):
    app, db = receipt_app
    body, device_id = assignment(db, platform="linux", connection="heartbeat")
    if conflict == "claim_binding":
        db.query(EnrollmentClaim).one().installation_session_digest = "mismatched"
    else:
        db.get(Device, device_id).retired_at = datetime.now(UTC)
    db.flush()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint-staging.example.test") as client:
        response = await client.post(PATH, json=body, headers={"Authorization": "Bearer fixture-receipt-reader"})
    assert response.status_code == 409
    assert response.headers["cache-control"] == "no-store"
    assert str(device_id) not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("connection", ["heartbeat", "missing"])
async def test_assignment_expires_even_with_matching_claim(receipt_app, connection):
    app, db = receipt_app
    body, _ = assignment(db, platform="linux", connection=connection)
    body["expires_at"] = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint-staging.example.test") as client:
        response = await client.post(PATH, json=body, headers={"Authorization": "Bearer fixture-receipt-reader"})
    assert response.status_code == 200
    assert response.json() == {"state": "expired"}


@pytest.mark.asyncio
async def test_receipt_rejects_multiple_consumed_claims_for_one_assignment(receipt_app):
    app, db = receipt_app
    # SQLite treats the PostgreSQL partial unique index as unconditional.
    # Completed historical requests can legitimately coexist in PostgreSQL.
    db.execute(text("DROP INDEX uq_enrollment_requests_active_installation"))
    body, first = assignment(db, platform="linux", connection="heartbeat")
    _, second = assignment(db, platform="linux", connection="heartbeat", installation=body["installation_id"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint-staging.example.test") as client:
        response = await client.post(PATH, json=body, headers={"Authorization": "Bearer fixture-receipt-reader"})
    assert response.status_code == 409
    assert str(first) not in response.text
    assert str(second) not in response.text
