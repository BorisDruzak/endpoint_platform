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
    AuditEvent, Device, DeviceInstance, DeviceSession, EnrollmentCampaign, EnrollmentClaim, EnrollmentRequest,
    InventoryInstallationAssignment,
)
from endpoint_server.enrollment.campaigns import hardware_fingerprint_digest, issue_install_claim
from endpoint_server.enrollment.requests import CampaignSelection, build_enrollment_request, installation_id_digest
from endpoint_server.main import create_app


PATH = "/api/v1/enrollment/installation-receipts/lookup"
ASSIGN = "/api/v1/enrollment/installation-assignments"
ASSIGN_SCOPE = "enrollment.installation-assignments.issue"
OWNER = uuid4()
OTHER_OWNER = uuid4()
SCOPE = "enrollment.installation-receipts.read"
PEPPER = b"test-device-pepper"
FINGERPRINT = "sha256:synthetic-hardware-fingerprint"


@pytest.fixture
def receipt_app(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[
        model.__table__ for model in (
            AuditEvent, Device, DeviceInstance, DeviceSession, EnrollmentClaim, EnrollmentRequest,
            InventoryInstallationAssignment,
        )
    ])
    with Session(engine) as db:
        @asynccontextmanager
        async def provider():
            class Adapter:
                async def execute(self, statement):
                    return db.execute(statement)

                def add(self, value):
                    db.add(value)

                async def commit(self):
                    db.commit()

            yield Adapter()

        async def principal(session, token, pepper):
            permissions = {
                "fixture-receipt-reader": (OWNER, SCOPE),
                "fixture-device-reader": (OWNER, "devices.read"),
                "fixture-assignment-issuer": (OWNER, ASSIGN_SCOPE),
                "fixture-other-issuer": (OTHER_OWNER, ASSIGN_SCOPE),
                "fixture-other-reader": (OTHER_OWNER, SCOPE),
            }
            if token not in permissions:
                return None
            owner, scope = permissions[token]
            return SimpleNamespace(
                client=SimpleNamespace(id=owner, client_identifier="fixture-inventory"),
                credential=SimpleNamespace(scopes=(scope,)),
            )

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
    digest = installation_id_digest(installation, PEPPER)
    if db.get(InventoryInstallationAssignment, digest) is None:
        db.add(InventoryInstallationAssignment(
            installation_digest=digest, service_client_id=OWNER,
            fingerprint_digest=hardware_fingerprint_digest(FINGERPRINT, PEPPER),
            platform=platform, issued_at=issued, expires_at=expires, enrollment_request_id=request.id,
        ))
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
    return {"installation_id": installation}, device.id


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
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    result = response.json()
    assert result["state"] == expected
    if expected == "connected":
        assert result["device_id"] == str(device_id)
    else:
        assert result == {"state": expected}
    assert FINGERPRINT not in response.text
    assert body["installation_id"] not in response.text


@pytest.mark.asyncio
async def test_receipt_uses_persisted_window_and_redacts_malformed_input(receipt_app):
    app, db = receipt_app
    body, _ = assignment(db, platform="linux", connection="heartbeat")
    row = db.query(InventoryInstallationAssignment).one()
    row.issued_at = datetime.now(UTC) - timedelta(minutes=3)
    db.flush()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint-staging.example.test") as client:
        headers = {"Authorization": "Bearer fixture-receipt-reader"}
        outside = await client.post(PATH, json=body, headers=headers)
        malformed = await client.post(PATH, json={**body, body["installation_id"]: FINGERPRINT}, headers=headers)
    assert malformed.status_code == 422
    assert malformed.headers["cache-control"] == "no-store"
    assert body["installation_id"] not in malformed.text
    assert FINGERPRINT not in malformed.text
    assert outside.status_code == 200
    assert outside.json() == {"state": "waiting_registration"}


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
@pytest.mark.parametrize(("connection", "consumption", "expected"), [
    ("heartbeat", "registered", "connected"),
    ("missing", "registered", "waiting_connection"),
    ("heartbeat", "late", "expired"),
    ("heartbeat", "unconsumed", "expired"),
    ("heartbeat", "unbound", "expired"),
])
async def test_assignment_expiry_limits_registration_but_preserves_valid_receipts(receipt_app, connection, consumption, expected):
    app, db = receipt_app
    body, device_id = assignment(db, platform="linux", connection=connection)
    now = datetime.now(UTC)
    window = db.query(InventoryInstallationAssignment).one()
    window.expires_at = now - timedelta(minutes=1)
    if consumption == "unconsumed":
        db.query(EnrollmentClaim).one().claimed_at = None
    elif consumption == "late":
        db.query(EnrollmentClaim).one().claimed_at = now - timedelta(seconds=40)
    elif consumption == "unbound":
        window.enrollment_request_id = None
    db.flush()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint-staging.example.test") as client:
        response = await client.post(PATH, json=body, headers={"Authorization": "Bearer fixture-receipt-reader"})
    assert response.status_code == 200
    result = response.json()
    assert result["state"] == expected
    if expected == "connected":
        assert result["device_id"] == str(device_id)
    else:
        assert result == {"state": expected}


@pytest.mark.asyncio
async def test_receipt_uses_only_the_request_pinned_to_the_assignment(receipt_app):
    app, db = receipt_app
    # SQLite treats the PostgreSQL partial unique index as unconditional.
    # Completed historical requests can legitimately coexist in PostgreSQL.
    db.execute(text("DROP INDEX uq_enrollment_requests_active_installation"))
    body, first = assignment(db, platform="linux", connection="heartbeat")
    _, second = assignment(db, platform="linux", connection="heartbeat", installation=body["installation_id"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint-staging.example.test") as client:
        response = await client.post(PATH, json=body, headers={"Authorization": "Bearer fixture-receipt-reader"})
    assert response.status_code == 200
    assert response.json()["device_id"] == str(first)
    assert str(second) not in response.text


@pytest.mark.asyncio
async def test_issue_assignment_is_owner_bound_and_reuses_original_deadline(receipt_app):
    app, _ = receipt_app
    body = {
        "installation_id": f"inventory-{uuid4()}-{uuid4()}-" + "a" * 32,
        "platform": "linux",
        "hardware_fingerprint": FINGERPRINT,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint-staging.example.test") as client:
        issuer = {"Authorization": "Bearer fixture-assignment-issuer"}
        reader = {"Authorization": "Bearer fixture-receipt-reader"}
        other = {"Authorization": "Bearer fixture-other-issuer"}
        assert (await client.post(ASSIGN, json=body, headers=reader)).status_code == 403
        created = await client.post(ASSIGN, json=body, headers=issuer)
        repeated = await client.post(ASSIGN, json=body, headers=issuer)
        changed = await client.post(ASSIGN, json={**body, "platform": "windows"}, headers=issuer)
        collision = await client.post(ASSIGN, json=body, headers=other)
        pending = await client.post(PATH, json={"installation_id": body["installation_id"]}, headers=reader)
        hidden = await client.post(PATH, json={"installation_id": body["installation_id"]},
                                   headers={"Authorization": "Bearer fixture-other-reader"})
    assert created.status_code == repeated.status_code == 200
    assert created.json() == repeated.json()
    issued = datetime.fromisoformat(created.json()["issued_at"])
    expires = datetime.fromisoformat(created.json()["expires_at"])
    assert expires - issued == timedelta(minutes=30)
    assert changed.status_code == collision.status_code == 409
    assert pending.json() == {"state": "waiting_registration"}
    assert hidden.status_code == 404
    assert body["installation_id"] not in created.text
