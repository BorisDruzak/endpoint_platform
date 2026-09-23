"""Console enrollment queues remain complete, bounded, and secret safe."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.db.models import AdminSession, AdminUser, EnrollmentRequest
from endpoint_server.main import create_app


@pytest.mark.asyncio
async def test_console_enrollment_queue_filters_and_paginates_without_claim_material() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(EnrollmentRequest.__table__.create)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    records = [
        EnrollmentRequest(
            id=uuid4(), created_at=now + timedelta(minutes=index),
            installation_id_digest=f"private-install-{index}",
            fingerprint_digest=f"private-fingerprint-{index}",
            request_capability_digest=f"private-capability-{index}",
            platform="windows", hostname=f"PC-{index}", macs=["00:11:22:33:44:55"],
            source_address="192.0.2.10", installer_version="3.2.63",
            installer_release_id="3.2.63", expires_at=now + timedelta(hours=1),
            status="waiting_approval" if index < 2 else "denied" if index == 2 else "approved",
        )
        for index in range(4)
    ]
    async with sessions() as session:
        session.add_all(records)
        await session.commit()
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"device-test-pepper",
        service_token_pepper=b"service-test-pepper",
        session_secret=b"session-test-secret",
        allowed_agent_cidrs=(), allowed_admin_cidrs=(), artifact_root=Path("artifacts"),
    )
    app = create_app(settings, session_provider=sessions)
    user_id = uuid4()
    app.dependency_overrides[require_admin] = lambda: AdminPrincipal(
        user=AdminUser(id=user_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
        session=AdminSession(id=uuid4(), admin_user_id=user_id, session_digest="unused", expires_at=now + timedelta(hours=1), revoked_at=None),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        pending = await client.get("/api/admin/console/enrollment/requests?queue=pending&limit=1&offset=1")
        denied = await client.get("/api/admin/console/enrollment/requests?queue=denied")
        active = await client.get("/api/admin/console/enrollment/requests?queue=active")
        other = await client.get("/api/admin/console/enrollment/requests?queue=other")
        invalid_queue = await client.get("/api/admin/console/enrollment/requests?queue=arbitrary")
        unbounded = await client.get("/api/admin/console/enrollment/requests?queue=pending&limit=501")
        invalid_offset = await client.get("/api/admin/console/enrollment/requests?queue=pending&offset=-1")
        app.dependency_overrides.clear()
        unauthorized = await client.get("/api/admin/console/enrollment/requests")
    await engine.dispose()

    assert pending.status_code == 200
    assert pending.json()["total"] == 2
    assert pending.json()["data"][0]["hostname"] == "PC-0"
    assert pending.json()["limit"] == pending.json()["offset"] == 1
    assert denied.status_code == 200 and denied.json()["total"] == 1
    assert active.status_code == 200 and active.json()["data"][0]["status"] == "approved"
    assert other.status_code == 200 and other.json()["total"] == 0
    assert invalid_queue.status_code == unbounded.status_code == invalid_offset.status_code == 422
    assert unauthorized.status_code == 401
    for private in ("private-install", "private-fingerprint", "private-capability"):
        assert private not in pending.text + denied.text
