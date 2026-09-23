"""Read-only Audit projection is bounded, filterable, and redacted."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.db.models import AdminSession, AdminUser, AuditEvent
from endpoint_server.main import create_app


@pytest.mark.asyncio
async def test_audit_events_are_paginated_filtered_and_redacted_on_read() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(AuditEvent.__table__.create)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    device_id = uuid4()
    async with sessions() as session:
        session.add_all([
            AuditEvent(
                id=uuid4(), created_at=now - timedelta(minutes=1), actor_kind="admin",
                actor_identifier="operator", action="device.created", object_kind="device",
                object_identifier=str(device_id), request_id="request-one",
                details={"status": "ready", "nested": {"access_token": "secret-marker"}},
            ),
            AuditEvent(
                id=uuid4(), created_at=now, actor_kind="service",
                actor_identifier="agent", action="device.seen", object_kind="device",
                object_identifier=str(device_id), request_id="request-two",
                details={"message": "Bearer another-secret"},
            ),
        ])
        await session.commit()
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"audit-test-device-pepper",
        service_token_pepper=b"audit-test-service-pepper",
        session_secret=b"audit-test-session-secret",
        allowed_agent_cidrs=(), allowed_admin_cidrs=(), artifact_root=Path("artifacts"),
    )
    app = create_app(settings, session_provider=sessions)
    user_id = uuid4()
    app.dependency_overrides[require_admin] = lambda: AdminPrincipal(
        user=AdminUser(id=user_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
        session=AdminSession(id=uuid4(), admin_user_id=user_id, session_digest="unused", expires_at=now + timedelta(hours=1), revoked_at=None),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        page = await client.get("/api/admin/audit/events?limit=1")
        filtered = await client.get(f"/api/admin/audit/events?actor=operator&object_kind=device&object_id={device_id}&request_id=request-one")
        invalid_page = await client.get("/api/admin/audit/events?limit=101")
        invalid_date = await client.get("/api/admin/audit/events?since=2026-01-01T00:00:00")
        mutation = await client.delete("/api/admin/audit/events")
    await engine.dispose()
    assert page.status_code == 200 and page.json()["total"] == 2 and len(page.json()["data"]) == 1
    assert filtered.status_code == 200 and filtered.json()["total"] == 1
    assert filtered.json()["data"][0]["details"]["nested"]["access_token"] == "[REDACTED]"
    assert "secret-marker" not in filtered.text and "another-secret" not in page.text
    assert invalid_page.status_code == invalid_date.status_code == 422
    assert mutation.status_code == 405
