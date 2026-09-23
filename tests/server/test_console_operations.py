"""Admin operation journal stays bounded and excludes private requests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.db.models import AdminSession, AdminUser, AuditEvent, ContextCollection, Device, EndpointOperation, ServiceClient
from endpoint_server.main import create_app


@pytest.mark.asyncio
async def test_operation_journal_and_detail_are_secret_safe() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: [table.create(sync) for table in (
            ServiceClient.__table__, Device.__table__, AuditEvent.__table__,
            ContextCollection.__table__, EndpointOperation.__table__,
        )])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    owner = ServiceClient(id=uuid4(), client_identifier="helpdesk", display_name="Helpdesk")
    device = Device(id=uuid4(), device_identifier="OP-01")
    collection_id = uuid4()
    operation = EndpointOperation(
        id=uuid4(), requested_by_service_client_id=owner.id, device_id=device.id,
        idempotency_key="private-request-key", capability="context.diagnostic.collect",
        parameters={"reason": "private-parameter"}, correlation={"secret": "private-correlation"},
        status="queued", deadline_at=now + timedelta(hours=1),
        context_collection_id=collection_id,
    )
    async with sessions() as session:
        session.add_all([owner, device, operation]); await session.flush()
        session.add(ContextCollection(
            id=collection_id, device_id=device.id, profile="diagnostic_v1", requested_by="helpdesk",
            idempotency_key="collection-key", operation_id=operation.id, status="requested", requested_at=now,
        ))
        await session.commit()
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"operations-test-device-pepper", service_token_pepper=b"operations-test-service-pepper",
        session_secret=b"operations-test-session-secret", allowed_agent_cidrs=(), allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"), endpoint_operations_api_enabled=True,
    )
    app = create_app(settings, session_provider=sessions)
    user_id = uuid4()
    principal = AdminPrincipal(
        user=AdminUser(id=user_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
        session=AdminSession(id=uuid4(), admin_user_id=user_id, session_digest="unused", expires_at=now + timedelta(hours=1), revoked_at=None),
    )
    app.dependency_overrides[require_admin] = lambda: principal
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        listing = await client.get("/api/admin/operations?limit=1&operation_status=queued")
        detail = await client.get(f"/api/admin/operations/{operation.id}")
        canceled = await client.post(f"/api/admin/operations/{operation.id}/cancel")
    async with sessions() as session:
        audit = await session.scalar(select(AuditEvent).where(AuditEvent.action == "endpoint.operation_canceled"))
    await engine.dispose()
    assert listing.status_code == detail.status_code == 200
    assert listing.json()["total"] == 1
    assert listing.json()["data"][0]["owner"] == "helpdesk"
    assert detail.json()["safe_result"] is None
    assert canceled.status_code == 200
    assert canceled.json()["data"]["status"] == "canceled"
    assert audit is not None and audit.actor_kind == "admin"
    for secret in ("private-request-key", "private-parameter", "private-correlation"):
        assert secret not in listing.text + detail.text
