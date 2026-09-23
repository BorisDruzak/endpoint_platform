"""Bounded, safe fleet projections for the browser Console."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.context.models import ContextCollection, ContextCurrent, ContextSnapshot
from endpoint_server.db.models import AuditEvent, Device, DeviceInstance, DeviceSession, EndpointOperation, EnrollmentRequest, UpdateTarget
from endpoint_server.console.fleet import dashboard_fleet, list_fleet
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.db.models import AdminSession, AdminUser
from endpoint_server.main import create_app


@pytest.mark.asyncio
async def test_fleet_is_paginated_and_does_not_expose_raw_context() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = [
        Device.__table__, DeviceInstance.__table__, DeviceSession.__table__,
        ContextSnapshot.__table__, ContextCurrent.__table__, UpdateTarget.__table__,
        EnrollmentRequest.__table__, EndpointOperation.__table__,
    ]
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: [table.create(sync) for table in tables])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    first, second = Device(device_identifier="PC-01", display_name="Первый"), Device(device_identifier="PC-02", display_name="Второй")
    collection_id = uuid4()
    snapshot = ContextSnapshot(
        collection_id=collection_id, device_id=first.id, profile="inventory_v1",
        collected_at=now, raw_payload={"secret": "must-not-leak"},
        normalized_projection={
            "schema_version": "device_context_v1", "profile": "inventory_v1",
            "collected_at": now.isoformat(), "warnings": [],
            "sections": {
                "system": {"hostname": "PC-01", "platform": "windows", "os_name": "Windows 11", "os_version": "11"},
                "hardware": {"cpu_model": "Sample CPU"},
                "memory": {"total_bytes": 17179869184, "module_count": 0, "modules": []},
                "storage": {"physical_devices": []}, "interfaces": [],
            },
        },
    )
    # Defaults are assigned at insert time; explicit IDs keep the fixture small.
    first.id, second.id, snapshot.id = uuid4(), uuid4(), uuid4()
    snapshot.device_id = first.id
    async with sessions() as session:
        session.add_all([first, second, snapshot])
        await session.flush()
        session.add_all([
            DeviceSession(
                device_id=first.id, session_identifier="session-1", expires_at=now + timedelta(hours=1),
                last_seen_at=now, created_at=now,
            ),
            DeviceInstance(device_id=first.id, instance_identifier="instance-1", agent_version="3.2.63", last_result_sequence=0),
            ContextCurrent(device_id=first.id, profile="inventory_v1", snapshot_id=snapshot.id, updated_at=now),
        ])
        await session.commit()
    queries = 0

    def count_query(*_: object) -> None:
        nonlocal queries
        queries += 1

    event.listen(engine.sync_engine, "before_cursor_execute", count_query)
    try:
        async with sessions() as session:
            page = await list_fleet(session, limit=1, offset=0)
            online = await list_fleet(session, limit=10, offset=0, online=True)
            windows = await list_fleet(session, limit=10, offset=0, platform="windows")
            list_queries = queries
            dashboard = await dashboard_fleet(session)
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", count_query)
        await engine.dispose()
    assert page["total"] == 2
    assert len(page["data"]) == 1
    assert online["total"] == 1
    assert online["data"][0]["agent_version"] == "3.2.63"
    assert online["data"][0]["os_name"] == "Windows 11"
    assert online["data"][0]["ram_bytes"] == 17179869184
    assert windows["total"] == 1
    assert dashboard["total"] == 2
    assert dashboard["online"] == 1
    assert dashboard["context_stale"] == 1
    assert {item["version"] for item in dashboard["versions"]} == {"3.2.63", None}
    assert "must-not-leak" not in str(page)
    assert list_queries <= 6
    assert queries <= 20


@pytest.mark.asyncio
async def test_console_device_api_uses_session_and_safe_projection() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: [
            table.create(sync) for table in (
                Device.__table__, DeviceSession.__table__, DeviceInstance.__table__,
                ContextCollection.__table__, ContextSnapshot.__table__, ContextCurrent.__table__,
                AuditEvent.__table__, UpdateTarget.__table__,
            )
        ])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    device = Device(id=uuid4(), device_identifier="CONSOLE-01", display_name="Console test")
    snapshot = ContextSnapshot(
        id=uuid4(), collection_id=uuid4(), device_id=device.id, profile="session_v1",
        collected_at=now, raw_payload={"device_token": "private-token"},
        normalized_projection={
            "schema_version": "device_context_v1", "profile": "session_v1",
            "collected_at": now.isoformat(), "warnings": [],
            "sections": {"current_user_login": "operator", "interactive_session_present": True},
        },
    )
    inventory_snapshots = [ContextSnapshot(
        id=uuid4(), collection_id=uuid4(), device_id=device.id, profile="inventory_v1",
        collected_at=now - timedelta(days=2 - index), raw_payload={"secret": "inventory-private"},
        normalized_projection={
            "schema_version": "device_context_v1", "profile": "inventory_v1",
            "collected_at": (now - timedelta(days=2 - index)).isoformat(), "warnings": [],
            "sections": {
                "system": {"hostname": "CONSOLE-01", "platform": "windows"},
                "hardware": {}, "memory": {"total_bytes": size, "module_count": 0, "modules": []},
                "storage": {"physical_devices": []}, "interfaces": [],
            },
        },
    ) for index, size in enumerate((8 * 1024 ** 3, 16 * 1024 ** 3))]
    async with sessions() as session:
        session.add_all([device, snapshot, *inventory_snapshots])
        await session.flush()
        session.add(ContextCurrent(device_id=device.id, profile="session_v1", snapshot_id=snapshot.id, updated_at=now))
        await session.commit()
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"fleet-test-device-pepper", service_token_pepper=b"fleet-test-service-pepper",
        session_secret=b"fleet-test-session-secret", allowed_agent_cidrs=(), allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"),
    )
    app = create_app(settings, session_provider=sessions)
    user_id = uuid4()
    principal = AdminPrincipal(
        user=AdminUser(id=user_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
        session=AdminSession(id=uuid4(), admin_user_id=user_id, session_digest="unused", expires_at=now + timedelta(hours=1), revoked_at=None),
    )
    app.dependency_overrides[require_admin] = lambda: principal
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        response = await client.get(f"/api/admin/console/devices/{device.id}")
        changes = await client.get(f"/api/admin/console/devices/{device.id}/changes")
        first_refresh = await client.post(
            f"/api/admin/console/devices/{device.id}/context/collections",
            headers={"Idempotency-Key": "console-refresh-1"}, json={"profile": "health_v1"},
        )
        replay_refresh = await client.post(
            f"/api/admin/console/devices/{device.id}/context/collections",
            headers={"Idempotency-Key": "console-refresh-1"}, json={"profile": "health_v1"},
        )
    async with sessions() as session:
        collection_count = await session.scalar(select(func.count()).select_from(ContextCollection))
        audit_count = await session.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "context.collection_requested"))
    await engine.dispose()
    assert response.status_code == 200
    assert response.json()["snapshots"][0]["sections"]["current_user_login"] == "operator"
    assert "private-token" not in response.text
    assert "device_token" not in response.text
    assert changes.status_code == 200
    assert any(row["code"] == "RAM_CHANGED" and row["before_value"] == 8 * 1024 ** 3 and row["after_value"] == 16 * 1024 ** 3 for row in changes.json()["data"])
    assert "inventory-private" not in changes.text
    assert first_refresh.status_code == 201
    assert replay_refresh.status_code == 200
    assert first_refresh.json()["data"]["id"] == replay_refresh.json()["data"]["id"]
    assert collection_count == audit_count == 1
