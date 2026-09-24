"""Read-only update projections count actual target states and remain bounded."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.db.models import AdminSession, AdminUser, Device, UpdateBuild, UpdateRollout, UpdateTarget
from endpoint_server.main import create_app


@pytest.mark.asyncio
async def test_rollout_read_has_exact_status_counts_and_bounded_targets() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: [table.create(sync) for table in (
            Device.__table__, UpdateBuild.__table__, UpdateRollout.__table__, UpdateTarget.__table__,
        )])
        # SQLite cannot express the PostgreSQL-only active-target partial index.
        await connection.exec_driver_sql("DROP INDEX uq_update_targets_active_device")
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    build = UpdateBuild(
        id=uuid4(), build_identifier="windows-stable-1", version="3.2.63",
        platform="windows_amd64", channel="stable", artifact_identifier="agent.tar.gz",
        artifact_url="https://endpoint.sosnadmin.local/api/agent/update/artifacts/agent",
        artifact_name="agent.tar.gz", archive_type="tar.gz", sha256_digest="a" * 64,
        size=100, release_notes="Release notes",
    )
    rollout = UpdateRollout(
        id=uuid4(), rollout_identifier="rollout-1", build_id=build.id,
        mode="canary", status="active", started_at=now,
    )
    completed = UpdateRollout(
        id=uuid4(), rollout_identifier="rollout-completed", build_id=build.id,
        mode="canary", status="completed", started_at=now, completed_at=now,
    )
    cancelled = UpdateRollout(
        id=uuid4(), rollout_identifier="rollout-cancelled", build_id=build.id,
        mode="canary", status="cancelled", started_at=now, cancelled_at=now,
    )
    devices = [Device(id=uuid4(), device_identifier=f"READ-{index}") for index in range(3)]
    targets = [UpdateTarget(
        id=uuid4(), rollout_id=rollout.id, device_id=device.id,
        target_identifier=f"target-{index}", operation_id=f"op-{index}",
        status=status, assigned_at=now,
    ) for index, (device, status) in enumerate(zip(devices, ("applied", "failed", "scheduled")))]
    previous_target = UpdateTarget(
        id=uuid4(), rollout_id=completed.id, device_id=devices[1].id,
        target_identifier="target-previous", operation_id="op-previous",
        status="applied", assigned_at=now - timedelta(days=1), terminal_at=now - timedelta(days=1),
    )
    async with sessions() as session:
        session.add_all([build, rollout, completed, cancelled, *devices, *targets, previous_target]); await session.commit()
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"update-read-device-pepper", service_token_pepper=b"update-read-service-pepper",
        session_secret=b"update-read-session-secret", allowed_agent_cidrs=(), allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"),
    )
    app = create_app(settings, session_provider=sessions)
    updates_schema = app.openapi()["paths"]["/api/admin/console/devices/{device_id}/updates"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert updates_schema["$ref"].endswith("/ConsoleDeviceUpdatesPageResponse")
    user_id = uuid4()
    principal = AdminPrincipal(
        user=AdminUser(id=user_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
        session=AdminSession(id=uuid4(), admin_user_id=user_id, session_digest="unused", expires_at=now + timedelta(hours=1), revoked_at=None),
    )
    app.dependency_overrides[require_admin] = lambda: principal
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        listing = await client.get("/api/admin/updates/rollouts")
        history_first = await client.get("/api/admin/updates/rollouts?terminal=true&limit=1")
        history_second = await client.get("/api/admin/updates/rollouts?terminal=true&limit=1&offset=1")
        detail = await client.get(f"/api/admin/updates/rollouts/{rollout.id}?limit=1")
        builds = await client.get("/api/admin/updates/builds")
        device_updates = await client.get(f"/api/admin/console/devices/{devices[1].id}/updates")
        device_updates_first = await client.get(f"/api/admin/console/devices/{devices[1].id}/updates?limit=1")
        device_updates_second = await client.get(f"/api/admin/console/devices/{devices[1].id}/updates?limit=1&offset=1")
    await engine.dispose()
    assert listing.status_code == 200
    assert listing.json()["total"] == 3
    assert next(item for item in listing.json()["data"] if item["id"] == str(rollout.id))["counts"] == {"applied": 1, "failed": 1, "scheduled": 1}
    assert history_first.status_code == history_second.status_code == 200
    assert history_first.json()["total"] == history_second.json()["total"] == 2
    assert {history_first.json()["data"][0]["id"], history_second.json()["data"][0]["id"]} == {str(completed.id), str(cancelled.id)}
    assert detail.status_code == 200
    assert detail.json()["targets_total"] == 3
    assert len(detail.json()["targets"]) == 1
    assert builds.status_code == 200
    assert "artifact_url" not in builds.text
    assert device_updates.status_code == 200
    assert device_updates.json()["data"][0]["status"] == "failed"
    assert device_updates_first.json()["total"] == device_updates_second.json()["total"] == 2
    assert device_updates_first.json()["data"][0]["rollout_id"] == str(rollout.id)
    assert device_updates_second.json()["data"][0]["rollout_id"] == str(completed.id)
