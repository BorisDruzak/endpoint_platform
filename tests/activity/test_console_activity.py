"""Console Activity reads the latest validated current projection only."""

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
from endpoint_server.context.models import ContextCurrent, ContextSnapshot
from endpoint_server.db.models import AdminSession, AdminUser, Device, DeviceInstance, DeviceSession
from endpoint_server.main import create_app


@pytest.mark.asyncio
async def test_activity_route_uses_current_validated_observation_and_admin_session() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: [
            table.create(sync) for table in (
                Device.__table__, DeviceSession.__table__, DeviceInstance.__table__,
                ContextSnapshot.__table__, ContextCurrent.__table__,
            )
        ])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    device_id, snapshot_id = uuid4(), uuid4()
    device = Device(id=device_id, device_identifier="ACTIVITY-CONSOLE-01")
    envelope = {
        "schema_version": "device_context_v1", "profile": "activity_v1",
        "collected_at": (now - timedelta(minutes=1)).isoformat(), "warnings": [],
        "sections": {
            "user_login": "operator", "session_state": "ACTIVE", "idle_seconds": 99,
            "foreground": {"process_name": "chrome.exe", "application_category": "browser"},
            "browser": None,
        },
    }
    latest = {
        **envelope,
        "sections": {
            **envelope["sections"], "idle_seconds": 23,
            "browser": {
                "browser_family": "chrome", "origin": "https://example.org",
                "domain": "example.org", "sensor_state": "ACTIVE",
                "extension_version": "0.1.0", "last_seen_at": now.isoformat(),
            },
        },
    }
    async with sessions() as session:
        session.add_all([
            device,
            DeviceSession(
                device_id=device_id, session_identifier="activity-session",
                created_at=now, last_seen_at=now, expires_at=now + timedelta(hours=1),
            ),
            ContextSnapshot(
                id=snapshot_id, collection_id=uuid4(), device_id=device_id,
                profile="activity_v1", collected_at=now - timedelta(minutes=1),
                raw_payload={"private_marker": "MUST_NOT_LEAK"},
                normalized_projection=envelope,
            ),
            ContextCurrent(
                device_id=device_id, profile="activity_v1", snapshot_id=snapshot_id,
                updated_at=now, last_observed_at=now, last_projection=latest,
            ),
        ])
        await session.commit()

    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"activity-device-pepper",
        service_token_pepper=b"activity-service-pepper",
        session_secret=b"activity-session-secret", allowed_agent_cidrs=(),
        allowed_admin_cidrs=(), artifact_root=Path("artifacts"),
        endpoint_policy_enabled=True,
    )
    app = create_app(settings, session_provider=sessions)
    path = f"/api/admin/console/devices/{device_id}/activity"
    async with AsyncClient(transport=ASGITransport(app=app), base_url=settings.public_base_url) as client:
        assert (await client.get(path)).status_code == 401
        admin_id = uuid4()
        app.dependency_overrides[require_admin] = lambda: AdminPrincipal(
            user=AdminUser(
                id=admin_id, username="operator", password_digest="unused",
                scopes=[], disabled_at=None,
            ),
            session=AdminSession(
                id=uuid4(), admin_user_id=admin_id, session_digest="unused",
                expires_at=now + timedelta(hours=1), revoked_at=None,
            ),
        )
        response = await client.get(path)
        missing = await client.get(f"/api/admin/console/devices/{uuid4()}/activity")
        async with sessions() as session:
            current = await session.scalar(select(ContextCurrent).where(
                ContextCurrent.device_id == device_id,
            ))
            assert current is not None
            current.last_observed_at = now - timedelta(minutes=3)
            await session.commit()
        stale = await client.get(path)
        async with sessions() as session:
            live_session = await session.scalar(select(DeviceSession).where(
                DeviceSession.device_id == device_id,
            ))
            assert live_session is not None
            live_session.closed_at = now
            await session.commit()
        offline = await client.get(path)
    await engine.dispose()

    assert response.status_code == 200, response.text
    assert missing.status_code == 404
    data = response.json()["data"]
    assert data["sections"]["idle_seconds"] == 23
    assert data["sections"]["browser"]["domain"] == "example.org"
    assert data["fresh"] is True
    assert data["online"] is True
    assert stale.json()["data"]["online"] is True
    assert stale.json()["data"]["fresh"] is False
    assert offline.json()["data"]["online"] is False
    assert offline.json()["data"]["fresh"] is False
    assert "MUST_NOT_LEAK" not in response.text
    assert "raw_payload" not in response.text


@pytest.mark.asyncio
async def test_activity_route_returns_null_for_malformed_current_projection() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: [
            table.create(sync) for table in (
                Device.__table__, DeviceSession.__table__, DeviceInstance.__table__,
                ContextSnapshot.__table__, ContextCurrent.__table__,
            )
        ])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    device_id = uuid4()
    async with sessions() as session:
        session.add(Device(id=device_id, device_identifier="ACTIVITY-INVALID-01"))
        await session.commit()
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"activity-device-pepper",
        service_token_pepper=b"activity-service-pepper",
        session_secret=b"activity-session-secret", allowed_agent_cidrs=(),
        allowed_admin_cidrs=(), artifact_root=Path("artifacts"),
        endpoint_policy_enabled=True,
    )
    app = create_app(settings, session_provider=sessions)
    admin_id = uuid4()
    app.dependency_overrides[require_admin] = lambda: AdminPrincipal(
        user=AdminUser(id=admin_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
        session=AdminSession(id=uuid4(), admin_user_id=admin_id, session_digest="unused",
                             expires_at=datetime.now(UTC) + timedelta(hours=1), revoked_at=None),
    )
    path = f"/api/admin/console/devices/{device_id}/activity"
    async with AsyncClient(transport=ASGITransport(app=app), base_url=settings.public_base_url) as client:
        missing = await client.get(path)
        now = datetime.now(UTC)
        async with sessions() as session:
            session.add(ContextCurrent(
                device_id=device_id, profile="activity_v1", snapshot_id=uuid4(),
                updated_at=now, last_observed_at=now,
                last_projection={"sections": {"window_title": "MUST_NOT_LEAK"}},
            ))
            await session.commit()
        malformed = await client.get(path)
    await engine.dispose()
    assert missing.status_code == 200 and missing.json() == {"data": None}
    assert malformed.status_code == 200 and malformed.json() == {"data": None}
    assert "MUST_NOT_LEAK" not in malformed.text
