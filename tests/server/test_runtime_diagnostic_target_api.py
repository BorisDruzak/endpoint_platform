"""Acceptance tests for Endpoint-owned runtime diagnostic target state."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
import ipaddress
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from endpoint_server.config import Settings
from endpoint_server.db.models import Device, DeviceCredential, DeviceInstance, DeviceSession
from endpoint_server.enrollment.credentials import device_token_digest
from endpoint_server.main import create_app


def _settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"device-pepper",
        service_token_pepper=b"service-pepper",
        session_secret=b"runtime-session-secret",
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        allowed_admin_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        artifact_root=Path("artifacts"),
    )


def _as_utc(value: datetime) -> datetime:
    """Normalize SQLite fixture timestamps without altering production UTC values."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


@pytest_asyncio.fixture
async def session_provider() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = (
        Device.__table__,
        DeviceCredential.__table__,
        DeviceInstance.__table__,
        DeviceSession.__table__,
    )
    async with engine.begin() as connection:
        await connection.execute(text("PRAGMA foreign_keys=ON"))
        await connection.run_sync(
            lambda sync: Device.metadata.create_all(sync, tables=tables)
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def _device_with_bearer(
    session_provider: async_sessionmaker[AsyncSession], token: str
) -> Device:
    device = Device(id=uuid4(), device_identifier="runtime-device", display_name="Runtime", retired_at=None)
    async with session_provider() as session:
        session.add_all(
            (
                device,
                DeviceCredential(
                    id=uuid4(),
                    device_id=device.id,
                    credential_identifier="runtime-credential",
                    token_digest=device_token_digest(token, b"device-pepper"),
                    pending_token_digest=None,
                    rotation_overlap_expires_at=None,
                    expires_at=None,
                    revoked_at=None,
                ),
            )
        )
        await session.commit()
    return device


@pytest.mark.asyncio
async def test_heartbeat_persists_server_observed_session_and_ignores_reported_time(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Presence must be established by server time, never by a client clock claim."""
    token = "runtime-device-token"
    device = await _device_with_bearer(session_provider, token)
    app = create_app(_settings(), session_provider)

    before = datetime.now(UTC)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 12345)),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/agent/v1/runtime/heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "schema_version": "agent_heartbeat_v1",
                "device_id": str(device.id),
                "platform": "linux",
                "agent_version": "3.2.11",
                "reported_at": "2000-01-01T00:00:00Z",
            },
        )

    assert response.status_code == 204
    async with session_provider() as session:
        instance = await session.scalar(select(DeviceInstance).where(DeviceInstance.device_id == device.id))
        runtime_session = await session.scalar(select(DeviceSession).where(DeviceSession.device_id == device.id))
    assert instance is not None
    assert runtime_session is not None
    assert instance.agent_version == "3.2.11"
    assert instance.last_seen_at is not None and _as_utc(instance.last_seen_at) >= before
    assert runtime_session.last_handshake_at is not None
    assert _as_utc(runtime_session.last_handshake_at) >= before
    assert _as_utc(runtime_session.expires_at) - _as_utc(runtime_session.last_handshake_at) == timedelta(seconds=90)


@pytest.mark.asyncio
async def test_heartbeat_rejects_body_device_other_than_bearer_device(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """A bearer must never be able to write runtime state for another device."""
    token = "runtime-device-token"
    await _device_with_bearer(session_provider, token)
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 12345)),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/agent/v1/runtime/heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "schema_version": "agent_heartbeat_v1",
                "device_id": str(uuid4()),
                "platform": "linux",
                "agent_version": "3.2.11",
                "reported_at": "2026-08-16T10:00:00Z",
            },
        )

    assert response.status_code == 401
