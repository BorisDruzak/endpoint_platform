"""Device-authenticated HTTPS Gateway delivery boundary."""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from endpoint_server.config import Settings
from endpoint_server.context.models import ContextCollection
from endpoint_server.db.models import (
    Command,
    CommandDelivery,
    CommandResult,
    Device,
    DeviceCredential,
    DeviceInstance,
    DeviceSession,
)
from endpoint_server.enrollment.credentials import device_token_digest
from endpoint_server.main import create_app


def _settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"device-pepper",
        service_token_pepper=b"service-pepper",
        session_secret=b"gateway-test-secret",
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        allowed_admin_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        artifact_root=Path("artifacts"),
    )


@pytest_asyncio.fixture
async def session_provider() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = (
        Device.__table__,
        DeviceCredential.__table__,
        DeviceInstance.__table__,
        DeviceSession.__table__,
        Command.__table__,
        CommandDelivery.__table__,
        CommandResult.__table__,
        ContextCollection.__table__,
    )
    async with engine.begin() as connection:
        await connection.execute(text("PRAGMA foreign_keys=ON"))
        await connection.run_sync(
            lambda sync: Device.metadata.create_all(sync, tables=tables)
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest.mark.asyncio
async def test_gateway_replays_unacknowledged_delivery_without_creating_a_second_command(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    token = "gateway-device-token"
    async with session_provider() as session:
        device = Device(
            id=uuid4(), device_identifier="gateway-device", display_name="ALT"
        )
        session.add(device)
        await session.flush()
        session.add_all(
            (
                device,
                DeviceCredential(
                    id=uuid4(),
                    device_id=device.id,
                    credential_identifier="gateway-credential",
                    token_digest=device_token_digest(token, b"device-pepper"),
                    pending_token_digest=None,
                    rotation_overlap_expires_at=None,
                    expires_at=None,
                    revoked_at=None,
                ),
                ContextCollection(
                    id=uuid4(),
                    device_id=device.id,
                    profile="baseline_v1",
                    requested_by="gateway-service",
                    idempotency_key="gateway-request-0001",
                    status="requested",
                    requested_at=datetime.now(UTC),
                ),
            )
        )
        await session.commit()

    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 12345)),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        first = await client.get(
            "/agent/v1/gateway/commands/next",
            headers={"Authorization": f"Bearer {token}"},
        )
        retry = await client.get(
            "/agent/v1/gateway/commands/next",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert first.status_code == 200
    assert retry.status_code == 200
    assert retry.json()["command_id"] == first.json()["command_id"]
    async with session_provider() as session:
        assert len((await session.scalars(select(Command))).all()) == 1
        assert len((await session.scalars(select(CommandDelivery))).all()) == 1
