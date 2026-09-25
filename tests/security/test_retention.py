"""Server removes only expired SecurityEvents in bounded worker batches."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.db.models import Device
from endpoint_server.security.models import SecurityEvent
from endpoint_server.security.retention import retain_security_events


NOW = datetime(2026, 9, 25, tzinfo=UTC)


@pytest.mark.asyncio
async def test_retention_deletes_expired_rows_in_bounded_batches() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(
            lambda sync: Device.metadata.create_all(
                sync, tables=[Device.__table__, SecurityEvent.__table__]
            )
        )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    device_id = uuid4()

    def event(expires_at):
        return SecurityEvent(
            event_identifier=uuid4(),
            device_id=device_id,
            event_type="USB_DEVICE_CONNECTED",
            channel="USB",
            severity="INFO",
            occurred_at=NOW - timedelta(days=30),
            received_at=NOW - timedelta(days=30),
            policy_id=uuid4(),
            policy_version=1,
            safe_metadata={"removable": True},
            expires_at=expires_at,
        )

    async with factory() as session:
        session.add(Device(id=device_id, device_identifier="retention-device"))
        session.add_all(
            [
                event(NOW - timedelta(seconds=1)),
                event(NOW),
                event(NOW + timedelta(days=1)),
            ]
        )
        await session.commit()
    async with factory() as session:
        assert await retain_security_events(session, now=NOW, limit=1) == 1
        await session.commit()
        assert await retain_security_events(session, now=NOW, limit=1) == 1
        await session.commit()
        assert await retain_security_events(session, now=NOW, limit=1) == 0
        await session.commit()
        assert len((await session.scalars(select(SecurityEvent))).all()) == 1
    await engine.dispose()


@pytest.mark.asyncio
async def test_retention_rejects_unbounded_limit() -> None:
    with pytest.raises(ValueError):
        await retain_security_events(None, limit=0)
