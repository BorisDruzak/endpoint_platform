"""SecurityEvent is a separate, deduplicated persistence model."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.db.models import Device
from endpoint_server.security.models import SecurityEvent


NOW = datetime(2026, 9, 25, tzinfo=UTC)


@pytest.mark.asyncio
async def test_event_identity_is_unique_per_device() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(
            lambda sync: Device.metadata.create_all(
                sync, tables=[Device.__table__, SecurityEvent.__table__]
            )
        )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    first_device, second_device, event_id = uuid4(), uuid4(), uuid4()
    async with factory() as session:
        session.add_all(
            [
                Device(id=first_device, device_identifier="security-one"),
                Device(id=second_device, device_identifier="security-two"),
            ]
        )
        await session.commit()

    def event(device_id):
        return SecurityEvent(
            id=uuid4(),
            event_identifier=event_id,
            device_id=device_id,
            event_type="USB_DEVICE_CONNECTED",
            channel="USB",
            severity="INFO",
            occurred_at=NOW,
            received_at=NOW,
            user_login=None,
            policy_id=uuid4(),
            policy_version=1,
            safe_metadata={"removable": True},
            expires_at=NOW + timedelta(days=30),
        )

    async with factory() as session:
        session.add_all([event(first_device), event(second_device)])
        await session.commit()
        assert len((await session.scalars(select(SecurityEvent))).all()) == 2
        session.add(event(first_device))
        with pytest.raises(IntegrityError):
            await session.commit()
    await engine.dispose()
