"""Bounded periodic Device Context scheduling behavior."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from endpoint_server.context.models import ContextCollection
from endpoint_server.context.scheduler import schedule_due_collections
from endpoint_server.db.models import Command, CommandResult, Device


NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.execute(text("PRAGMA foreign_keys=ON"))
        await connection.run_sync(
            lambda sync: Device.metadata.create_all(
                sync,
                tables=(
                    Device.__table__,
                    Command.__table__,
                    CommandResult.__table__,
                    ContextCollection.__table__,
                ),
            )
        )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as value:
        yield value
    await engine.dispose()


async def _completed_collection(
    session: AsyncSession, *, device_id, profile: str, completed_at: datetime
) -> None:
    session.add(
        ContextCollection(
            id=uuid4(),
            device_id=device_id,
            profile=profile,
            requested_by="seed",
            idempotency_key=f"seed-{profile}",
            status="completed",
            requested_at=completed_at,
            completed_at=completed_at,
        )
    )
    await session.flush()


@pytest.mark.asyncio
async def test_scheduler_creates_one_active_baseline(session: AsyncSession) -> None:
    """A second concurrent-equivalent tick must not enqueue the baseline twice."""
    device = Device(id=uuid4(), device_identifier="scheduler-alt", display_name="ALT")
    session.add(device)
    await session.flush()
    await _completed_collection(
        session, device_id=device.id, profile="health_v1", completed_at=NOW
    )
    await _completed_collection(
        session, device_id=device.id, profile="network_v1", completed_at=NOW
    )

    assert await schedule_due_collections(session, now=NOW) == 1
    assert await schedule_due_collections(session, now=NOW) == 0

    scheduled = (await session.scalars(
        select(ContextCollection).where(ContextCollection.profile == "baseline_v1")
    )).all()
    assert len(scheduled) == 1
    assert scheduled[0].status == "requested"
    assert scheduled[0].requested_by == "scheduler"
    assert scheduled[0].expires_at is not None
    assert scheduled[0].expires_at.replace(tzinfo=UTC) == NOW + timedelta(hours=24)


@pytest.mark.asyncio
async def test_scheduler_never_enqueues_manual_only_diagnostics(session: AsyncSession) -> None:
    """Adding diagnostic_v1 to the periodic allowlist would violate the manual boundary."""
    device = Device(id=uuid4(), device_identifier="scheduler-manual", display_name="ALT")
    session.add(device)
    await session.flush()

    assert await schedule_due_collections(session, now=NOW) == 3
    profiles = set(await session.scalars(select(ContextCollection.profile)))
    assert profiles == {"baseline_v1", "health_v1", "network_v1"}
