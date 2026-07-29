"""Retention rules for immutable Device Context snapshots."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from endpoint_server.context.models import ContextCollection, ContextCurrent, ContextSnapshot
from endpoint_server.context.retention import retain_context_snapshots
from endpoint_server.db.models import Command, CommandResult, Device


NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = (
        Device.__table__,
        Command.__table__,
        CommandResult.__table__,
        ContextCollection.__table__,
        ContextSnapshot.__table__,
        ContextCurrent.__table__,
    )
    async with engine.begin() as connection:
        await connection.execute(text("PRAGMA foreign_keys=ON"))
        await connection.run_sync(lambda sync: Device.metadata.create_all(sync, tables=tables))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as value:
        yield value
    await engine.dispose()


async def _snapshot(
    session: AsyncSession,
    *,
    device_id,
    collected_at: datetime,
    pinned_at: datetime | None = None,
    snapshot_id: UUID | None = None,
) -> ContextSnapshot:
    collection = ContextCollection(
        id=snapshot_id or uuid4(),
        device_id=device_id,
        profile="baseline_v1",
        requested_by="seed",
        idempotency_key=f"seed-{uuid4().hex}",
        status="completed",
        requested_at=collected_at,
        completed_at=collected_at,
    )
    snapshot = ContextSnapshot(
        id=uuid4(),
        collection_id=collection.id,
        device_id=device_id,
        profile="baseline_v1",
        collected_at=collected_at,
        pinned_at=pinned_at,
        raw_payload={},
        normalized_projection={},
    )
    session.add_all((collection, snapshot))
    await session.flush()
    return snapshot


@pytest.mark.asyncio
async def test_retention_keeps_current_previous_and_pinned_snapshots(session: AsyncSession) -> None:
    """Removing the pin/current/previous selection would delete user-relevant history."""
    device = Device(id=uuid4(), device_identifier="retention-alt", display_name="ALT")
    session.add(device)
    await session.flush()
    oldest_pinned = await _snapshot(
        session, device_id=device.id, collected_at=NOW - timedelta(days=3), pinned_at=NOW
    )
    old = await _snapshot(session, device_id=device.id, collected_at=NOW - timedelta(days=2))
    previous = await _snapshot(session, device_id=device.id, collected_at=NOW - timedelta(days=1))
    current = await _snapshot(session, device_id=device.id, collected_at=NOW)
    session.add(
        ContextCurrent(
            id=uuid4(), device_id=device.id, profile="baseline_v1", snapshot_id=current.id, updated_at=NOW
        )
    )
    await session.flush()

    assert await retain_context_snapshots(session) == 1
    remaining = set(await session.scalars(select(ContextSnapshot.id)))
    assert remaining == {oldest_pinned.id, previous.id, current.id}
    assert old.id not in remaining


@pytest.mark.asyncio
async def test_retention_handles_equal_collection_times_with_a_stable_id_order(
    session: AsyncSession,
) -> None:
    """Equal collection times must not make the previous-snapshot comparison crash."""
    device = Device(id=uuid4(), device_identifier="retention-equal", display_name="ALT")
    session.add(device)
    await session.flush()
    snapshots = [
        await _snapshot(session, device_id=device.id, collected_at=NOW)
        for _ in range(3)
    ]
    old, previous, current = sorted(snapshots, key=lambda snapshot: str(snapshot.id))
    session.add(
        ContextCurrent(
            id=uuid4(), device_id=device.id, profile="baseline_v1", snapshot_id=current.id, updated_at=NOW
        )
    )
    await session.flush()

    assert await retain_context_snapshots(session) == 1
    assert set(await session.scalars(select(ContextSnapshot.id))) == {previous.id, current.id}
    assert old.id not in set(await session.scalars(select(ContextSnapshot.id)))
