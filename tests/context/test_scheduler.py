"""Bounded periodic Device Context scheduling behavior."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import event, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from endpoint_server.context.models import ContextCollection
from endpoint_server.context.scheduler import schedule_due_collections, schedule_due_collections_with_backlog
from endpoint_server.db.models import Command, CommandResult, Device
from tests.server.test_update_postgresql import update_service_database_url, update_service_provider


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
                    Device.metadata.tables["installation_states"], Device.__table__,
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

    assert await schedule_due_collections(session, now=NOW) == 3
    assert await schedule_due_collections(session, now=NOW) == 0

    scheduled = (await session.scalars(select(ContextCollection))).all()
    scheduled_by_profile = {item.profile: item for item in scheduled if item.requested_by == "scheduler"}
    assert set(scheduled_by_profile) == {"baseline_v1", "inventory_v1", "session_v1"}
    assert scheduled_by_profile["baseline_v1"].expires_at.replace(tzinfo=UTC) == NOW + timedelta(hours=24)
    assert scheduled_by_profile["inventory_v1"].expires_at.replace(tzinfo=UTC) == NOW + timedelta(hours=24)
    assert scheduled_by_profile["session_v1"].expires_at.replace(tzinfo=UTC) == NOW + timedelta(minutes=5)


@pytest.mark.asyncio
async def test_scheduler_never_enqueues_manual_only_diagnostics(session: AsyncSession) -> None:
    """Adding diagnostic_v1 to the periodic allowlist would violate the manual boundary."""
    device = Device(id=uuid4(), device_identifier="scheduler-manual", display_name="ALT")
    session.add(device)
    await session.flush()

    assert await schedule_due_collections(session, now=NOW) == 5
    profiles = set(await session.scalars(select(ContextCollection.profile)))
    assert profiles == {
        "baseline_v1",
        "health_v1",
        "network_v1",
        "inventory_v1",
        "session_v1",
    }


@pytest.mark.asyncio
async def test_scheduler_inserts_new_collections_with_deadlines(session: AsyncSession) -> None:
    device = Device(device_identifier="scheduler-insert-deadlines", created_at=NOW)
    session.add(device)
    await session.flush()
    statements = []

    def observe(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    engine = session.get_bind()
    event.listen(engine, "before_cursor_execute", observe)
    try:
        assert await schedule_due_collections(session, now=NOW) == 5
        await session.commit()
    finally:
        event.remove(engine, "before_cursor_execute", observe)

    writes = [sql for sql in statements if sql.startswith(("INSERT ", "UPDATE "))]
    assert writes
    assert all(sql.startswith("INSERT INTO context_collections") and "expires_at" in sql for sql in writes)
    assert not await schedule_due_collections(session, now=NOW)


@pytest.mark.asyncio
async def test_scheduler_measures_lateness_for_work_it_actually_enqueues(session):
    device = Device(device_identifier="scheduler-age", created_at=NOW - timedelta(minutes=2))
    retired = Device(device_identifier="retired-age", created_at=NOW - timedelta(days=3), retired_at=NOW)
    session.add_all([device, retired])
    await session.flush()
    await _completed_collection(
        session, device_id=device.id, profile="network_v1", completed_at=NOW - timedelta(minutes=2),
    )
    session.add(ContextCollection(
        device_id=device.id, profile="baseline_v1", requested_by="operator",
        idempotency_key="active-baseline", status="requested", requested_at=NOW - timedelta(days=2),
    ))
    await session.flush()
    await _completed_collection(
        session, device_id=device.id, profile="health_v1", completed_at=NOW - timedelta(minutes=9),
    )
    observed = await schedule_due_collections_with_backlog(session, now=NOW)
    assert (observed.created, observed.oldest_due_age_seconds) == (3, 240)
    repeated = await schedule_due_collections_with_backlog(session, now=NOW)
    assert (repeated.created, repeated.oldest_due_age_seconds) == (0, 0)


@pytest.mark.asyncio
async def test_scheduler_pages_by_device_and_retries_a_rolled_back_page(session):
    first_id, retired_id, second_id, third_id = (UUID(int=value) for value in range(1, 5))
    session.add_all([
        Device(id=device_id, device_identifier=str(device_id), created_at=NOW,
               retired_at=NOW if device_id == retired_id else None)
        for device_id in (third_id, retired_id, second_id, first_id)
    ])
    await session.commit()

    first = await schedule_due_collections_with_backlog(session, now=NOW, page_size=1)
    assert (first.created, first.next_device_id) == (5, first_id)
    await session.commit()

    abandoned = await schedule_due_collections_with_backlog(
        session, now=NOW, page_size=1, after_device_id=first.next_device_id,
    )
    assert (abandoned.created, abandoned.next_device_id) == (5, second_id)
    await session.rollback()

    resumed = await schedule_due_collections_with_backlog(
        session, now=NOW, page_size=2, after_device_id=first.next_device_id,
    )
    assert (resumed.created, resumed.next_device_id) == (10, None)
    await session.commit()
    device_ids = (await session.scalars(select(ContextCollection.device_id))).all()
    assert sorted(device_ids) == sorted([first_id, second_id, third_id] * 5)


@pytest.mark.asyncio
async def test_scheduler_reads_device_and_profile_history_once(session):
    device = Device(device_identifier="scheduler-single-history-read", created_at=NOW)
    session.add(device)
    await session.flush()
    await _completed_collection(session, device_id=device.id, profile="baseline_v1", completed_at=NOW)
    session.add(ContextCollection(
        device_id=device.id, profile="baseline_v1", requested_by="operator",
        idempotency_key="older-active", status="collecting", requested_at=NOW - timedelta(days=2),
    ))
    await _completed_collection(
        session, device_id=device.id, profile="health_v1", completed_at=NOW - timedelta(minutes=6),
    )
    await _completed_collection(session, device_id=device.id, profile="session_v1", completed_at=NOW)
    history_reads = []
    device_reads = []

    def observe(_connection, _cursor, statement, _parameters, _context, _many):
        if "ORDER BY context_collections.requested_at" in statement:
            history_reads.append(statement)
        if "FROM devices" in statement and "WHERE devices.id =" in statement:
            device_reads.append(statement)

    engine = session.get_bind()
    event.listen(engine, "before_cursor_execute", observe)
    try:
        assert await schedule_due_collections(session, now=NOW) == 3
    finally:
        event.remove(engine, "before_cursor_execute", observe)

    assert len(history_reads) == 1
    assert len(device_reads) == 1
    profiles = await session.scalars(select(ContextCollection.profile).where(ContextCollection.requested_by == "scheduler"))
    assert set(profiles) == {"health_v1", "network_v1", "inventory_v1"}


@pytest.mark.asyncio
async def test_scheduler_locks_active_row_without_locking_history(update_service_provider):
    provider = update_service_provider
    async with provider() as seed:
        device = Device(device_identifier="scheduler-locked-active", created_at=NOW)
        seed.add(device)
        await seed.flush()
        active_id, history_id = uuid4(), uuid4()
        seed.add_all([
            ContextCollection(
                id=active_id, device_id=device.id, profile="baseline_v1",
                requested_by="operator", idempotency_key="active",
                requested_at=NOW - timedelta(days=3), status="collecting",
            ),
            ContextCollection(
                id=history_id, device_id=device.id, profile="baseline_v1",
                requested_by="operator", idempotency_key="history",
                requested_at=NOW - timedelta(days=2), status="completed",
            ),
        ])
        await seed.commit()

    def lock(collection_id):
        return select(ContextCollection).where(ContextCollection.id == collection_id).with_for_update(nowait=True)

    async with provider() as scheduler:
        assert await schedule_due_collections(scheduler, now=NOW) == 4
        async with provider() as observer:
            with pytest.raises(DBAPIError) as rejected:
                await observer.scalar(
                    select(Device).where(Device.id == device.id).with_for_update(nowait=True)
                )
            assert rejected.value.orig.sqlstate == "55P03"
        async with provider() as observer:
            assert (await observer.scalar(lock(history_id))).id == history_id
            with pytest.raises(DBAPIError) as rejected:
                await observer.scalar(lock(active_id))
            assert rejected.value.orig.sqlstate == "55P03"


@pytest.mark.asyncio
async def test_scheduler_locks_profiles_in_order_in_one_statement(update_service_provider):
    provider = update_service_provider
    device_id = UUID(int=(1 << 128) - 1)
    async with provider() as seed:
        seed.add(Device(
            id=device_id,
            device_identifier="scheduler-advisory-order",
            scheduled_context_profiles=["session_v1", "health_v1", "baseline_v1"],
        ))
        await seed.commit()

    lock = text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))")
    try_lock = text("SELECT pg_try_advisory_xact_lock(hashtextextended(:key, 0))")
    baseline, health, session_key = (
        f"context.schedule:{device_id}:{profile}" for profile in ("baseline_v1", "health_v1", "session_v1")
    )
    waiter_pid = asyncio.get_running_loop().create_future()
    statements = []

    async def schedule():
        async with provider() as scheduler:
            pid = await scheduler.scalar(text("SELECT pg_backend_pid()"))
            engine = scheduler.get_bind()

            def record(_connection, _cursor, statement, parameters, _context, _many):
                if statement.startswith("SELECT pg_advisory_xact_lock") and "context.schedule:" in str(parameters):
                    statements.append(statement)

            event.listen(engine, "before_cursor_execute", record)
            try:
                waiter_pid.set_result(pid)
                batch = await schedule_due_collections_with_backlog(
                    scheduler, now=NOW, after_device_id=UUID(int=device_id.int - 1), page_size=1,
                )
                return batch.created
            finally:
                event.remove(engine, "before_cursor_execute", record)

    async with provider() as blocker:
        await blocker.execute(lock, {"key": health})
        pending = asyncio.create_task(schedule())
        try:
            pid = await asyncio.wait_for(waiter_pid, 5)
            async with provider() as observer, asyncio.timeout(5):
                waiting = text("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid=:pid "
                               "AND locktype='advisory' AND NOT granted)")
                while not await observer.scalar(waiting, {"pid": pid}):
                    await asyncio.sleep(0.01)
                assert not await observer.scalar(try_lock, {"key": baseline})
                assert await observer.scalar(try_lock, {"key": session_key})
            await blocker.commit()
            assert await asyncio.wait_for(pending, 5) == 3
        finally:
            if not pending.done():
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
    assert len(statements) == 1
