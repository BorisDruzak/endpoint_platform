"""Observable lifecycle behavior for Device Context persistence."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from endpoint_contracts import AgentResultV1
from endpoint_server.context import ingestion
from endpoint_server.context.models import ContextCollection, ContextCurrent, ContextSnapshot
from endpoint_server.context.repository import request_collection
from endpoint_server.context.ingestion import ingest_context_result
from endpoint_server.db.models import (
    Command,
    CommandDelivery,
    CommandResult,
    Device,
    DeviceInstance,
    DeviceSession,
)


NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = (
        Device.__table__,
        DeviceInstance.__table__,
        DeviceSession.__table__,
        Command.__table__,
        CommandDelivery.__table__,
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


async def _result(
    session: AsyncSession,
    *,
    status: str = "succeeded",
    device_id=None,
    collected_at: datetime = NOW,
) -> tuple[CommandResult, AgentResultV1]:
    device = None
    if device_id is None:
        device = Device(id=uuid4(), device_identifier=f"device-{uuid4().hex}", display_name="ALT")
        session.add(device)
        device_id = device.id
        await session.flush()
    command = Command(
        id=uuid4(),
        command_identifier=f"command-{uuid4().hex}",
        device_id=device_id,
        command_kind="context.baseline.collect",
        status="completed",
    )
    record = CommandResult(
        id=uuid4(),
        command_id=command.id,
        result_identifier=f"result-{uuid4().hex}",
        status=status,
        completed_at=collected_at,
    )
    session.add_all((command, record))
    await session.flush()
    return record, AgentResultV1(
        schema_version="agent_result_v1",
        command_id=command.id,
        device_id=device_id,
        status=status,
        completed_at=collected_at,
        result_items=[
            {
                "schema_version": "device_context_v1",
                "profile": "baseline_v1",
                "collected_at": collected_at.isoformat(),
                "sections": {
                    "system": {"platform": "linux", "distribution": "ALT", "architecture": "x86_64"},
                    "hardware": {"manufacturer": "Acme", "model": "A1", "cpu_model": "CPU", "memory_bytes": 1024},
                    "storage": [{"stable_key": "disk:one", "model": "Disk", "size_bytes": 2048}],
                    "interfaces": [],
                    "software": [],
                },
                "warnings": [],
            }
        ],
    )


@pytest.mark.asyncio
async def test_request_collection_replays_same_device_profile_and_idempotency_key(session: AsyncSession) -> None:
    """Removing collection identity uniqueness would schedule the same collection twice."""
    device = Device(id=uuid4(), device_identifier="device-request", display_name="ALT")
    session.add(device)
    await session.flush()

    first = await request_collection(session, device.id, "baseline_v1", "admin-1", "request-0001")
    replay = await request_collection(session, device.id, "baseline_v1", "admin-1", "request-0001")

    assert replay.id == first.id
    assert (await session.scalars(select(ContextCollection))).all() == [first]


@pytest.mark.asyncio
async def test_successful_result_creates_snapshot_and_current_from_separate_raw_and_projection(session: AsyncSession) -> None:
    """Dropping raw/result separation or the current pointer would lose the audit boundary."""
    result_record, result = await _result(session)

    collection = await ingest_context_result(session, result_record.id, result)

    snapshot = await session.scalar(select(ContextSnapshot).where(ContextSnapshot.collection_id == collection.id))
    current = await session.scalar(select(ContextCurrent).where(ContextCurrent.device_id == collection.device_id))
    assert collection.status == "completed"
    assert snapshot is not None
    assert snapshot.raw_payload["schema_version"] == "agent_result_v1"
    assert snapshot.normalized_projection["profile"] == "baseline_v1"
    assert current is not None
    assert current.snapshot_id == snapshot.id


@pytest.mark.asyncio
async def test_delayed_older_result_does_not_replace_newer_current_snapshot(session: AsyncSession) -> None:
    """Replacing this comparison would regress current context after delayed delivery."""
    device = Device(id=uuid4(), device_identifier="device-ordering", display_name="ALT")
    session.add(device)
    await session.flush()
    older_at = datetime(2026, 7, 29, 11, 0, tzinfo=UTC)
    newer_at = datetime(2026, 7, 29, 13, 0, tzinfo=UTC)
    newer_record, newer_result = await _result(session, device_id=device.id, collected_at=newer_at)
    older_record, older_result = await _result(session, device_id=device.id, collected_at=older_at)

    newer = await ingest_context_result(session, newer_record.id, newer_result)
    older = await ingest_context_result(session, older_record.id, older_result)

    current = await session.scalar(
        select(ContextCurrent).where(
            ContextCurrent.device_id == device.id,
            ContextCurrent.profile == "baseline_v1",
        )
    )
    assert current is not None
    assert current.snapshot_id == (
        await session.scalar(
            select(ContextSnapshot.id).where(ContextSnapshot.collection_id == newer.id)
        )
    )
    assert (await session.scalar(
        select(ContextSnapshot.id).where(ContextSnapshot.collection_id == older.id)
    )) != current.snapshot_id


@pytest.mark.asyncio
async def test_equal_collection_time_keeps_existing_current_snapshot(session: AsyncSession) -> None:
    """Equal observations are intentionally first-current-wins to avoid pointer churn."""
    device = Device(id=uuid4(), device_identifier="device-equal-ordering", display_name="ALT")
    session.add(device)
    await session.flush()
    first_record, first_result = await _result(session, device_id=device.id)
    second_record, second_result = await _result(session, device_id=device.id)

    first = await ingest_context_result(session, first_record.id, first_result)
    await ingest_context_result(session, second_record.id, second_result)

    current = await session.scalar(
        select(ContextCurrent).where(ContextCurrent.device_id == device.id)
    )
    assert current is not None
    assert current.snapshot_id == await session.scalar(
        select(ContextSnapshot.id).where(ContextSnapshot.collection_id == first.id)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("pointer_device", "pointer_profile"),
    (("second", "baseline_v1"), ("first", "health_v1")),
)
async def test_current_pointer_cannot_reference_different_device_or_profile_snapshot(
    session: AsyncSession, pointer_device: str, pointer_profile: str
) -> None:
    """A single-column snapshot FK would permit cross-device/profile current pointers."""
    first_device = Device(id=uuid4(), device_identifier="device-fk-first", display_name="ALT")
    second_device = Device(id=uuid4(), device_identifier="device-fk-second", display_name="ALT")
    session.add_all((first_device, second_device))
    await session.flush()
    result_record, result = await _result(session, device_id=first_device.id)
    await ingest_context_result(session, result_record.id, result)
    snapshot = await session.scalar(select(ContextSnapshot).where(ContextSnapshot.collection_id.is_not(None)))
    assert snapshot is not None

    current_device_id = first_device.id if pointer_device == "first" else second_device.id
    session.add(ContextCurrent(
        id=uuid4(), device_id=current_device_id, profile=pointer_profile,
        snapshot_id=snapshot.id, updated_at=NOW,
    ))
    with pytest.raises(IntegrityError):
        await session.flush()


@pytest.mark.asyncio
async def test_each_result_serializes_current_pointer_by_device_and_profile(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An absent pointer row still needs one shared PostgreSQL lock key."""
    lock_keys: list[str] = []

    async def capture_lock(_: AsyncSession, key: str) -> None:
        lock_keys.append(key)

    monkeypatch.setattr(ingestion, "_advisory_lock", capture_lock)
    device = Device(id=uuid4(), device_identifier="device-current-lock", display_name="ALT")
    session.add(device)
    await session.flush()
    first_record, first_result = await _result(session, device_id=device.id)
    second_record, second_result = await _result(session, device_id=device.id)

    await ingest_context_result(session, first_record.id, first_result)
    await ingest_context_result(session, second_record.id, second_result)

    assert lock_keys.count(f"context.current:{device.id}:baseline_v1") == 2
