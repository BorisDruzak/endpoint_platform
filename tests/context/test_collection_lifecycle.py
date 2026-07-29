"""Observable lifecycle behavior for Device Context persistence."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from endpoint_contracts import AgentResultV1
from endpoint_server.context.models import ContextCollection, ContextCurrent, ContextSnapshot
from endpoint_server.context.repository import request_collection
from endpoint_server.context.ingestion import ingest_context_result
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
        await connection.run_sync(lambda sync: Device.metadata.create_all(sync, tables=tables))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as value:
        yield value
    await engine.dispose()


async def _result(
    session: AsyncSession, *, status: str = "succeeded", device_id=None
) -> tuple[CommandResult, AgentResultV1]:
    device = None
    if device_id is None:
        device = Device(id=uuid4(), device_identifier=f"device-{uuid4().hex}", display_name="ALT")
        session.add(device)
        device_id = device.id
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
        completed_at=NOW,
    )
    session.add_all((command, record))
    await session.flush()
    return record, AgentResultV1(
        schema_version="agent_result_v1",
        command_id=command.id,
        device_id=device_id,
        status=status,
        completed_at=NOW,
        result_items=[
            {
                "schema_version": "device_context_v1",
                "profile": "baseline_v1",
                "collected_at": NOW.isoformat(),
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
