"""Continuous Activity has its own Context path and never creates a command."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from endpoint_contracts.activity import ActivityObservationV1
from endpoint_server.activity.ingestion import ingest_activity_observation
from endpoint_server.context.models import ContextCollection, ContextCurrent, ContextSnapshot
from endpoint_server.context.projection import activity_current_projection, snapshot_projection
from endpoint_server.context.retention import retain_context_snapshots
from endpoint_server.db.models import Command, CommandResult, Device


NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = (Device.__table__, Command.__table__, CommandResult.__table__,
              ContextCollection.__table__, ContextSnapshot.__table__, ContextCurrent.__table__)
    async with engine.begin() as connection:
        await connection.execute(text("PRAGMA foreign_keys=ON"))
        await connection.run_sync(lambda sync: Device.metadata.create_all(sync, tables=tables))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as value:
        value.add(Device(id=uuid4(), device_identifier="activity-test"))
        await value.flush()
        yield value
    await engine.dispose()


def _observation(*, seconds: int = 10, state: str = "ACTIVE", when: datetime = NOW,
                 process: str = "chrome.exe") -> ActivityObservationV1:
    return ActivityObservationV1.model_validate({
        "schema_version": "activity_observation_v1", "observation_id": uuid4(),
        "observed_at": when, "user_login": "ivanova.aa", "session_state": state,
        "idle_seconds": seconds if state in {"ACTIVE", "IDLE"} else None,
        "foreground": ({"process_name": process, "application_category": "browser"}
                       if state in {"ACTIVE", "IDLE"} else None),
        "browser": None,
    })


async def _device_id(session: AsyncSession):
    return await session.scalar(select(Device.id))


async def _snapshots(session: AsyncSession):
    return (await session.scalars(select(ContextSnapshot).order_by(ContextSnapshot.collected_at))).all()


@pytest.mark.asyncio
async def test_threshold_and_semantic_dedup_advance_observation(session: AsyncSession) -> None:
    device_id = await _device_id(session)
    await ingest_activity_observation(session, device_id, _observation(), idle_threshold_seconds=600,
                                      received_at=NOW)
    await ingest_activity_observation(session, device_id, _observation(seconds=590, when=NOW + timedelta(minutes=1)),
                                      idle_threshold_seconds=600, received_at=NOW + timedelta(minutes=1))
    snapshots = await _snapshots(session)
    assert len(snapshots) == 1
    assert snapshots[0].normalized_projection["sections"]["session_state"] == "ACTIVE"
    current = await session.scalar(select(ContextCurrent).where(ContextCurrent.device_id == device_id))
    assert current.last_observed_at.replace(tzinfo=UTC) == NOW + timedelta(minutes=1)
    assert activity_current_projection(current)["sections"]["idle_seconds"] == 590
    await ingest_activity_observation(session, device_id, _observation(seconds=600, when=NOW + timedelta(minutes=2)),
                                      idle_threshold_seconds=600, received_at=NOW + timedelta(minutes=2))
    snapshots = await _snapshots(session)
    assert len(snapshots) == 2
    assert snapshots[-1].normalized_projection["sections"]["session_state"] == "IDLE"
    assert snapshot_projection(snapshots[-1])["sections"]["idle_seconds"] == 600
    assert await session.scalar(select(func.count()).select_from(Command)) == 0
    collections = (await session.scalars(select(ContextCollection))).all()
    assert all(row.command_id is None and row.operation_id is None for row in collections)


@pytest.mark.asyncio
async def test_replay_and_old_sample_do_not_replace_current(session: AsyncSession) -> None:
    device_id = await _device_id(session)
    first = _observation()
    await ingest_activity_observation(session, device_id, first, idle_threshold_seconds=600, received_at=NOW)
    await ingest_activity_observation(session, device_id, first, idle_threshold_seconds=600,
                                      received_at=NOW + timedelta(seconds=1))
    await ingest_activity_observation(session, device_id,
        _observation(state="LOCKED", when=NOW - timedelta(minutes=1)),
        idle_threshold_seconds=600, received_at=NOW + timedelta(seconds=2))
    assert len(await _snapshots(session)) == 1
    current = await session.scalar(select(ContextCurrent).where(ContextCurrent.device_id == device_id))
    assert current.last_observed_at.replace(tzinfo=UTC) == NOW + timedelta(seconds=1)


@pytest.mark.asyncio
async def test_activity_hot_history_expires_but_current_survives(session: AsyncSession) -> None:
    device_id = await _device_id(session)
    for minute, state in enumerate(("ACTIVE", "LOCKED", "DISCONNECTED")):
        when = NOW + timedelta(minutes=minute)
        await ingest_activity_observation(session, device_id, _observation(state=state, when=when),
                                          idle_threshold_seconds=600, received_at=when)
    assert await retain_context_snapshots(session, now=NOW + timedelta(hours=24, minutes=1)) == 1
    remaining = await _snapshots(session)
    assert [row.normalized_projection["sections"]["session_state"] for row in remaining] == ["LOCKED", "DISCONNECTED"]
    assert await retain_context_snapshots(session, now=NOW + timedelta(hours=25)) == 1
    assert (await _snapshots(session))[0].normalized_projection["sections"]["session_state"] == "DISCONNECTED"
