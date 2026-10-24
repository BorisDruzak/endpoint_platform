from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from endpoint_contracts.power_events import (
    PowerEventV1,
    PowerEventBatchV1,
    PowerSourceStatusV1,
)
from endpoint_server.context.models import DeviceEvent
from endpoint_server.db.base import Base
from endpoint_server.db.models import Device
from endpoint_server.power.models import PowerSourceState
from endpoint_server.power.ingestion import commit_and_ack_power_events
from endpoint_server.power.projection import (
    project_power,
    power_summary,
    enrich_power_summaries,
)
from endpoint_server.power.retention import retain_power_events
from endpoint_server.power.projection import power_timeline_markers

NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)


def event(**changes):
    return PowerEventV1.model_validate(
        dict(
            schema_version="power_event_v1",
            event_identifier=uuid4(),
            event_kind="OS_SLEEP_STARTED",
            occurred_at=NOW - timedelta(minutes=10),
            observed_at=NOW,
            boot_id="boot-1",
            source="systemd-journal",
            native_record_id="record-1",
            evidence="transition",
            **changes,
        )
    )


def batch(events=(), **status):
    return PowerEventBatchV1(
        schema_version="power_event_batch_v1",
        batch_id=uuid4(),
        events=list(events),
        source_status=PowerSourceStatusV1.model_validate(
            dict(
                schema_version="power_source_status_v1",
                source="systemd-journal",
                availability="READY",
                reported_at=NOW,
                coverage_started_at=NOW - timedelta(days=3),
                **status,
            )
        ),
    )


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(
            lambda sync: Base.metadata.create_all(
                sync,
                tables=[
                    Device.__table__,
                    DeviceEvent.__table__,
                    PowerSourceState.__table__,
                ],
            )
        )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    device_id = uuid4()
    async with factory() as session:
        session.add(Device(id=device_id, device_identifier="power-test"))
        await session.commit()
    yield factory, device_id
    await engine.dispose()


async def send_batch(db, value, factory=None):
    sessions, device_id = db
    sent = []

    async def send(envelope):
        # An independent transaction can see each accepted event before ACK.
        async with sessions() as session:
            rows = list((await session.scalars(select(DeviceEvent))).all())
            accepted = [
                r for r in envelope.payload.results if r.disposition == "accepted"
            ]
            assert len(rows) >= len(accepted)
        sent.append(envelope)

    await commit_and_ack_power_events(
        factory or sessions, device_id, value, sequence=7, send=send, received_at=NOW
    )
    return sent[0].payload


async def test_native_replay_and_conflicting_id_are_exact(db):
    original = event()
    assert (await send_batch(db, batch([original]))).results[
        0
    ].disposition == "accepted"
    replay = original.model_copy(update={"observed_at": NOW + timedelta(seconds=1)})
    assert (await send_batch(db, batch([replay]))).results[0].disposition == "accepted"
    native_replay = replay.model_copy(update={"event_identifier": uuid4()})
    assert (await send_batch(db, batch([native_replay]))).results[
        0
    ].disposition == "rejected"
    conflict = original.model_copy(update={"event_kind": "OS_SHUTDOWN_STARTED"})
    assert (await send_batch(db, batch([conflict]))).results[
        0
    ].disposition == "rejected"
    async with db[0]() as session:
        assert len(list((await session.scalars(select(DeviceEvent))).all())) == 1


async def test_mixed_bounds_valid_siblings_no_policy_and_empty_status(db):
    good = event()
    future = event().model_copy(
        update={"native_record_id": "future", "occurred_at": NOW + timedelta(minutes=6)}
    )
    old = event().model_copy(
        update={"native_record_id": "old", "occurred_at": NOW - timedelta(days=31)}
    )
    ack = await send_batch(db, batch([future, good, old]))
    assert [r.event_identifier for r in ack.results] == [
        future.event_identifier,
        good.event_identifier,
        old.event_identifier,
    ]
    assert [r.disposition for r in ack.results] == ["rejected", "accepted", "rejected"]
    assert (await send_batch(db, batch([], loss_count=4, reset_count=2))).results == []
    async with db[0]() as session:
        state = await session.scalar(select(PowerSourceState))
        assert (state.loss_count, state.reset_count, state.availability) == (
            4,
            2,
            "READY",
        )


async def test_commit_failure_rolls_back_all_siblings_and_source_without_ack(db):
    class FailingSession(AsyncSession):
        async def commit(self):
            raise RuntimeError("commit unavailable")

    factory = async_sessionmaker(db[0].kw["bind"], class_=FailingSession)
    with pytest.raises(RuntimeError, match="commit unavailable"):
        await send_batch(db, batch([event()]), factory)
    async with db[0]() as session:
        assert await session.scalar(select(DeviceEvent)) is None
        assert await session.scalar(select(PowerSourceState)) is None


async def test_poison_savepoint_rolls_back_staged_row_only(db, monkeypatch):
    from endpoint_server.power import ingestion

    original = ingestion._ingest_event

    async def stage_then_reject(session, device_id, fact, when):
        await original(session, device_id, fact, when)
        if fact.native_record_id == "poison":
            raise ingestion.PowerEventRejected("event_conflict")

    monkeypatch.setattr(ingestion, "_ingest_event", stage_then_reject)
    poison = event().model_copy(update={"native_record_id": "poison"})
    good = event()
    ack = await send_batch(db, batch([poison, good]))
    assert [result.disposition for result in ack.results] == ["rejected", "accepted"]
    async with db[0]() as session:
        rows = list((await session.scalars(select(DeviceEvent))).all())
        assert [row.event_identifier for row in rows] == [str(good.event_identifier)]


async def test_reordered_delivery_keeps_latest_resume_in_summary(db):
    sleep = event()
    resume = sleep.model_copy(
        update={
            "event_identifier": uuid4(),
            "native_record_id": "resume",
            "event_kind": "OS_RESUMED",
            "occurred_at": NOW - timedelta(minutes=5),
        }
    )
    await send_batch(db, batch([resume]))
    await send_batch(db, batch([sleep]))
    async with db[0]() as session:
        summary = await power_summary(
            session, db[1], online=False, last_seen_at=None, now=NOW
        )
        assert (
            summary.status == "unknown"
            and summary.latest_event.event_kind == "OS_RESUMED"
        )


async def test_current_coverage_does_not_regress(db):
    await send_batch(db, batch([], loss_count=5))
    stale = batch().model_copy(
        update={
            "source_status": batch().source_status.model_copy(
                update={
                    "reported_at": NOW - timedelta(hours=1),
                    "availability": "UNAVAILABLE",
                    "loss_count": 0,
                }
            )
        }
    )
    await send_batch(db, stale)
    async with db[0]() as session:
        state = await session.scalar(select(PowerSourceState))
        assert state.availability == "READY" and state.loss_count == 5


async def test_same_identifier_cannot_move_to_another_native_record(db):
    original = event()
    await send_batch(db, batch([original]))
    conflict = original.model_copy(update={"native_record_id": "different"})
    assert (await send_batch(db, batch([conflict]))).results[
        0
    ].disposition == "rejected"


@pytest.mark.parametrize(
    "online,seen,availability,evidence,expected",
    [
        (True, None, "READY", "transition", "online"),
        (False, None, "READY", "transition", "sleep"),
        (False, None, "READY", "request", "unknown"),
        (False, NOW, "READY", "transition", "unknown"),
        (False, None, "UNSUPPORTED", "transition", "unknown"),
        (False, None, None, "transition", "unknown"),
    ],
)
def test_truthful_projection(online, seen, availability, evidence, expected):
    fact = event().model_copy(update={"evidence": evidence})
    source = (
        batch().source_status.model_copy(update={"availability": availability})
        if availability
        else None
    )
    assert (
        project_power(
            online=online,
            last_seen_at=seen,
            source_status=source,
            events=[fact],
            now=NOW,
        ).status
        == expected
    )


def test_latest_event_time_wins_not_arrival_and_reconnect_is_no_boot():
    sleep = event()
    resume = sleep.model_copy(
        update={
            "event_identifier": uuid4(),
            "event_kind": "OS_RESUMED",
            "occurred_at": NOW - timedelta(minutes=5),
        }
    )
    for facts in ([resume, sleep], [sleep, resume], []):
        value = project_power(
            online=False,
            last_seen_at=None,
            source_status=batch().source_status,
            events=facts,
            now=NOW,
        )
        assert value.status == "unknown"
    assert (
        project_power(
            online=False,
            last_seen_at=None,
            source_status=batch().source_status,
            events=[],
            now=NOW,
        ).latest_event
        is None
    )


async def test_retention_only_power_and_summary_coverage(db):
    await send_batch(db, batch([event()]))
    async with db[0]() as session:
        session.add(
            DeviceEvent(
                device_id=db[1],
                event_identifier="session-end",
                event_kind="SESSION_ENDED",
                category="session",
                profile="session_v1",
                occurred_at=NOW - timedelta(days=60),
                source_key="session-end",
                summary_code="SESSION_ENDED",
                details={},
            )
        )
        await session.flush()
        summary = await power_summary(
            session, db[1], online=False, last_seen_at=None, now=NOW
        )
        assert summary.status == "sleep"
        assert await retain_power_events(session, now=NOW + timedelta(days=31)) == 1
        remaining = list((await session.scalars(select(DeviceEvent))).all())
        assert len(remaining) == 1 and remaining[0].category == "session"
        await session.commit()


def test_contract_bounds_and_unique_ids():
    valid = event()
    with pytest.raises(ValidationError):
        batch([valid, valid])
    with pytest.raises(ValidationError):
        PowerEventV1.model_validate(
            {**valid.model_dump(), "occurred_at": NOW.replace(tzinfo=None)}
        )
    with pytest.raises(ValidationError):
        PowerEventV1.model_validate(
            {
                **valid.model_dump(),
                "sleep_subtype": "hibernate",
                "event_kind": "OS_STARTED",
            }
        )


async def test_bounded_batch_summary_enrichment(db):
    await send_batch(db, batch([event()]))
    data = [dict(id=str(db[1]), online=False, last_seen_at=None)]
    async with db[0]() as session:
        await enrich_power_summaries(session, data, now=NOW)
    assert data[0]["power"]["status"] == "sleep"


async def test_timeline_marks_only_authoritative_history_without_changing_activity(db):
    await send_batch(db, batch([event()]))
    async with db[0]() as session:
        markers, truncated = await power_timeline_markers(
            session, {db[1]}, NOW - timedelta(hours=1), NOW, now=NOW
        )
        assert not truncated and len(markers) == 1
        assert markers[0]["event"].event_kind == "OS_SLEEP_STARTED"
        assert markers[0]["device_id"] == str(db[1])
