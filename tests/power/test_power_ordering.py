"""Regressions for equal-time source replay and bounded semantic selection."""

from datetime import timedelta
from uuid import UUID

import pytest
from sqlalchemy import select

from endpoint_server.context.models import DeviceEvent
from endpoint_server.power.models import PowerSourceState
from endpoint_server.power.ingestion import commit_and_ack_power_events
from endpoint_server.power.projection import (
    enrich_power_summaries,
    power_summary,
    project_power,
    source_projection,
)
from .test_power_provider import NOW, batch, db as db, event, send_batch


@pytest.mark.parametrize("reverse", [False, True])
async def test_equal_time_source_replay_converges_without_restoring_coverage(
    db, reverse
):
    original = batch([event()])
    ready = original.source_status
    lost = ready.model_copy(
        update={
            "availability": "UNAVAILABLE",
            "loss_count": 5,
            "reset_count": 1,
            "coverage_started_at": NOW - timedelta(days=1),
        }
    )
    statuses = [ready, lost]
    if reverse:
        statuses.reverse()
    for status in statuses:
        await send_batch(db, batch().model_copy(update={"source_status": status}))
    await send_batch(db, original)
    async with db[0]() as session:
        state = await session.scalar(select(PowerSourceState))
        assert source_projection(state) == lost
        summary = await power_summary(
            session, db[1], online=False, last_seen_at=None, now=NOW
        )
        assert summary.status == "unknown"
        received = state.received_at

    # Replaying the exact conservative snapshot is idempotent as well.
    async def discard_ack(_envelope):
        pass

    await commit_and_ack_power_events(
        db[0],
        db[1],
        batch().model_copy(update={"source_status": lost}),
        sequence=8,
        send=discard_ack,
        received_at=NOW + timedelta(seconds=3),
    )
    async with db[0]() as session:
        state = await session.scalar(select(PowerSourceState))
        assert source_projection(state) == lost and state.received_at == received


@pytest.mark.parametrize("reverse", [False, True])
async def test_equal_time_unknown_coverage_and_conflicting_sources_merge_conservatively(
    db, reverse
):
    first = batch().source_status.model_copy(
        update={"source": "source-a", "loss_count": 2, "reset_count": 3}
    )
    second = first.model_copy(
        update={
            "source": "source-b",
            "coverage_started_at": None,
            "loss_count": 5,
            "reset_count": 1,
        }
    )
    for status in [second, first] if reverse else [first, second]:
        await send_batch(db, batch().model_copy(update={"source_status": status}))
    async with db[0]() as session:
        source = source_projection(await session.scalar(select(PowerSourceState)))
        assert source.source == "source-a"
        assert source.availability == "DEGRADED"
        assert source.coverage_started_at is None
        assert (source.loss_count, source.reset_count) == (5, 3)
    newer = first.model_copy(
        update={
            "reported_at": NOW + timedelta(seconds=1),
            "availability": "READY",
            "loss_count": 0,
            "reset_count": 0,
        }
    )
    await send_batch(db, batch().model_copy(update={"source_status": newer}))
    async with db[0]() as session:
        assert (
            source_projection(await session.scalar(select(PowerSourceState))) == newer
        )


@pytest.mark.parametrize(
    "suppressor,evidence",
    [
        ("OS_RESUMED", "transition"),
        ("OS_STARTED", "transition"),
        ("OS_SHUTDOWN_STARTED", "request"),
    ],
)
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("same_priority", [False, True])
async def test_readers_apply_complete_semantic_tie_order_before_128_bound(
    db, suppressor, evidence, reverse, same_priority
):
    # Lowest server row UUID belongs to the suppressor; row UUID must not select state.
    facts = [
        event().model_copy(
            update={
                "event_identifier": UUID(int=1),
                "event_kind": suppressor,
                "evidence": evidence,
                "native_record_id": "suppressor",
            }
        )
    ]
    facts += [
        event().model_copy(
            update={
                "event_identifier": UUID(int=index + 2),
                "native_record_id": f"sleep-{index}",
            }
        )
        for index in range(128)
    ]
    if same_priority:
        facts = [
            fact.model_copy(update={"event_kind": suppressor, "evidence": evidence})
            for fact in facts
        ]
    # Lowest row UUID has the highest event UUID even with >128 equal priorities.
    facts.append(
        facts[0].model_copy(
            update={
                "event_identifier": UUID(int=1000),
                "native_record_id": "winning-suppressor",
            }
        )
    )
    if reverse:
        facts.reverse()
    async with db[0]() as session:
        source = batch().source_status
        session.add(
            PowerSourceState(
                device_id=db[1],
                source=source.source,
                availability=source.availability,
                reported_at=source.reported_at,
                received_at=NOW,
                coverage_started_at=source.coverage_started_at,
                loss_count=0,
                reset_count=0,
            )
        )
        for fact in facts:
            row_id = UUID(
                int=1
                if fact.native_record_id == "winning-suppressor"
                else 2
                if fact.native_record_id == "suppressor"
                else fact.event_identifier.int + 1000
            )
            session.add(
                DeviceEvent(
                    id=row_id,
                    device_id=db[1],
                    event_identifier=str(fact.event_identifier),
                    event_kind=fact.event_kind,
                    category="power",
                    profile="power_v1",
                    occurred_at=fact.occurred_at,
                    source_key=f"power:{fact.native_record_id}",
                    summary_code=fact.event_kind,
                    details={
                        "event": fact.model_dump(mode="json"),
                        "received_at": NOW.isoformat(),
                    },
                )
            )
        await session.commit()
    expected = project_power(
        online=False, last_seen_at=None, source_status=source, events=facts, now=NOW
    )
    assert (
        expected.status == "unknown"
        and expected.latest_event.event_identifier == UUID(int=1000)
    )
    async with db[0]() as session:
        actual = await power_summary(
            session, db[1], online=False, last_seen_at=None, now=NOW
        )
        fleet = [dict(id=str(db[1]), online=False, last_seen_at=None)]
        await enrich_power_summaries(session, fleet, now=NOW)
    assert actual == expected
    assert fleet[0]["power"] == expected.model_dump(mode="json")
