"""Power facts and native checkpoints survive offline restarts and exact ACKs."""

import sqlite3
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from endpoint_contracts.power_events import PowerEventAckV1, PowerSourceStatusV1
from pc_agent.power.native import NativePage, native_event
from pc_agent.power.spool import PowerEventSpool, PowerEventSpoolError

NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)


def event(record="1", **kwargs):
    return native_event(
        source="test.native",
        boot_id="boot1",
        native_record_id=record,
        event_kind="OS_STARTED",
        occurred_at=NOW,
        observed_at=NOW,
        **kwargs,
    )


def page(events=(), checkpoint="cursor1", **kwargs):
    return NativePage(
        tuple(events),
        checkpoint,
        PowerSourceStatusV1(
            schema_version="power_source_status_v1",
            source="test.native",
            availability="READY",
            reported_at=NOW,
            coverage_started_at=NOW - timedelta(days=3),
        ),
        **kwargs,
    )


def ack(batch, dispositions=None):
    return PowerEventAckV1(
        schema_version="power_event_ack_v1",
        batch_id=batch.batch_id,
        persisted_at=NOW,
        results=[
            {
                "event_identifier": e.event_identifier,
                "disposition": d,
                "reason_code": "persisted",
            }
            for e, d in zip(
                batch.events,
                dispositions or ["accepted"] * len(batch.events),
                strict=True,
            )
        ],
    )


async def test_restart_lost_ack_exact_order_and_mixed_disposition(tmp_path):
    spool = PowerEventSpool(tmp_path)
    await spool.open()
    await spool.commit_page(page([event("1"), event("2"), event("3")]), now=NOW)
    restarted = PowerEventSpool(tmp_path)
    await restarted.open()
    assert await restarted.checkpoint() == "cursor1"
    batch = await restarted.next_batch(now=NOW)
    foreign = ack(batch).model_copy(update={"batch_id": uuid4()})
    assert not await restarted.acknowledge(batch, foreign)
    assert not await restarted.acknowledge(
        batch,
        ack(batch).model_copy(update={"results": list(reversed(ack(batch).results))}),
    )
    assert not await restarted.acknowledge(
        batch, ack(batch).model_copy(update={"results": ack(batch).results[:1]})
    )
    assert (await restarted.stats()).queued_events == 3
    assert await restarted.acknowledge(
        batch, ack(batch, ["accepted", "retry_later", "rejected"])
    )
    assert [
        e.native_record_id for e in (await restarted.next_batch(now=NOW)).events
    ] == ["2"]
    stats = await restarted.stats()
    assert stats.rejected_permanent == stats.quarantined_events == 1


async def test_native_identity_observation_replay_and_conflict_rollback(tmp_path):
    spool = PowerEventSpool(tmp_path)
    await spool.open()
    e = event()
    await spool.commit_page(page([e]), now=NOW)
    await spool.commit_page(
        page(
            [e.model_copy(update={"observed_at": NOW + timedelta(seconds=2)})],
            "cursor2",
        ),
        now=NOW,
    )
    assert (await spool.stats()).queued_events == 1
    bad = e.model_copy(update={"event_kind": "OS_RESUMED"})
    with pytest.raises(PowerEventSpoolError):
        await spool.commit_page(page([event("new"), bad], "cursor3"), now=NOW)
    assert await spool.checkpoint() == "cursor2"
    assert (await spool.stats()).queued_events == 1


async def test_checkpoint_and_enqueue_atomic_on_sql_failure(tmp_path):
    spool = PowerEventSpool(tmp_path)
    await spool.open()
    await spool.commit_page(page([event()]), now=NOW)
    with sqlite3.connect(spool.path) as db:
        db.execute(
            "CREATE TRIGGER force_checkpoint_failure BEFORE UPDATE ON power_state BEGIN SELECT RAISE(ABORT,'test'); END"
        )
    with pytest.raises(sqlite3.Error):
        await spool.commit_page(page([event("2")], "cursor2"), now=NOW)
    assert await spool.checkpoint() == "cursor1"
    assert (await spool.stats()).queued_events == 1


async def test_bounds_expiry_reset_and_offline_multiday_pages(tmp_path):
    spool = PowerEventSpool(tmp_path, max_events=130)
    await spool.open()
    for i in range(3):
        await spool.commit_page(
            page([event(str(j)) for j in range(i * 60, (i + 1) * 60)], str(i)), now=NOW
        )
    assert (await spool.stats()).queued_events == 130
    assert (await spool.stats()).dropped_overflow == 50
    batch = await spool.next_batch(now=NOW + timedelta(days=3))
    assert len(batch.events) <= 128
    assert len(batch.model_dump_json().encode()) < 60000
    await spool.commit_page(page([], "reset", reset_count=1, loss_count=2), now=NOW)
    assert (await spool.source_status()).reset_count == 1
    assert (await spool.source_status()).loss_count == 52
    await spool.next_batch(now=NOW + timedelta(days=31))
    assert (await spool.stats()).queued_events == 0
    assert (await spool.stats()).dropped_expired == 130


async def test_byte_bound_and_unsafe_file(tmp_path):
    spool = PowerEventSpool(tmp_path, max_payload_bytes=1)
    await spool.open()
    await spool.commit_page(page([event()]), now=NOW)
    assert (await spool.stats()).dropped_overflow == 1
    assert await spool.checkpoint() == "cursor1"
    spool.path.unlink()
    spool.path.mkdir()
    with pytest.raises(PowerEventSpoolError):
        await PowerEventSpool(tmp_path).open()


async def test_ack_for_evicted_inflight_does_not_poison_remaining_queue(tmp_path):
    spool = PowerEventSpool(tmp_path, max_events=1)
    await spool.open()
    await spool.commit_page(page([event("old")]), now=NOW)
    inflight = await spool.next_batch(now=NOW)
    await spool.commit_page(page([event("new")], "newcursor"), now=NOW)
    assert await spool.acknowledge(inflight, ack(inflight))
    assert [e.native_record_id for e in (await spool.next_batch(now=NOW)).events] == [
        "new"
    ]


async def test_quarantine_metadata_expires_but_permanent_loss_counter_survives(
    tmp_path,
):
    spool = PowerEventSpool(tmp_path)
    await spool.open()
    await spool.commit_page(page([event()]), now=NOW)
    batch = await spool.next_batch(now=NOW)
    assert await spool.acknowledge(batch, ack(batch, ["rejected"]))
    assert (await spool.stats()).quarantined_events == 1
    await spool.next_batch(now=NOW + timedelta(days=31))
    assert (await spool.stats()).quarantined_events == 0
    assert (await spool.stats()).rejected_permanent == 1


async def test_worst_native_ids_status_counters_and_sequence_fit_entire_frame(tmp_path):
    from endpoint_contracts.gateway_ws import PowerEventBatchEnvelopeV1

    spool = PowerEventSpool(tmp_path)
    await spool.open()
    events = [
        native_event(
            source="s" * 128,
            boot_id="b" * 128,
            native_record_id=f"n{i:03d}" + "x" * 124,
            event_kind="OS_UNEXPECTED_SHUTDOWN_REPORTED",
            evidence="reported",
            occurred_at=NOW,
            observed_at=NOW,
        )
        for i in range(128)
    ]
    status = PowerSourceStatusV1(
        schema_version="power_source_status_v1",
        source="s" * 128,
        availability="DEGRADED",
        reported_at=NOW,
        coverage_started_at=NOW,
    )
    await spool.commit_page(NativePage(tuple(events), "cursor", status), now=NOW)
    with sqlite3.connect(spool.path) as db:
        db.execute("UPDATE power_state SET loss=?,resets=?", (2**63 - 1, 2**63 - 1))
    batch = await spool.next_batch(now=NOW)
    frame = PowerEventBatchEnvelopeV1(
        schema_version="gateway_ws_envelope_v1",
        kind="power_event_batch",
        sequence=2**63 - 1,
        payload=batch,
    )
    encoded = frame.model_dump_json().encode("utf-8")
    assert 1 <= len(batch.events) < 128
    assert len(encoded) <= 61440
    larger = batch.model_copy(
        update={"events": [*batch.events, events[len(batch.events)]]}
    )
    larger_frame = frame.model_copy(update={"payload": larger})
    assert len(larger_frame.model_dump_json().encode("utf-8")) > 61440
    print(f"worst_native_frame: events={len(batch.events)} frame_bytes={len(encoded)}")
