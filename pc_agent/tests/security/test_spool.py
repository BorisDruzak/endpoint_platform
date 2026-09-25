"""A SecurityEvent remains durable until its exact persisted ACK is received."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from endpoint_contracts.security_events import SecurityEventAckV1, UsbConnectedEventV1, UsbEventMetadataV1
from pc_agent.security.spool import SecurityEventSpool, SecurityEventSpoolError
import pytest


NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)


def _event(*, occurred_at: datetime = NOW) -> UsbConnectedEventV1:
    return UsbConnectedEventV1(
        schema_version="security_event_v1", event_identifier=uuid4(),
        severity="INFO", occurred_at=occurred_at, policy_id=uuid4(),
        policy_version=1, event_type="USB_DEVICE_CONNECTED", channel="USB",
        safe_metadata=UsbEventMetadataV1(removable=True),
    )


def test_spool_survives_restart_and_deletes_only_matching_ack(tmp_path) -> None:
    async def scenario() -> None:
        first = SecurityEventSpool(tmp_path)
        await first.open()
        event = _event()
        assert await first.enqueue(event, now=NOW)

        restarted = SecurityEventSpool(tmp_path)
        await restarted.open()
        batch = await restarted.next_batch(now=NOW)
        assert batch is not None
        assert [item.event_identifier for item in batch.events] == [event.event_identifier]

        wrong_ack = SecurityEventAckV1(
            schema_version="security_event_ack_v1", batch_id=uuid4(),
            event_identifiers=[event.event_identifier], persisted_at=NOW,
        )
        assert not await restarted.acknowledge(batch, wrong_ack)
        assert (await restarted.stats()).queued_events == 1

        ack = wrong_ack.model_copy(update={"batch_id": batch.batch_id})
        assert await restarted.acknowledge(batch, ack)
        assert (await restarted.stats()).queued_events == 0
        assert not await restarted.acknowledge(batch, ack)

    asyncio.run(scenario())


def test_spool_discards_oldest_and_counts_overflow(tmp_path) -> None:
    async def scenario() -> None:
        spool = SecurityEventSpool(tmp_path, max_events=2)
        await spool.open()
        events = [_event() for _ in range(3)]
        for event in events:
            assert await spool.enqueue(event, now=NOW)
        batch = await spool.next_batch(now=NOW)
        assert batch is not None
        assert [item.event_identifier for item in batch.events] == [
            events[1].event_identifier, events[2].event_identifier,
        ]
        stats = await spool.stats()
        assert stats.queued_events == 2
        assert stats.dropped_overflow == 1

    asyncio.run(scenario())


def test_spool_discards_expired_events_and_counts_them(tmp_path) -> None:
    async def scenario() -> None:
        spool = SecurityEventSpool(tmp_path)
        await spool.open()
        old = _event(occurred_at=NOW - timedelta(hours=25))
        assert not await spool.enqueue(old, now=NOW)
        current = _event()
        assert await spool.enqueue(current, now=NOW)
        assert await spool.next_batch(now=NOW + timedelta(hours=25)) is None
        stats = await spool.stats()
        assert stats.queued_events == 0
        assert stats.dropped_expired == 2

    asyncio.run(scenario())


def test_spool_enforces_byte_bound(tmp_path) -> None:
    async def scenario() -> None:
        event = _event()
        event_size = len(event.model_dump_json().encode("utf-8"))
        spool = SecurityEventSpool(
            tmp_path, max_payload_bytes=2 * event_size + event_size // 2,
        )
        await spool.open()
        events = [event, _event(), _event()]
        for item in events:
            assert await spool.enqueue(item, now=NOW)
        stats = await spool.stats()
        assert stats.queued_events == 2
        assert stats.queued_payload_bytes <= 2 * event_size + event_size // 2
        assert stats.dropped_overflow == 1
        batch = await spool.next_batch(now=NOW)
        assert batch is not None
        assert [item.event_identifier for item in batch.events] == [
            events[1].event_identifier, events[2].event_identifier,
        ]

    asyncio.run(scenario())


def test_duplicate_browser_delivery_is_acknowledged_only_if_payload_matches(tmp_path) -> None:
    async def scenario() -> None:
        spool = SecurityEventSpool(tmp_path)
        await spool.open()
        event = _event()
        assert await spool.enqueue(event, now=NOW)
        assert await spool.enqueue(event, now=NOW)
        assert (await spool.stats()).queued_events == 1
        changed = event.model_copy(update={
            "safe_metadata": UsbEventMetadataV1(removable=False),
        })
        with pytest.raises(SecurityEventSpoolError, match="conflicts"):
            await spool.enqueue(changed, now=NOW)
        assert (await spool.stats()).queued_events == 1

    asyncio.run(scenario())
