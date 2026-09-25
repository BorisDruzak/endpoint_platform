"""SecurityEvent send loop replays stable IDs and waits for persisted ACK."""

from __future__ import annotations

import asyncio

from endpoint_contracts.security_events import SecurityEventAckV1
from endpoint_contracts.gateway_ws import SecurityEventAckEnvelopeV1
from pc_agent.runtime.lifecycle import _handle_inbound
from pc_agent.security.runtime import SecurityEventRuntime
from pc_agent.security.spool import SecurityEventSpool
from pc_agent.transport.protocol import GatewayInboundV1

from .test_spool import NOW, _event


def test_sender_retries_same_batch_until_exact_ack(tmp_path) -> None:
    async def scenario() -> None:
        sent = asyncio.Queue()

        class Transport:
            async def send_security_event_batch(self, batch):
                await sent.put(batch)

        spool = SecurityEventSpool(tmp_path)
        await spool.open()
        runtime = SecurityEventRuntime(spool, ack_timeout_seconds=0.02)
        event = _event()
        assert await runtime.record(event, now=NOW)
        task = asyncio.create_task(runtime.send_forever(Transport(), now=lambda: NOW))
        try:
            first = await asyncio.wait_for(sent.get(), 1)
            second = await asyncio.wait_for(sent.get(), 1)
            assert first.batch_id == second.batch_id
            assert first.events[0].event_identifier == second.events[0].event_identifier
            assert (await spool.stats()).queued_events == 1
            bad = SecurityEventAckV1(
                schema_version="security_event_ack_v1", batch_id=first.batch_id,
                event_identifiers=[_event().event_identifier], persisted_at=NOW,
            )
            assert not await runtime.receive_ack(bad)
            good = bad.model_copy(update={
                "event_identifiers": [event.event_identifier],
            })
            assert await runtime.receive_ack(good)
            await asyncio.wait_for(runtime.acknowledged.wait(), 1)
            assert (await spool.stats()).queued_events == 0
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    asyncio.run(scenario())


def test_gateway_inbound_routes_security_ack_to_runtime() -> None:
    async def scenario() -> None:
        ack = SecurityEventAckV1(
            schema_version="security_event_ack_v1", batch_id=_event().event_identifier,
            event_identifiers=[_event().event_identifier], persisted_at=NOW,
        )
        inbound = GatewayInboundV1(root=SecurityEventAckEnvelopeV1(
            schema_version="gateway_ws_envelope_v1", sequence=1,
            kind="security_event_ack", payload=ack,
        ))
        received = []

        async def handler(value):
            received.append(value)
            return True

        await _handle_inbound(
            object(), object(), inbound, security_ack_handler=handler,
        )
        assert received == [ack]

    asyncio.run(scenario())
