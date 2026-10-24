import asyncio
from datetime import timedelta

from pc_agent.power.runtime import PowerEventRuntime
from pc_agent.power.spool import PowerEventSpool
from pc_agent.tests.power.test_spool import NOW, ack, event, page


async def test_power_ack_nonfatal_dispatch_and_hello_feature_bound(tmp_path):
    from endpoint_contracts.gateway_ws import PowerEventAckEnvelopeV1
    from pc_agent.runtime.lifecycle import _handle_inbound
    from pc_agent.transport.protocol import GatewayInboundV1

    # Dispatch is optional and a stale ACK must not terminate this session.
    batch_spool = PowerEventSpool(tmp_path)
    await batch_spool.open()
    await batch_spool.commit_page(page([event()]), now=NOW)
    batch = await batch_spool.next_batch(now=NOW)
    inbound = GatewayInboundV1(
        root=PowerEventAckEnvelopeV1(
            schema_version="gateway_ws_envelope_v1",
            kind="power_event_ack",
            sequence=1,
            payload=ack(batch),
        )
    )
    received = []

    async def receive(value):
        received.append(value)
        return False

    await _handle_inbound(None, None, inbound, power_ack_handler=receive)
    await _handle_inbound(None, None, inbound)
    assert received == [ack(batch)]


async def test_callback_does_not_overwrite_committed_cursor(tmp_path):
    runtime = PowerEventRuntime(PowerEventSpool(tmp_path), None)
    await runtime._open()
    await runtime.spool.commit_page(page([event()]), now=NOW)
    await runtime.record(event("callback"))
    assert await runtime.spool.checkpoint() == "cursor1"


async def test_collector_failure_and_timeout_are_nonfatal_and_status_is_current(
    tmp_path,
):
    class Source:
        source = "test.native"

        async def read_page(self, checkpoint, *, now):
            raise PermissionError("journal denied")

    runtime = PowerEventRuntime(PowerEventSpool(tmp_path), Source(), poll_seconds=0.01)
    await runtime.collect_once(now=NOW)
    status = await runtime.spool.source_status()
    assert status.availability == "UNAVAILABLE" and status.reported_at == NOW

    class Slow(Source):
        async def read_page(self, checkpoint, *, now):
            await asyncio.Event().wait()

    runtime.source = Slow()
    runtime.collect_timeout = 0.01
    await runtime.collect_once(now=NOW + timedelta(seconds=1))
    assert (await runtime.spool.source_status()).reported_at == NOW + timedelta(
        seconds=1
    )


async def test_timed_out_native_reader_is_not_spawned_again_while_pending(tmp_path):
    called = []
    unblock = asyncio.Event()

    class Source:
        source = "test.native"

        async def read_page(self, checkpoint, *, now):
            called.append(checkpoint)
            await unblock.wait()
            return page([])

    runtime = PowerEventRuntime(
        PowerEventSpool(tmp_path), Source(), collect_timeout=0.01
    )
    await runtime.collect_once(now=NOW)
    await runtime.collect_once(now=NOW)
    assert called == [None]
    unblock.set()
    await asyncio.sleep(0)
    await runtime.collect_once(now=NOW)


async def test_auth_transport_failure_wins_while_collector_is_unavailable(tmp_path):
    import pytest

    from pc_agent.transport.base import GatewayCredentialRejected

    runtime = PowerEventRuntime(PowerEventSpool(tmp_path), None)
    await runtime._open()
    await runtime.spool.commit_page(page([event()]), now=NOW)

    class Transport:
        protocol_features = frozenset({"endpoint.power-events.v1"})

        async def send_power_event_batch(self, batch):
            raise GatewayCredentialRejected("expired")

    with pytest.raises(GatewayCredentialRejected):
        await runtime.send_forever(Transport(), now=lambda: NOW)


async def test_unavailable_collector_coexists_with_heartbeat_on_same_connection(
    tmp_path,
):
    import pytest

    from endpoint_contracts.gateway_ws import GatewayHelloV1
    from pc_agent.runtime.lifecycle import _run_connected
    from pc_agent.tests.transport.test_websocket_transport import (
        _agent_hello,
        _gateway_hello_body,
    )
    from pc_agent.transport.base import GatewayRetryableError

    class Source:
        source = "test.native"

        async def read_page(self, checkpoint, *, now):
            raise PermissionError("unavailable")

    runtime = PowerEventRuntime(PowerEventSpool(tmp_path), Source(), poll_seconds=0.001)
    heartbeat_seen = asyncio.Event()
    heartbeats = []

    class Transport:
        async def receive(self):
            await heartbeat_seen.wait()
            raise GatewayRetryableError("test complete")

        async def send_heartbeat(self, heartbeat):
            heartbeats.append(heartbeat)
            if len(heartbeats) == 3:
                heartbeat_seen.set()

    async def sleep(_seconds):
        await asyncio.sleep(0.005)

    await runtime.collect_once(now=NOW)
    collector = asyncio.create_task(runtime.collect_forever())
    try:
        with pytest.raises(GatewayRetryableError):
            await _run_connected(
                Transport(),
                None,
                _agent_hello(),
                GatewayHelloV1.model_validate(_gateway_hello_body()["payload"]),
                sleep,
            )
        assert len(heartbeats) >= 3
        assert (await runtime.spool.source_status()).availability == "UNAVAILABLE"
    finally:
        collector.cancel()
        await asyncio.gather(collector, return_exceptions=True)


async def test_replay_only_when_negotiated_no_policy_and_foreign_ack_stays(tmp_path):
    class Source:
        source = "test.native"

        async def read_page(self, checkpoint, *, now):
            return page([event()])

    runtime = PowerEventRuntime(
        PowerEventSpool(tmp_path), Source(), ack_timeout_seconds=0.01
    )
    await runtime.collect_once(now=NOW)
    batches = []

    class Transport:
        protocol_features = frozenset()

        async def send_power_event_batch(self, batch):
            batches.append(batch)

    transport = Transport()
    task = asyncio.create_task(runtime.send_forever(transport, now=lambda: NOW))
    await asyncio.sleep(0.02)
    assert batches == []
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    transport.protocol_features = frozenset({"endpoint.power-events.v1"})
    task = asyncio.create_task(runtime.send_forever(transport, now=lambda: NOW))
    for _ in range(100):
        if len(batches) >= 2:
            break
        await asyncio.sleep(0.002)
    assert batches[0].batch_id == batches[1].batch_id
    assert await runtime.receive_ack(ack(batches[-1]))
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert (await runtime.spool.stats()).queued_events == 0
