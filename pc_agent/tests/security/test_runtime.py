"""SecurityEvent send loop replays stable IDs and waits for persisted ACK."""

from __future__ import annotations

import asyncio

import pytest

from endpoint_contracts.security_events import SecurityEventAckV1
from endpoint_contracts.gateway_ws import SecurityEventAckEnvelopeV1
from pc_agent.runtime.lifecycle import _handle_inbound
from pc_agent.security.runtime import SecurityEventRuntime
from pc_agent.security.spool import SecurityEventSpool
from pc_agent.transport.protocol import GatewayInboundV1

from .test_spool import NOW, _event


@pytest.mark.asyncio
async def test_subset_result_requires_pending_batch_sequence_and_exact_pending_ids(tmp_path):
    from endpoint_contracts.telemetry_results import TelemetryResultV1
    spool = SecurityEventSpool(tmp_path)
    await spool.open()
    runtime = SecurityEventRuntime(spool)
    events = [_event(), _event()]
    for event in events:
        await runtime.record(event, now=NOW)
    sent = asyncio.Queue()
    class Transport:
        async def send_security_event_batch(self, batch):
            await sent.put(batch)
            return 23
    runtime.policy_ack_sent()
    task = asyncio.create_task(runtime.send_forever(Transport(), now=lambda: NOW))
    try:
        batch = await asyncio.wait_for(sent.get(), 1)
        await asyncio.sleep(0)
        result = TelemetryResultV1(schema_version="telemetry_result_v1", report_kind="security_event_batch",
            report_id=batch.batch_id, report_sequence=23, disposition="rejected", reason_code="outside_policy",
            event_identifiers=[events[1].event_identifier])
        assert not await runtime.receive_result(result.model_copy(update={"report_sequence": 24}))
        assert not await runtime.receive_result(result.model_copy(update={"event_identifiers": [_event().event_identifier]}))
        assert not await runtime.receive_result(result.model_copy(update={"report_id": _event().event_identifier}))
        assert not await runtime.receive_result(result.model_copy(update={"event_identifiers": [
            events[1].event_identifier, events[0].event_identifier,
        ]}))
        assert await runtime.receive_result(result.model_copy(update={"disposition": "retry_later"}))
        assert (await spool.stats()).queued_events == 2
        assert (await spool.stats()).rejected_permanent == 0
        assert await runtime.receive_result(result)
        assert not await runtime.receive_result(result)  # no double counting
        assert (await spool.stats()).rejected_permanent == 1
        assert (await spool.stats()).queued_events == 1
        assert await runtime.receive_result(result.model_copy(update={"disposition": "accepted", "reason_code": "persisted",
            "event_identifiers": [events[0].event_identifier]}))
        assert (await spool.stats()).queued_events == 0
        reopened = SecurityEventSpool(tmp_path)
        await reopened.open()
        assert (await reopened.stats()).rejected_permanent == 1
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_inbound_telemetry_disposition_is_nonfatal_and_routes_to_security_runtime():
    from types import SimpleNamespace
    from endpoint_contracts.telemetry_results import TelemetryResultV1
    result = TelemetryResultV1(schema_version="telemetry_result_v1", report_kind="security_event_batch",
        report_id=_event().event_identifier, report_sequence=7, disposition="retry_later",
        reason_code="policy_pending", event_identifiers=[_event().event_identifier])
    received = []
    async def handler(value):
        received.append(value)
        return True
    await _handle_inbound(object(), object(), SimpleNamespace(root=SimpleNamespace(kind="telemetry_result", payload=result)),
                          telemetry_result_handler=handler)
    assert received == [result]


@pytest.mark.asyncio
async def test_immediate_result_waits_for_send_sequence_registration(tmp_path):
    from endpoint_contracts.telemetry_results import TelemetryResultV1
    spool = SecurityEventSpool(tmp_path)
    await spool.open()
    runtime = SecurityEventRuntime(spool)
    event = _event()
    await runtime.record(event, now=NOW)
    sent, release = asyncio.Queue(), asyncio.Event()
    class Transport:
        async def send_security_event_batch(self, batch):
            await sent.put(batch)
            await release.wait()
            return 11
    runtime.policy_ack_sent()
    task = asyncio.create_task(runtime.send_forever(Transport(), now=lambda: NOW))
    response = None
    try:
        batch = await asyncio.wait_for(sent.get(), 1)
        result = TelemetryResultV1(schema_version="telemetry_result_v1", report_kind="security_event_batch",
            report_id=batch.batch_id, report_sequence=11, disposition="accepted", reason_code="persisted",
            event_identifiers=[event.event_identifier])
        response = asyncio.create_task(runtime.receive_result(result))
        await asyncio.sleep(0)
        assert not response.done()
        release.set()
        assert await asyncio.wait_for(response, 1)
        assert (await spool.stats()).queued_events == 0
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, *([response] if response else []), return_exceptions=True)


@pytest.mark.asyncio
async def test_runtime_health_checks_open_spool(tmp_path) -> None:
    runtime = SecurityEventRuntime(SecurityEventSpool(tmp_path))
    assert not await runtime.available()
    await runtime.open()
    assert await runtime.available()


@pytest.mark.asyncio
async def test_temporary_spool_read_failure_keeps_the_sender_alive(tmp_path, monkeypatch):
    import pc_agent.security.runtime as module
    spool = SecurityEventSpool(tmp_path)
    await spool.open()
    original = spool.next_batch
    recovered = asyncio.Event()
    calls = 0
    async def flaky(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError('temporary spool failure')
        recovered.set()
        return await original(**kwargs)
    monkeypatch.setattr(spool,'next_batch',flaky)
    real_sleep=asyncio.sleep
    monkeypatch.setattr(module.asyncio,'sleep',lambda _delay:real_sleep(0.001))
    runtime=SecurityEventRuntime(spool)
    runtime.policy_ack_sent()
    task=asyncio.create_task(runtime.send_forever(object(),now=lambda:NOW))
    try:
        await asyncio.wait_for(recovered.wait(),1)
        assert not task.done()
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


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
        runtime.begin_connection()
        runtime.policy_ack_sent()
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


def test_sender_waits_for_policy_ack_frame_before_replaying(tmp_path) -> None:
    async def scenario() -> None:
        sent = asyncio.Queue()

        class Transport:
            async def send_security_event_batch(self, batch):
                await sent.put(batch)

        spool = SecurityEventSpool(tmp_path)
        await spool.open()
        runtime = SecurityEventRuntime(spool, ack_timeout_seconds=1)
        await runtime.record(_event(), now=NOW)
        runtime.begin_connection()
        task = asyncio.create_task(runtime.send_forever(Transport(), now=lambda: NOW))
        try:
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(sent.get(), 0.05)
            runtime.policy_ack_sent()
            assert (await asyncio.wait_for(sent.get(), 1)).events
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    asyncio.run(scenario())
