"""Health reports require a current policy ACK and live bounded facts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from pc_agent.sensor_health import SensorHealthFacts, SensorHealthRuntime
from tests.contracts.test_endpoint_policy_v1 import _policy


NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)


@pytest.mark.asyncio
async def test_health_runtime_waits_for_ack_and_never_sends_old_policy_facts() -> None:
    policy = EndpointPolicyV1.model_validate(_policy())
    current = [policy]
    observed_policies = []

    async def collect(selected):
        observed_policies.append(selected.policy_version)
        return SensorHealthFacts(
            activity_listener_state="READY",
            user_sensor_last_seen_at=NOW - timedelta(seconds=15),
            security_spool_state="READY",
            usb_source_state="READY",
            print_source_state="UNAVAILABLE",
        )

    class Transport:
        def __init__(self):
            self.reports = []

        async def send_sensor_health_report(self, report):
            self.reports.append(report)

    transport = Transport()
    runtime = SensorHealthRuntime(
        policy_provider=lambda: current[0], fact_provider=collect,
    )
    runtime.begin_connection()
    assert not await runtime.send_once(transport, observed_at=NOW)
    runtime.policy_ack_sent()
    assert await runtime.send_once(transport, observed_at=NOW)
    assert len(transport.reports) == 1
    assert transport.reports[0].user_sensor_last_seen_at == NOW - timedelta(seconds=15)
    assert "compliance" not in transport.reports[0].model_dump()
    current[0] = policy.model_copy(update={"policy_version": 2})
    assert not await runtime.send_once(transport, observed_at=NOW)
    assert observed_policies == [1]
    runtime.policy_ack_sent()
    assert await runtime.send_once(transport, observed_at=NOW + timedelta(minutes=1))
    assert transport.reports[-1].policy_version == 2


@pytest.mark.asyncio
async def test_local_health_failure_is_discarded_but_transport_failure_propagates():
    from pc_agent.transport.base import GatewayRetryableError
    policy = EndpointPolicyV1.model_validate(_policy())
    attempts = 0
    async def collect(_policy):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("local source unavailable")
        return SensorHealthFacts("READY", None, "READY", "READY", "UNAVAILABLE")
    class Transport:
        async def send_sensor_health_report(self, report):
            raise GatewayRetryableError("real transport lost")
    runtime = SensorHealthRuntime(policy_provider=lambda: policy, fact_provider=collect)
    runtime.policy_ack_sent()
    assert not await runtime.send_once(Transport(), observed_at=NOW)
    with pytest.raises(GatewayRetryableError):
        await runtime.send_once(Transport(), observed_at=NOW)


@pytest.mark.asyncio
async def test_collector_failure_does_not_stop_heartbeat_or_mask_transport_failure():
    import asyncio
    from types import SimpleNamespace
    from pc_agent.runtime.lifecycle import _run_connected
    from pc_agent.transport.base import GatewayRetryableError
    from pc_agent.transport.protocol import compatibility_agent_hello
    collected, heartbeat = asyncio.Event(), asyncio.Event()
    policy = EndpointPolicyV1.model_validate(_policy())
    async def collect(_policy):
        collected.set()
        raise OSError("expected local source failure")
    runtime = SensorHealthRuntime(policy_provider=lambda: policy, fact_provider=collect, interval_seconds=0.01)
    runtime.policy_ack_sent()
    class Transport:
        async def receive(self):
            await heartbeat.wait()
            raise GatewayRetryableError("simultaneous real failure")
        async def send_heartbeat(self, value):
            assert collected.is_set()
            heartbeat.set()
    async def heartbeat_sleep(_delay):
        await collected.wait()
        await asyncio.sleep(0)
    with pytest.raises(GatewayRetryableError, match="simultaneous real failure"):
        await _run_connected(Transport(), object(), compatibility_agent_hello(),
            SimpleNamespace(heartbeat_interval_seconds=30), heartbeat_sleep,
            connected_tasks=[runtime.send_forever(Transport(), now=lambda: NOW)])
    assert heartbeat.is_set()
