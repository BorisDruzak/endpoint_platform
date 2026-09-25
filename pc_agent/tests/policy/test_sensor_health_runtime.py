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
