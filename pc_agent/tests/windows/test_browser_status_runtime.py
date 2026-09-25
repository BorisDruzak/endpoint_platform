"""Browser facts are coalesced after a policy ACK on the WSS connection."""

from __future__ import annotations

import asyncio
from datetime import datetime

import pytest

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from pc_agent.platform.windows.browser_status import (
    BrowserHostFacts, BrowserStatusRuntime,
)
from tests.contracts.test_endpoint_policy_v1 import _policy


@pytest.mark.asyncio
async def test_runtime_waits_for_policy_ack_and_sends_one_report_per_interval() -> None:
    policy = EndpointPolicyV1.model_validate(_policy())
    current = [policy]

    class Ingress:
        def latest_heartbeats(self, _policy):
            return {}

    class Probe:
        def collect(self, *, observed_at: datetime):
            return {
                family: BrowserHostFacts(
                    browser_state="UNKNOWN", running_state="UNKNOWN",
                    policy_owner="NONE", installation_policy_state="NOT_APPLIED",
                    native_host_state="MISSING", last_running_at=None,
                )
                for family in ("chrome", "yandex")
            }

    class Transport:
        def __init__(self) -> None:
            self.reports = []
            self.sent = asyncio.Event()

        async def send_browser_status_report(self, report) -> None:
            self.reports.append(report)
            self.sent.set()

    transport = Transport()
    runtime = BrowserStatusRuntime(
        policy_provider=lambda: current[0], ingress=Ingress(), probe=Probe(),
        interval_seconds=0.05,
    )
    runtime.begin_connection()
    task = asyncio.create_task(runtime.send_forever(transport))
    try:
        await asyncio.sleep(0.02)
        assert transport.reports == []
        runtime.policy_ack_sent()
        await asyncio.wait_for(transport.sent.wait(), 1)
        assert len(transport.reports) == 1
        assert [item.browser_family for item in transport.reports[0].browsers] == [
            "chrome", "yandex",
        ]
        transport.sent.clear()
        await asyncio.wait_for(transport.sent.wait(), 1)
        assert len(transport.reports) == 2

        current[0] = policy.model_copy(update={"policy_version": 2})
        await asyncio.sleep(0.1)
        assert len(transport.reports) == 2
        runtime.policy_ack_sent()
        transport.sent.clear()
        await asyncio.wait_for(transport.sent.wait(), 1)
        assert transport.reports[-1].policy_version == 2
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
