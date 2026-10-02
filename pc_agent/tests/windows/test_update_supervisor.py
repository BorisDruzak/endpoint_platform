"""HTTPS recovery backoff, cancellation and independent status semantics."""
from __future__ import annotations

import asyncio

import pytest

from pc_agent.platform.windows.update_supervisor import WindowsRecoveryUpdateSupervisor
from pc_agent.runtime.lifecycle import UpdatePending
from pc_agent.update_schedule import UPDATE_POLL_INTERVAL_SEC


@pytest.mark.asyncio
@pytest.mark.parametrize("result,state", [
    ("idle", "up_to_date"), ("unavailable", "unknown"),
    ("request_ack_pending", "unknown"), ("download_rejected", "failed"),
    ("verifying", "unknown"), ("report_pending", "unknown"),
])
async def test_one_immediate_check_then_bounded_interval(result, state):
    events = []
    async def check():
        events.append("check")
        return result
    async def report():
        events.append("report")
        return False
    async def sleep(delay):
        assert delay == UPDATE_POLL_INTERVAL_SEC == 300
        events.append("sleep")
        raise asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await WindowsRecoveryUpdateSupervisor(check=check, report=report,
            trigger=lambda: pytest.fail("no pending update"),
            publish=events.append, sleep=sleep).run()
    assert events == ["checking", "report", "check", state, "sleep"]


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["report", "request", "download", "sleep"])
async def test_parent_cancellation_awaits_update_cleanup(phase):
    entered = asyncio.Event()
    cleaned = asyncio.Event()
    async def block():
        entered.set()
        try:
            await asyncio.Future()
        finally:
            cleaned.set()
    async def report():
        if phase == "report":
            await block()
        return False
    async def check():
        if phase in {"request", "download"}:
            await block()
        return "idle"
    async def sleep(_delay):
        await block()
    task = asyncio.create_task(WindowsRecoveryUpdateSupervisor(check=check,
        report=report, trigger=lambda: None, sleep=sleep).run())
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cleaned.is_set()


@pytest.mark.asyncio
async def test_pending_updater_trigger_failure_retries_without_busy_loop():
    triggers = []
    async def check():
        return "pending"
    async def report():
        return False
    def trigger():
        triggers.append(True)
        if len(triggers) == 1:
            raise RuntimeError("SCM unavailable")
    async def sleep(delay):
        assert delay == 300
    with pytest.raises(UpdatePending):
        await WindowsRecoveryUpdateSupervisor(check=check, report=report,
            trigger=trigger, sleep=sleep).run()
    assert len(triggers) == 2
