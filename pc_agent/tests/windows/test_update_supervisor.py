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
        assert 0 < delay <= 360
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
        assert 0 < delay <= 30
    with pytest.raises(UpdatePending):
        await WindowsRecoveryUpdateSupervisor(check=check, report=report,
            trigger=trigger, sleep=sleep).run()
    assert len(triggers) == 2


@pytest.mark.asyncio
async def test_network_retry_grows_is_bounded_and_resets_after_success():
    results = iter(["unavailable"] * 9 + ["idle", "unavailable"])
    delays = []
    async def check():
        return next(results)
    async def report():
        return False
    async def sleep(delay):
        delays.append(delay)
        if len(delays) == 11:
            raise asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await WindowsRecoveryUpdateSupervisor(check=check, report=report,
            trigger=lambda: None, sleep=sleep, random_sample=lambda: 0.5).run()
    assert delays[:9] == [5, 10, 20, 40, 80, 160, 300, 300, 300]
    assert delays[9:] == [300, 5]


@pytest.mark.asyncio
async def test_successful_poll_checks_do_not_align_for_different_devices():
    delays = []
    async def check():
        return "idle"
    async def report():
        return False
    async def sleep(delay):
        delays.append(delay)
        raise asyncio.CancelledError
    for sample in (0.0, 0.5, 1.0):
        with pytest.raises(asyncio.CancelledError):
            await WindowsRecoveryUpdateSupervisor(check=check, report=report,
                trigger=lambda: None, sleep=sleep, random_sample=lambda: sample).run()
    assert delays == [240, 300, 360]


@pytest.mark.asyncio
async def test_corrupt_local_update_state_keeps_supervisor_alive_and_disables_trigger():
    states = []
    async def check():
        raise ValueError("invalid local journal")
    async def report():
        return False
    async def sleep(delay):
        assert delay > 0
        raise asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await WindowsRecoveryUpdateSupervisor(check=check, report=report,
            trigger=lambda: pytest.fail("corrupt state must never trigger"),
            publish=states.append, sleep=sleep).run()
    assert states == ["checking", "failed"]
