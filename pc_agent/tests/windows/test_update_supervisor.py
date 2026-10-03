"""Deterministic recovery schedules, independent retries and cancellation."""
from __future__ import annotations

import asyncio
from uuid import UUID

import pytest

from pc_agent.platform.windows import update_supervisor as scheduling
from pc_agent.platform.windows.update_supervisor import WindowsRecoveryUpdateSupervisor
from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateResult

DEVICE_ID = "00000000-0000-4000-8000-000000000001"


async def _run_results(results, *, device_id=DEVICE_ID, trigger=lambda: None, report_success=False):
    count = len(results)
    results = iter(results)
    delays = []
    async def check():
        return next(results)
    async def report():
        return report_success
    async def sleep(delay):
        delays.append(delay)
        if len(delays) == count + 1:
            raise asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await WindowsRecoveryUpdateSupervisor(device_id=device_id, check=check,
            report=report, trigger=trigger, sleep=sleep).run()
    return delays


@pytest.mark.asyncio
@pytest.mark.parametrize("result,state", [
    ("idle", "up_to_date"), ("unavailable", "unknown"),
    ("request_ack_pending", "unknown"), ("download_rejected", "failed"),
    ("verifying", "unknown"), ("report_pending", "unknown"),
    ("disk_insufficient", "failed"),
])
async def test_first_check_waits_for_device_delay_then_reports_before_check(result, state):
    events = []
    async def check():
        events.append("check")
        return WindowsOnlineUpdateResult(result, authenticated_check=result == "idle")
    async def report():
        events.append("report")
        return False
    async def sleep(delay):
        if not events:
            assert 0 <= delay <= 15
            events.append("initial")
            return
        assert 0 < delay <= 360
        events.append("sleep")
        raise asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await WindowsRecoveryUpdateSupervisor(device_id=DEVICE_ID, check=check, report=report,
            trigger=lambda: pytest.fail("no pending update"),
            publish=events.append, sleep=sleep).run()
    assert events == ["initial", "checking", "report", "check", state, "sleep"]


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["initial", "report", "request", "download", "sleep"])
async def test_parent_cancellation_awaits_update_cleanup(phase):
    entered, cleaned = asyncio.Event(), asyncio.Event()
    first = True
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
        return WindowsOnlineUpdateResult("idle", authenticated_check=True)
    async def sleep(_delay):
        nonlocal first
        if first:
            first = False
            if phase != "initial":
                return
        await block()
    task = asyncio.create_task(WindowsRecoveryUpdateSupervisor(device_id=DEVICE_ID, check=check,
        report=report, trigger=lambda: None, sleep=sleep).run())
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cleaned.is_set()


@pytest.mark.parametrize("value", ["", "hostname", "00000000-0000-0000-0000-000000000000",
    "00000000000040008000000000000001", "00000000-0000-4000-8000-00000000000A", None, UUID(DEVICE_ID)])
def test_invalid_or_noncanonical_device_identity_cannot_create_supervisor(value):
    with pytest.raises(ValueError):
        WindowsRecoveryUpdateSupervisor(device_id=value, check=None, report=None, trigger=None)


@pytest.mark.asyncio
async def test_reconstruction_produces_same_schedule_and_attempts_vary():
    results = [WindowsOnlineUpdateResult("idle", authenticated_check=True)] * 5 + [WindowsOnlineUpdateResult("unavailable")] * 4
    first = await _run_results(results)
    assert await _run_results(results) == first
    assert len(set(first[1:6])) == 5


def test_one_hundred_devices_have_reproducible_bounded_spread():
    devices = [str(UUID(int=(4 << 76) | (2 << 62) | i)) for i in range(1, 101)]
    for purpose, attempt, base, low, high in [
        ("initial", 0, 15, 0, 15), ("healthy", 0, 300, 240, 360),
        ("network", 9, 300, 240, 300), ("scm", 9, 30, 24, 30),
    ]:
        delays = [scheduling.deterministic_delay(device, purpose, attempt, base) for device in devices]
        assert delays == [scheduling.deterministic_delay(device, purpose, attempt, base) for device in devices]
        assert all(low <= delay <= high for delay in delays)
        assert len(set(delays)) > 1
        # Fixed inputs must occupy all four quartiles, without random sampling.
        assert {min(3, int((delay - low) / ((high - low) / 4))) for delay in delays} == {0, 1, 2, 3}


@pytest.mark.asyncio
@pytest.mark.parametrize("success_status", ["idle", "scheduled", "request_ack_pending", "download_rejected", "disk_insufficient", "update_in_progress"])
async def test_network_retry_grows_caps_and_authenticated_check_resets(success_status):
    results = [WindowsOnlineUpdateResult("unavailable")] * 9 + [WindowsOnlineUpdateResult(success_status, authenticated_check=True), WindowsOnlineUpdateResult("unavailable")]
    delays = await _run_results(results)
    for delay, base in zip(delays[1:10], [5, 10, 20, 40, 80, 160, 300, 300, 300], strict=True):
        assert base * 0.8 <= delay <= min(300, base * 1.2)
    if success_status == "idle":
        assert 240 <= delays[10] <= 360
    assert 4 <= delays[11] <= 6


@pytest.mark.asyncio
@pytest.mark.parametrize("local_status", ["pending", "recovery_pending", "verifying", "report_pending", "request_ack_pending", "update_in_progress", "idle"])
async def test_local_results_and_reports_do_not_reset_network_failure_streak(local_status):
    results = [WindowsOnlineUpdateResult("unavailable")] * 4 + [WindowsOnlineUpdateResult(local_status), WindowsOnlineUpdateResult("unavailable")]
    delays = await _run_results(results, report_success=True)
    assert 128 <= delays[-1] <= 192


@pytest.mark.asyncio
async def test_scm_retry_grows_caps_and_retries_shortly_after_temporary_failure():
    triggers = []
    def failing_trigger():
        triggers.append(True)
        raise RuntimeError("SCM unavailable")
    delays = await _run_results([WindowsOnlineUpdateResult("pending")] * 8, trigger=failing_trigger)
    for delay, base in zip(delays[1:], [2, 4, 8, 16, 30, 30, 30, 30], strict=True):
        assert base * 0.8 <= delay <= min(30, base * 1.2)
    assert len(triggers) == 8


@pytest.mark.asyncio
async def test_scm_streak_resets_only_after_actual_successful_trigger():
    triggers = []
    def trigger():
        triggers.append(True)
        if len(triggers) != 3:
            raise RuntimeError("SCM unavailable")
    results = [WindowsOnlineUpdateResult("pending"), WindowsOnlineUpdateResult("idle", authenticated_check=True)] * 2 + [WindowsOnlineUpdateResult("pending")] * 2
    delays = await _run_results(results, trigger=trigger)
    assert 1.6 <= delays[1] <= 2.4
    assert 3.2 <= delays[3] <= 4.8
    assert 24 <= delays[5] <= 30
    assert 1.6 <= delays[6] <= 2.4


@pytest.mark.asyncio
async def test_pending_worker_success_keeps_core_alive_and_verifying_does_not_retrigger():
    triggers = []
    delays = await _run_results([WindowsOnlineUpdateResult(status) for status in ["scheduled", "verifying", "verifying", "verifying"]],
        trigger=lambda: triggers.append(True))
    assert triggers == [True]
    assert 24 <= delays[1] <= 30


@pytest.mark.asyncio
async def test_corrupt_local_update_state_keeps_supervisor_alive_and_disables_trigger():
    states, delays = [], []
    async def check():
        raise ValueError("invalid local journal")
    async def report():
        return False
    async def sleep(delay):
        delays.append(delay)
        if len(delays) == 2:
            raise asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await WindowsRecoveryUpdateSupervisor(device_id=DEVICE_ID, check=check, report=report,
            trigger=lambda: pytest.fail("corrupt state must never trigger"),
            publish=states.append, sleep=sleep).run()
    assert states == ["checking", "failed"]


@pytest.mark.asyncio
async def test_unexpected_local_exception_does_not_reset_network_streak():
    checks, delays = [], []
    async def check():
        checks.append(True)
        if len(checks) == 5:
            raise ValueError("unexpected local validation error")
        return WindowsOnlineUpdateResult("unavailable")
    async def report():
        return False
    async def sleep(delay):
        delays.append(delay)
        if len(delays) == 7:
            raise asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await WindowsRecoveryUpdateSupervisor(device_id=DEVICE_ID, check=check,
            report=report, trigger=lambda: None, sleep=sleep).run()
    assert 64 <= delays[5] <= 96
    assert 128 <= delays[6] <= 192


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", ["credential", "tls"])
async def test_terminal_errors_escape_without_retry(error_type):
    from pc_agent.transport.base import GatewayCredentialRejected, GatewayTerminalError
    error = GatewayCredentialRejected if error_type == "credential" else GatewayTerminalError
    sleeps = []
    async def check():
        raise error("terminal")
    async def report():
        return False
    async def sleep(delay):
        sleeps.append(delay)
    with pytest.raises(error):
        await WindowsRecoveryUpdateSupervisor(device_id=DEVICE_ID, check=check,
            report=report, trigger=lambda: None, sleep=sleep).run()
    assert len(sleeps) == 1
