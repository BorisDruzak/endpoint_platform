"""Install-independent Windows service boundary contracts."""

from __future__ import annotations

import asyncio
import builtins
import importlib
import sys
import threading
import time
from pathlib import Path

import pytest

from pc_agent.version import EXIT_UPDATE_PENDING


class _Scm:
    def __init__(self) -> None:
        self.states: list[str] = []

    def report_start_pending(self) -> None:
        self.states.append("start_pending")

    def report_running(self) -> None:
        self.states.append("running")

    def report_stop_pending(self) -> None:
        self.states.append("stop_pending")

    def report_stopped(self, exit_code: int) -> None:
        self.states.append(f"stopped:{exit_code}")


class _BlockingRuntime:
    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def run(self) -> int:
        self.started.set()
        await asyncio.Event().wait()
        raise AssertionError("service cancellation must stop the runtime")


@pytest.mark.asyncio
@pytest.mark.parametrize("control", ["stop", "shutdown"])
async def test_service_stop_controls_cancel_the_headless_runtime(control: str) -> None:
    """A missing SCM stop/shutdown bridge would leave LocalService running."""
    from pc_agent.platform.windows.service import ServiceCoordinator

    scm = _Scm()
    runtime = _BlockingRuntime()
    coordinator = ServiceCoordinator(runtime.run, scm)
    task = asyncio.create_task(coordinator.run())
    await runtime.started.wait()

    getattr(coordinator, f"request_{control}")()

    assert await task == 0
    assert scm.states == ["start_pending", "running", "stop_pending", "stopped:0"]


@pytest.mark.asyncio
async def test_service_stop_from_scm_worker_thread_wakes_an_idle_event_loop() -> None:
    """Direct Task.cancel from a callback thread waits for unrelated loop activity."""
    from pc_agent.platform.windows.service import ServiceCoordinator

    scm = _Scm()
    runtime = _BlockingRuntime()
    coordinator = ServiceCoordinator(runtime.run, scm)
    task = asyncio.create_task(coordinator.run())
    await runtime.started.wait()
    started_at = time.monotonic()
    worker = threading.Thread(target=coordinator.request_stop)
    worker.start()
    worker.join()
    # This is a watchdog only: the callback-thread control must wake the loop
    # before it fires, not piggyback on its next scheduled event.
    asyncio.get_running_loop().call_later(0.35, lambda: None)

    assert await task == 0
    assert time.monotonic() - started_at < 0.2


@pytest.mark.asyncio
async def test_service_stop_latched_before_runtime_task_prevents_start_race() -> None:
    """An SCM stop received during startup must not create an unkillable runtime task."""
    from pc_agent.platform.windows.service import ServiceCoordinator

    scm = _Scm()
    starts: list[str] = []

    async def runtime() -> int:
        starts.append("runtime.start")
        return 0

    coordinator = ServiceCoordinator(runtime, scm)
    coordinator.request_shutdown()

    assert await coordinator.run() == 0
    assert starts == []
    assert scm.states == ["stop_pending", "stopped:0"]


@pytest.mark.asyncio
async def test_service_preserves_update_exit_after_runtime_cleanup() -> None:
    """Changing update exit 42 would prevent the updater from taking over."""
    from pc_agent.platform.windows.service import ServiceCoordinator

    scm = _Scm()

    async def update_runtime() -> int:
        return EXIT_UPDATE_PENDING

    assert await ServiceCoordinator(update_runtime, scm).run() == EXIT_UPDATE_PENDING
    assert scm.states == ["start_pending", "running", "stop_pending", "stopped:42"]


def test_pywin32_service_stopped_status_preserves_update_exit_code() -> None:
    """Reporting STOPPED with default zero loses the updater's controlled exit."""
    from types import SimpleNamespace
    from pc_agent.platform.windows.service import _report_stopped

    calls: list[tuple[object, dict[str, object]]] = []
    service = SimpleNamespace(
        ReportServiceStatus=lambda status, **kwargs: calls.append((status, kwargs))
    )
    win32service = SimpleNamespace(SERVICE_STOPPED=1)
    winerror = SimpleNamespace(ERROR_SERVICE_SPECIFIC_ERROR=1066)

    _report_stopped(service, win32service, winerror, EXIT_UPDATE_PENDING)

    assert calls == [
        (1, {"win32ExitCode": 1066, "svcExitCode": EXIT_UPDATE_PENDING})
    ]


@pytest.mark.asyncio
async def test_service_allows_the_runtime_gateway_reconnect_loop_to_complete() -> None:
    """Wrapping the runtime must not turn a retryable Gateway outage into service exit."""
    from pc_agent.platform.windows.service import ServiceCoordinator

    scm = _Scm()
    attempts: list[str] = []

    async def reconnecting_runtime() -> int:
        attempts.append("gateway.connect")
        if len(attempts) == 1:
            attempts.append("gateway.reconnect")
            await asyncio.sleep(0)
            return await reconnecting_runtime()
        return 0

    assert await ServiceCoordinator(reconnecting_runtime, scm).run() == 0
    assert attempts == ["gateway.connect", "gateway.reconnect", "gateway.connect"]
    assert scm.states[-1] == "stopped:0"


def test_service_boundary_imports_without_desktop_or_ui_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A service import that reaches Qt or the desktop cannot run before logon."""
    forbidden = ("PySide6", "qasync", "pc_agent.ui_gui", "pc_agent.ui_bridge")
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if any(name == item or name.startswith(f"{item}.") for item in forbidden):
            raise AssertionError(f"desktop import attempted: {name}")
        return original_import(name, *args, **kwargs)

    for name in list(sys.modules):
        if name == "pc_agent.platform.windows" or name.startswith(
            "pc_agent.platform.windows."
        ):
            sys.modules.pop(name)
    monkeypatch.setattr(builtins, "__import__", guarded_import)

    service = importlib.import_module("pc_agent.platform.windows.service")

    assert service.SERVICE_ACCOUNT == "NT AUTHORITY\\LocalService"


def test_headless_entrypoint_exposes_exact_windows_service_modes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Renaming or omitting a mode would break the MSI service command contract."""
    from pc_agent.runtime import main as runtime_main

    ca_file = tmp_path / "endpoint-ca.crt"
    ca_file.write_text("test CA", encoding="ascii")
    observed: list[str] = []
    monkeypatch.setattr(
        "pc_agent.platform.windows.service.run_windows_service",
        lambda _settings: observed.append("service") or 0,
    )
    monkeypatch.setattr(
        "pc_agent.platform.windows.service.print_safe_status",
        lambda _settings: observed.append("status") or 0,
    )
    shared = ["--ca-file", str(ca_file), "--data-dir", str(tmp_path / "data")]

    assert runtime_main.main(["--windows-service", *shared]) == 0
    assert runtime_main.main(["--print-safe-status", *shared]) == 0
    assert observed == ["service", "status"]

    with pytest.raises(SystemExit):
        runtime_main.main(["--claim", "must-not-be-supported", *shared])


def test_safe_status_mode_reports_invalid_setup_without_requiring_a_ca_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An absent CA must produce safe diagnostic output, not suppress status entirely."""
    from pc_agent.runtime import main as runtime_main

    observed: list[object] = []
    monkeypatch.delenv("ENDPOINT_AGENT_CA_FILE", raising=False)
    monkeypatch.setattr(
        "pc_agent.platform.windows.service.print_safe_status",
        lambda settings: observed.append(settings) or 0,
    )

    assert runtime_main.main(["--print-safe-status"]) == 0
    assert len(observed) == 1
