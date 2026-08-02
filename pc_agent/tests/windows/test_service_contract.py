"""Install-independent Windows service boundary contracts."""

from __future__ import annotations

import asyncio
import builtins
import importlib
import sys
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
async def test_service_preserves_update_exit_after_runtime_cleanup() -> None:
    """Changing update exit 42 would prevent the updater from taking over."""
    from pc_agent.platform.windows.service import ServiceCoordinator

    scm = _Scm()

    async def update_runtime() -> int:
        return EXIT_UPDATE_PENDING

    assert await ServiceCoordinator(update_runtime, scm).run() == EXIT_UPDATE_PENDING
    assert scm.states == ["start_pending", "running", "stop_pending", "stopped:42"]


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
