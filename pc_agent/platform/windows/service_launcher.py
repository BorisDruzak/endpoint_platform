"""Fixed Program Files host for the version-selected Windows services."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import threading
from pathlib import Path
from typing import Sequence
from urllib.parse import urlsplit

from pc_agent.version import AGENT_VERSION, EXIT_UPDATE_PENDING

from pc_agent.platform.windows.service_control import SERVICE_NAME, trigger_pending_updater
from pc_agent.platform.windows.update_paths import UPDATE_EXECUTABLE_NAME, WindowsUpdatePaths
from pc_agent.platform.windows.runtime_identity import _reject_reparse_chain, validate_runtime_executable


_SEMVER_TRIPLET = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")
_MIN_LAUNCHER_VERSION_PROTOCOL = (3, 2, 82)
_DEFAULT_ENDPOINT_ORIGIN = "https://endpoint.sosnadmin.local"
_TRAY_EXECUTABLE_NAME = "EndpointAgentTray.exe"
_USER_SENSOR_EXECUTABLE_NAME = "EndpointUserSensor.exe"


def stop_tray_companions(paths: WindowsUpdatePaths | None = None) -> None:
    """Stop only fixed installed user companions before MSI replaces their files."""
    if os.name != "nt":
        return
    try:
        import win32api  # type: ignore[import-not-found]
        import win32con  # type: ignore[import-not-found]
        import win32event  # type: ignore[import-not-found]
        import win32process  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("pywin32 is required to stop Endpoint Agent tray") from error

    install_root = (paths or WindowsUpdatePaths.production()).install_root
    expected = {
        os.path.normcase(os.path.normpath(str(install_root / name)))
        for name in (_TRAY_EXECUTABLE_NAME, _USER_SENSOR_EXECUTABLE_NAME)
    }
    access = (
        win32con.PROCESS_QUERY_LIMITED_INFORMATION
        | win32con.PROCESS_TERMINATE
        | win32con.SYNCHRONIZE
    )
    tray_handles = []
    for process_id in win32process.EnumProcesses():
        try:
            handle = win32api.OpenProcess(access, False, process_id)
        except win32api.error:
            continue
        try:
            image = os.path.normcase(
                os.path.normpath(win32process.GetModuleFileNameEx(handle, 0))
            )
        except win32api.error:
            handle.Close()
            continue
        if image in expected:
            tray_handles.append(handle)
        else:
            handle.Close()
    try:
        for handle in tray_handles:
            win32process.TerminateProcess(handle, 0)
        for handle in tray_handles:
            if win32event.WaitForSingleObject(handle, 15_000) != win32event.WAIT_OBJECT_0:
                raise RuntimeError("Endpoint Agent user companion did not stop before update")
    finally:
        for handle in tray_handles:
            handle.Close()


def build_agent_child_command(paths: WindowsUpdatePaths | None = None) -> list[str]:
    """Resolve the immutable runtime selected by the strict current selector."""
    paths = paths or WindowsUpdatePaths.production()
    from .installer_fence import assert_launch_allowed
    assert_launch_allowed(paths)
    _reject_reparse_chain(paths.install_root, paths.current_path)
    try:
        payload = json.loads(paths.current_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("current selector is unreadable") from error
    if not isinstance(payload, dict):
        raise ValueError("current selector is invalid")
    if set(payload) == {"version"}:
        version = payload["version"]
    elif set(payload) == {"schema_version", "source_revision", "version"}:
        if (
            payload.get("schema_version") != 1
            or not isinstance(payload.get("source_revision"), str)
            or not _SOURCE_REVISION.fullmatch(payload["source_revision"])
        ):
            raise ValueError("current selector is invalid")
        version = payload["version"]
    else:
        raise ValueError("current selector is invalid")
    if not isinstance(version, str) or not _SEMVER_TRIPLET.fullmatch(version):
        raise ValueError("current selector is invalid")
    executable = validate_runtime_executable(paths, version)
    data_root = paths.pending_path.parents[1]
    endpoint_origin = _provisioned_endpoint_origin(data_root)
    command = [
        str(executable),
        "--windows-service-child",
        "--data-dir", str(data_root),
        "--install-root", str(paths.install_root),
        "--ca-file", str(data_root / "endpoint-ca.crt"),
        "--endpoint-origin", endpoint_origin,
        "--transport-mode", "gateway_wss",
        "--no-migration-http-pull-fallback",
    ]
    # Immutable older cores cannot parse this option. Protocol support starts
    # at 3.2.82 independently of the host's own compiled version.
    if tuple(int(part) for part in version.split(".")) >= _MIN_LAUNCHER_VERSION_PROTOCOL:
        command.extend(["--launcher-version", AGENT_VERSION])
    return command


def _provisioned_endpoint_origin(data_root: Path) -> str:
    """Read the protected Windows provisioning origin, with a safe production default."""
    origin_path = data_root / "endpoint-origin"
    try:
        origin = origin_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return _DEFAULT_ENDPOINT_ORIGIN
    except OSError as error:
        raise ValueError("provisioned endpoint origin is unreadable") from error
    parsed = urlsplit(origin)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("provisioned endpoint origin is invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("provisioned endpoint origin is invalid")
    return origin


class ChildProcessCoordinator:
    """Supervise one selected runtime and forward SCM stop by closing stdin."""

    def __init__(self, paths: WindowsUpdatePaths | None = None) -> None:
        self._paths = paths or WindowsUpdatePaths.production()
        self._process: subprocess.Popen[bytes] | None = None
        self._lock = threading.Lock()
        self._stop_requested = False

    def run(self) -> int:
        command = build_agent_child_command(self._paths)
        with self._lock:
            if self._stop_requested:
                return 0
            process = subprocess.Popen(  # noqa: S603 - executable is fixed-root validated
                command,
                cwd=str(Path(command[0]).parent),
                stdin=subprocess.PIPE,
            )
            self._process = process
        exit_code = process.wait()
        with self._lock:
            self._process = None
        if exit_code == EXIT_UPDATE_PENDING:
            trigger_pending_updater()
        return exit_code

    def stop(self) -> None:
        with self._lock:
            self._stop_requested = True
            pipe = self._process.stdin if self._process is not None else None
        if pipe is not None and not pipe.closed:
            pipe.close()


def run_agent_service() -> int:
    try:
        import servicemanager  # type: ignore[import-not-found]
        import win32service  # type: ignore[import-not-found]
        import win32serviceutil  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("pywin32 is required for EndpointAgent") from error

    class EndpointAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = "Endpoint Agent"
        _svc_description_ = "Headless Endpoint Platform device agent"

        def __init__(self, args) -> None:
            super().__init__(args)
            self._child = ChildProcessCoordinator()

        def SvcDoRun(self) -> None:
            exit_code = self._child.run()
            if exit_code:
                raise RuntimeError(f"EndpointAgent child exited with code {exit_code}")

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._child.stop()

        def SvcShutdown(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._child.stop()

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(EndpointAgentService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--agent-service", action="store_true")
    modes.add_argument("--updater-service", action="store_true")
    modes.add_argument("--installer-phase", choices=("inspect","prepare","msi-preflight","msi-enter","foundation-config","msi-complete","reconcile","finish","verify-settled"))
    parser.add_argument("--installer-session")
    parser.add_argument("--foundation-state", type=int)
    parser.add_argument("--foundation-action", type=int)
    parser.add_argument("--runtime-state", type=int)
    parser.add_argument("--runtime-action", type=int)
    parser.add_argument("--rollback-disabled", default="")
    parser.add_argument("--uninstall-finalization", default="")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.installer_phase:
        from pc_agent.platform.windows.installer_transaction_bridge import owner_authorized_phase, execute_authorized_phase
        try:
            with owner_authorized_phase(args.installer_session,args.installer_phase) as client:
                execute_authorized_phase(client,WindowsUpdatePaths.production(),
                    feature_states=(args.foundation_state,args.foundation_action,args.runtime_state,args.runtime_action),
                    rollback_disabled=args.rollback_disabled,uninstall_finalization=args.uninstall_finalization)
            return 0
        except (OSError,ValueError,TypeError,KeyError,RuntimeError) as error:
            if str(error)=="UPDATE_IN_PROGRESS": return 61
            if str(error)=="UPDATE_STATE_INVALID": return 62
            return 1
    if args.agent_service:
        return run_agent_service()
    if args.updater_service:
        from pc_agent.platform.windows.updater_service import run_windows_updater_service

        return run_windows_updater_service()
    raise ValueError("unsupported service host mode")


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ChildProcessCoordinator",
    "build_agent_child_command",
    "main",
    "run_agent_service",
    "validate_runtime_executable",
]
