"""Fixed Program Files host for the version-selected Windows services."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Sequence
from urllib.parse import urlsplit

from pc_agent.version import AGENT_VERSION, EXIT_UPDATE_PENDING
from pc_agent.platform.windows.companion_processes import stop_tray_companions
from pc_agent.platform.windows.core_shutdown import core_shutdown_gate, record_core_stopped, reserve_core_owner
from pc_agent.platform.windows.update_transaction import UpdateInProgress, _read_state
from pc_agent.platform.windows.service_control import SERVICE_NAME, trigger_pending_updater
from pc_agent.platform.windows.update_paths import UPDATE_EXECUTABLE_NAME, WindowsUpdatePaths
from pc_agent.platform.windows.runtime_identity import _reject_reparse_chain, validate_runtime_executable


_SEMVER_TRIPLET = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")
_MIN_LAUNCHER_VERSION_PROTOCOL = (3, 2, 82)
_DEFAULT_ENDPOINT_ORIGIN = "https://endpoint.sosnadmin.local"
_CORE_STOP_GRACE_SECONDS = 10.0
_CORE_KILL_GRACE_SECONDS = 5.0
_CORE_POLL_SECONDS = 0.1



def _verify_selected_runtime(paths: WindowsUpdatePaths, selector: dict) -> None:
    """Affirm ownership at boot without adding MSI imports to the worker."""
    from pc_agent.platform.windows.installation_provenance import _selector, _inspect_core_value, ProvenanceConflict
    selector_bytes, observed = _selector(paths.current_path)
    if observed != selector:
        raise ProvenanceConflict()
    evidence = _inspect_core_value(paths, selector_bytes, observed, AGENT_VERSION)
    from pc_agent.platform.windows.staged_update_state import assert_staged_update_allowed
    assert_staged_update_allowed(paths, purpose='launch', runtime_tree_sha256=evidence.identity.tree_sha256)


def build_agent_child_command(
    paths: WindowsUpdatePaths | None = None, *, selector_bytes: bytes | None = None,
) -> list[str]:
    """Resolve the immutable runtime selected by the strict current selector."""
    paths = paths or WindowsUpdatePaths.production()
    from pc_agent.platform.windows.installer_fence import assert_launch_allowed
    assert_launch_allowed(paths)
    _reject_reparse_chain(paths.install_root, paths.current_path)
    try:
        raw = paths.current_path.read_bytes() if selector_bytes is None else selector_bytes
        payload = json.loads(raw.decode("utf-8"))
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
    _verify_selected_runtime(paths, payload)
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
    """Supervise the selected Core and require its Job to empty before returning."""

    def __init__(self, paths: WindowsUpdatePaths | None = None) -> None:
        self._paths = paths or WindowsUpdatePaths.production()
        self._process = None
        self._lock = threading.Lock()
        self._stop_deadline: float | None = None

    def run(self) -> int:
        from pc_agent.platform.windows.installation_provenance import ProvenanceConflict

        for _ in range(2):
            with self._lock:
                if self._stop_deadline is not None:
                    return 0
            selector = _read_state(self._paths.current_path, 4096, return_bytes=True)
            if selector is None:
                raise ValueError("current selector is unreadable")
            try:
                command = build_agent_child_command(self._paths, selector_bytes=selector)
            except ProvenanceConflict:
                # Validation independently reads the selector to pin runtime
                # ownership. Retry only if those exact bytes actually changed.
                if _read_state(self._paths.current_path, 4096, return_bytes=True) == selector:
                    raise
                continue
            with self._lock:
                if self._stop_deadline is not None:
                    return 0
                from pc_agent.platform.windows.core_process import WindowsCoreProcess

                with core_shutdown_gate(self._paths):
                    if _read_state(self._paths.current_path, 4096, return_bytes=True) != selector:
                        continue
                    owner = reserve_core_owner(self._paths, selector)
                process = self._process = WindowsCoreProcess(command)
                break
        else:
            raise ValueError("current selector changed before Core reservation")
        try:
            exit_code = self._wait_for_core(process)
            # Descendants that remain after a normal Core exit also belong to
            # this instance. They must exit before SCM or the updater can proceed.
            if self._stop_owned_tree(process):
                try:
                    record_core_stopped(self._paths, owner)
                except (OSError, ValueError, UpdateInProgress):
                    # An unavailable receipt cannot authorize a later selector mutation.
                    pass
        finally:
            with self._lock:
                self._process = None
                process.close()
        if exit_code == EXIT_UPDATE_PENDING:
            trigger_pending_updater()
        return exit_code

    def _wait_for_core(self, process) -> int:
        while True:
            try:
                return process.wait(_CORE_POLL_SECONDS)
            except subprocess.TimeoutExpired:
                with self._lock:
                    deadline = self._stop_deadline
                if deadline is not None and time.monotonic() >= deadline:
                    # Force is an SCM stop, never a verified update handoff.
                    return 0

    def _stop_owned_tree(self, process) -> bool:
        deadline = time.monotonic() + _CORE_KILL_GRACE_SECONDS
        active = process.active_processes()
        if active:
            process.terminate_tree()
            while active:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Could not verify termination of EndpointAgent Core Job")
                time.sleep(_CORE_POLL_SECONDS)
                active = process.active_processes()
        return active == 0 and process.verify_tree_exited(deadline)

    def stop(self, *, shutdown: bool = False) -> None:
        with self._lock:
            if self._stop_deadline is not None:
                return
            self._stop_deadline = time.monotonic() + _CORE_STOP_GRACE_SECONDS
            pipe = self._process.stdin if self._process is not None else None
            if pipe is not None and not pipe.closed:
                try:
                    if shutdown:
                        # Immutable older cores stop on any byte/EOF.
                        pipe.write(b"S")
                except (BrokenPipeError, OSError):
                    pass
                finally:
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
            self._child.stop(shutdown=True)

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(EndpointAgentService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0


def _parser() -> argparse.ArgumentParser:
    from pc_agent.platform.windows.installer_native_entry import add_installer_arguments
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--agent-service", action="store_true")
    modes.add_argument("--updater-service", action="store_true")
    add_installer_arguments(parser, modes)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    from pc_agent.platform.windows.installer_native_entry import run_installer_args
    args = _parser().parse_args(argv)
    result = run_installer_args(args)
    if result is not None:
        return result

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
