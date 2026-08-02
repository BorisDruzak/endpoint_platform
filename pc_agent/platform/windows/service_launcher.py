"""Fixed Program Files host for the version-selected Windows services."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import threading
from pathlib import Path
from typing import Sequence

from pc_agent.version import EXIT_UPDATE_PENDING

from pc_agent.platform.windows.service_control import SERVICE_NAME, trigger_pending_updater
from pc_agent.platform.windows.update_paths import UPDATE_EXECUTABLE_NAME, WindowsUpdatePaths


_SEMVER_TRIPLET = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")


def _reject_reparse_chain(root: Path, leaf: Path) -> None:
    try:
        leaf.absolute().relative_to(root.absolute())
    except ValueError as error:
        raise ValueError("selected runtime is outside versions root") from error
    current = root
    for part in (Path(), *leaf.relative_to(root).parents[::-1], leaf.relative_to(root)):
        candidate = current if part == Path() else root / part
        try:
            details = candidate.lstat()
        except OSError as error:
            raise ValueError("selected runtime is missing") from error
        if candidate.is_symlink() or getattr(details, "st_file_attributes", 0) & 0x400:
            raise ValueError("selected runtime contains a reparse point")


def build_agent_child_command(paths: WindowsUpdatePaths | None = None) -> list[str]:
    """Resolve the immutable runtime selected by the strict current selector."""
    paths = paths or WindowsUpdatePaths.production()
    _reject_reparse_chain(paths.install_root, paths.current_path)
    try:
        payload = json.loads(paths.current_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("current selector is unreadable") from error
    if (
        not isinstance(payload, dict)
        or set(payload) != {"version"}
        or not isinstance(payload["version"], str)
        or not _SEMVER_TRIPLET.fullmatch(payload["version"])
    ):
        raise ValueError("current selector is invalid")
    executable = paths.versions_root / payload["version"] / UPDATE_EXECUTABLE_NAME
    _reject_reparse_chain(paths.versions_root, executable)
    if not executable.is_file():
        raise ValueError("selected runtime executable is missing")
    data_root = paths.pending_path.parents[1]
    return [
        str(executable),
        "--windows-service-child",
        "--data-dir", str(data_root),
        "--install-root", str(paths.install_root),
        "--ca-file", str(data_root / "endpoint-ca.crt"),
        "--endpoint-origin", "https://endpoint.sosnadmin.local",
        "--transport-mode", "gateway_wss",
        "--no-migration-http-pull-fallback",
    ]


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
    modes.add_argument("--apply-programdata-acl", action="store_true")
    modes.add_argument("--restrict-updater-start", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.agent_service:
        return run_agent_service()
    if args.updater_service:
        from pc_agent.platform.windows.updater_service import run_windows_updater_service

        return run_windows_updater_service()
    if args.apply_programdata_acl:
        from pc_agent.platform.windows.acl import apply_machine_data_acl

        apply_machine_data_acl()
        return 0
    from pc_agent.platform.windows.service_control import restrict_updater_start_permissions

    restrict_updater_start_permissions()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["ChildProcessCoordinator", "build_agent_child_command", "main", "run_agent_service"]
