"""Command-line entrypoint for the neutral headless Endpoint Agent."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import select
import sys
from pathlib import Path
from typing import Sequence

if __package__ in {None, ""} and not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pc_agent.core import runtime_paths
from pc_agent.enrollment_bootstrap import EnrollmentOutcome
from pc_agent.linux_enrollment_runtime import (
    derive_linux_enrollment_binding,
    derive_linux_hardware_fingerprint,
)
from pc_agent.linux_enrollment_runtime import (
    run_linux_enrollment_gate,
    systemd_runtime_paths,
)
from pc_agent.runtime.application import RuntimeSettings, run_runtime
from pc_agent.runtime.verification import run_verify
from pc_agent.version import AGENT_VERSION

__all__ = ["RuntimeSettings", "run_runtime", "run_verify"]


def _log_enrollment_refusal(reason: str) -> None:
    """Emit a journal-safe first-boot refusal reason without runtime inputs."""
    print(f"endpoint-agent enrollment refused: reason={reason}", file=sys.stderr)


async def _run_runtime_after_first_boot_enrollment(settings: RuntimeSettings) -> int:
    """Exchange the systemd-only first-boot claim before Gateway WSS starts."""
    if os.environ.get("ENDPOINT_AGENT_ENROLLMENT_REQUIRED", "") != "1":
        return await run_runtime(settings)
    try:
        paths = systemd_runtime_paths()
    except ValueError:
        _log_enrollment_refusal("invalid_runtime_paths")
        return 75
    if paths is None:
        _log_enrollment_refusal("credentials_missing")
        return 75
    config_path, ca_file, claim_file = paths
    try:
        outcome = await run_linux_enrollment_gate(
            config_path=config_path,
            ca_file=ca_file,
            claim_file=claim_file,
        )
    except (OSError, ValueError):
        _log_enrollment_refusal("runtime_input_error")
        return 75
    if outcome.status not in {"enrolled", "already_enrolled", "handoff_pending"}:
        _log_enrollment_refusal(outcome.status)
        return 75
    return await run_runtime(settings)


async def _wait_for_service_host_pipe() -> bytes:
    """Poll the fixed host pipe without a reader thread or blocking executor."""
    descriptor = sys.stdin.buffer.fileno()
    while True:
        signal = _poll_service_host_pipe(descriptor)
        if signal is not None:
            return signal
        await asyncio.sleep(0.05)


def _poll_service_host_pipe(descriptor: int) -> bytes | None:
    """Return pipe data/EOF when available, otherwise ``None`` without blocking."""
    if os.name != "nt":
        readable, _writeable, _errors = select.select([descriptor], [], [], 0)
        return os.read(descriptor, 1) if readable else None
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.PeekNamedPipe.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.PeekNamedPipe.restype = wintypes.BOOL
    available = wintypes.DWORD()
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(descriptor))
    if kernel32.PeekNamedPipe(
        handle, None, 0, None, ctypes.byref(available), None
    ):
        if not available.value:
            return None
        return os.read(descriptor, 1)
    error = ctypes.get_last_error()
    if error in {109, 232}:  # ERROR_BROKEN_PIPE / ERROR_NO_DATA
        return b""
    raise OSError(error, "could not poll EndpointAgent service control pipe")


async def _run_service_child(settings: RuntimeSettings) -> int:
    runtime = asyncio.create_task(run_runtime(settings))
    control = asyncio.create_task(_wait_for_service_host_pipe())
    done, _pending = await asyncio.wait(
        {runtime, control}, return_when=asyncio.FIRST_COMPLETED
    )
    if runtime in done:
        control.cancel()
        return await runtime
    runtime.cancel()
    try:
        await runtime
    except asyncio.CancelledError:
        pass
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Endpoint Agent headless runtime")
    parser.add_argument("--data-dir", default=None)
    parser.add_argument("--install-root", default=None)
    parser.add_argument("--ca-file", default=None)
    parser.add_argument(
        "--endpoint-origin",
        default=os.environ.get(
            "ENDPOINT_AGENT_ORIGIN", "https://endpoint.sosnadmin.local"
        ),
    )
    parser.add_argument(
        "--transport-mode",
        choices=("gateway_http_pull", "gateway_wss"),
        default=os.environ.get(
            "ENDPOINT_AGENT_TRANSPORT_MODE", "gateway_http_pull"
        ),
    )
    parser.add_argument(
        "--migration-http-pull-fallback",
        action=argparse.BooleanOptionalAction,
        default=os.environ.get(
            "ENDPOINT_AGENT_MIGRATION_HTTP_PULL_FALLBACK", "false"
        ).strip().lower()
        in {"1", "true", "yes"},
        help="temporarily use same-origin HTTP pull only when WSS is unavailable",
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--windows-service", action="store_true")
    modes.add_argument("--windows-service-child", action="store_true")
    modes.add_argument("--windows-updater-service", action="store_true")
    modes.add_argument("--windows-restrict-updater-start", action="store_true")
    modes.add_argument("--verify", action="store_true")
    modes.add_argument("--print-safe-status", action="store_true")
    modes.add_argument("--print-version", action="store_true")
    modes.add_argument("--print-hardware-fingerprint", action="store_true")
    modes.add_argument("--print-enrollment-binding", action="store_true")
    parser.add_argument("--installation-id", default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.print_version:
        print(AGENT_VERSION)
        return 0
    if args.print_hardware_fingerprint:
        print(derive_linux_hardware_fingerprint())
        return 0
    if args.print_enrollment_binding:
        if args.installation_id is None:
            parser.error("--print-enrollment-binding requires --installation-id")
        print(
            json.dumps(
                derive_linux_enrollment_binding(args.installation_id),
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    ca_value = args.ca_file or os.environ.get("ENDPOINT_AGENT_CA_FILE", "")
    if not str(ca_value).strip() and not (
        args.print_safe_status
        or args.windows_updater_service
        or args.windows_restrict_updater_start
    ):
        return 75
    if args.windows_restrict_updater_start:
        from pc_agent.platform.windows.service_control import (
            restrict_updater_start_permissions,
        )

        restrict_updater_start_permissions()
        return 0
    if args.windows_updater_service:
        from pc_agent.platform.windows.updater_service import run_windows_updater_service

        return run_windows_updater_service()
    settings = RuntimeSettings(
        data_root=runtime_paths.resolve_data_root(cli_value=args.data_dir),
        install_root=runtime_paths.resolve_install_root(cli_value=args.install_root),
        ca_file=Path(ca_value),
        endpoint_origin=args.endpoint_origin,
        transport_mode=args.transport_mode,
        migration_http_pull_fallback=args.migration_http_pull_fallback,
    )
    if args.windows_service:
        from pc_agent.platform.windows.service import run_windows_service

        return run_windows_service(settings)
    if args.windows_service_child:
        return asyncio.run(_run_service_child(settings))
    if args.verify:
        return run_verify(settings)
    if args.print_safe_status:
        from pc_agent.platform.windows.service import print_safe_status

        return print_safe_status(settings)
    return asyncio.run(_run_runtime_after_first_boot_enrollment(settings))


if __name__ == "__main__":
    raise SystemExit(main())
