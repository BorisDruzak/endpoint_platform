"""Command-line entrypoint for the neutral headless Endpoint Agent."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from typing import Sequence

if __package__ in {None, ""} and not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pc_agent.core import runtime_paths
from pc_agent.runtime.application import RuntimeSettings, run_runtime
from pc_agent.runtime.verification import run_verify

__all__ = ["RuntimeSettings", "run_runtime", "run_verify"]


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
    modes.add_argument("--windows-updater-service", action="store_true")
    modes.add_argument("--verify", action="store_true")
    modes.add_argument("--print-safe-status", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    ca_value = args.ca_file or os.environ.get("ENDPOINT_AGENT_CA_FILE", "")
    if not str(ca_value).strip() and not (args.print_safe_status or args.windows_updater_service):
        return 75
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
    if args.verify:
        return run_verify(settings)
    if args.print_safe_status:
        from pc_agent.platform.windows.service import print_safe_status

        return print_safe_status(settings)
    return asyncio.run(run_runtime(settings))


if __name__ == "__main__":
    raise SystemExit(main())
