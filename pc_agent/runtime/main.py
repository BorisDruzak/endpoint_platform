"""Command-line entrypoint for the neutral headless Endpoint Agent."""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path
from typing import Sequence

from pc_agent.core import runtime_paths

from .application import RuntimeSettings, run_runtime
from .verification import run_verify

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
    parser.add_argument("--verify", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    ca_value = args.ca_file or os.environ.get("ENDPOINT_AGENT_CA_FILE", "")
    if not str(ca_value).strip():
        return 75
    settings = RuntimeSettings(
        data_root=runtime_paths.resolve_data_root(cli_value=args.data_dir),
        install_root=runtime_paths.resolve_install_root(cli_value=args.install_root),
        ca_file=Path(ca_value),
        endpoint_origin=args.endpoint_origin,
        transport_mode=args.transport_mode,
    )
    if args.verify:
        return run_verify(settings)
    return asyncio.run(run_runtime(settings))


if __name__ == "__main__":
    raise SystemExit(main())
