# Frozen parser excerpt from pc_agent/runtime/main.py at
# d9b0fea2b14e34b05e25058e4ee004ea61643ca6; do not adapt to current runtime APIs.
# Excerpt SHA256: b7b5193b08d185087d2d0e7ca2a3815f910cf82e9206487c59f8b87287f77248
import argparse
import os


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
    parser.add_argument(
        "--network-probe-allowed-cidr",
        action="append",
        dest="network_probe_allowed_cidrs",
        help="allow one exact CIDR for typed network probes; repeat as needed",
    )
    parser.add_argument(
        "--network-probe-allowed-suffix",
        action="append",
        dest="network_probe_allowed_suffixes",
        help="allow one dotted DNS suffix for typed network probes; repeat as needed",
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
    return parser
