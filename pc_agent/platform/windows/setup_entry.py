"""Standalone universal Windows Setup entrypoint."""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from pc_agent.core.device_fingerprint import collect_device_fingerprint
from pc_agent.enrollment_bootstrap import _derive_hardware_fingerprint
from pc_agent.windows_setup import HttpsSetupTransport, SetupConfig, UniversalWindowsSetup


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="EndpointAgentSetup.exe")
    parser.add_argument("--endpoint-origin", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--installer-version", required=True)
    parser.add_argument("--installer-release-id", required=True)
    parser.add_argument("--quiet", action="store_true")
    return parser


def _inventory() -> dict[str, object]:
    return {"hostname": socket.gethostname(), "macs": []}


def _provisioner_command(
    executable: Path, config: SetupConfig, data_dir: Path, installation_id: str
) -> list[str]:
    return [
        str(executable),
        "--endpoint-origin",
        config.endpoint_origin,
        "--ca-file",
        str(config.ca_file),
        "--data-dir",
        str(data_dir),
        "--installation-id",
        installation_id,
    ]


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = SetupConfig(
        endpoint_origin=args.endpoint_origin,
        ca_file=Path(args.ca_file),
        installer_version=args.installer_version,
        installer_release_id=args.installer_release_id,
    )
    provisioner = Path(sys.executable).resolve().with_name("endpoint-agent-provision.exe")
    if not provisioner.is_file():
        print("Windows Setup failed: ProvisionerUnavailable", file=sys.stderr)
        return 1

    installation_id: str | None = None

    def run_provisioner(claim: str) -> None:
        if installation_id is None:
            raise RuntimeError("installation identity unavailable")
        completed = subprocess.run(
            _provisioner_command(provisioner, config, Path(args.data_dir), installation_id),
            input=claim + "\n",
            text=True,
            capture_output=True,
            check=False,
            shell=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("Windows provisioning failed")

    setup = UniversalWindowsSetup(
        config,
        transport=HttpsSetupTransport(config.endpoint_origin, config.ca_file),
        provision_claim=run_provisioner,
        fingerprint_probe=lambda: _derive_hardware_fingerprint(collect_device_fingerprint),
        inventory_probe=_inventory,
        clock=lambda: datetime.now(UTC),
    )
    original_installation_factory = setup.installation_id_factory

    def capture_installation_id() -> str:
        nonlocal installation_id
        installation_id = original_installation_factory()
        return installation_id

    setup.installation_id_factory = capture_installation_id
    try:
        outcome = setup.run()
    except Exception as error:
        print(f"Windows Setup failed: {type(error).__name__}", file=sys.stderr)
        return 1
    if outcome.status == "provisioned":
        return 0
    if not args.quiet:
        print(f"Windows Setup: {outcome.status}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
