"""Standalone universal Windows Setup entrypoint."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pc_agent.core.device_fingerprint import collect_device_fingerprint
from pc_agent.enrollment_bootstrap import _derive_hardware_fingerprint
from pc_agent.windows_setup import HttpsSetupTransport, SetupConfig, UniversalWindowsSetup


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="EndpointAgentSetup.exe")
    parser.add_argument("--quiet", action="store_true")
    return parser


def _resource_root() -> Path:
    """Locate one-file PyInstaller resources without accepting caller paths."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "payload"  # type: ignore[attr-defined]
    return Path(__file__).resolve().parents[3] / "setup-payload"


def _read_public_setup_config(path: Path) -> dict[str, str]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError("Windows Setup configuration is unavailable") from error
    if not raw or len(raw) > 4096:
        raise ValueError("Windows Setup configuration is invalid")
    try:
        payload: Any = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Windows Setup configuration is invalid") from error
    required = {
        "schema_version",
        "endpoint_origin",
        "installer_version",
        "installer_release_id",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("Windows Setup configuration is invalid")
    if payload.get("schema_version") != "endpoint_windows_setup_config_v1":
        raise ValueError("Windows Setup configuration is invalid")
    values = {name: payload[name] for name in required if name != "schema_version"}
    if not all(isinstance(value, str) and value for value in values.values()):
        raise ValueError("Windows Setup configuration is invalid")
    return values


def _install_embedded_msi(msi_path: Path) -> None:
    if not msi_path.is_file():
        raise RuntimeError("Windows Setup MSI is unavailable")
    completed = subprocess.run(
        ["msiexec.exe", "/i", str(msi_path), "/passive", "/norestart"],
        check=False,
        shell=False,
    )
    if completed.returncode not in {0, 3010}:
        raise RuntimeError("Windows Setup MSI installation failed")


def _installed_provisioner() -> Path:
    program_files = os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles")
    if not program_files:
        raise RuntimeError("Windows Setup Program Files location is unavailable")
    executable = Path(program_files) / "Endpoint Platform" / "Agent" / "endpoint-agent-provision.exe"
    if not executable.is_file():
        raise RuntimeError("Windows Setup provisioner is unavailable")
    return executable


def _data_root() -> Path:
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    return Path(program_data) / "Endpoint Platform" / "Agent"


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
    resources = _resource_root()
    try:
        public_config = _read_public_setup_config(resources / "setup-config.json")
        config = SetupConfig(
            endpoint_origin=public_config["endpoint_origin"],
            ca_file=resources / "endpoint-ca.crt",
            installer_version=public_config["installer_version"],
            installer_release_id=public_config["installer_release_id"],
        )
        config.validate()
        transport = HttpsSetupTransport(config.endpoint_origin, config.ca_file)
        _install_embedded_msi(resources / "EndpointAgent.msi")
        provisioner = _installed_provisioner()
    except Exception as error:
        print(f"Windows Setup failed: {type(error).__name__}", file=sys.stderr)
        return 1

    installation_id: str | None = None

    def run_provisioner(claim: str) -> None:
        if installation_id is None:
            raise RuntimeError("installation identity unavailable")
        completed = subprocess.run(
            _provisioner_command(provisioner, config, _data_root(), installation_id),
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
        transport=transport,
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
