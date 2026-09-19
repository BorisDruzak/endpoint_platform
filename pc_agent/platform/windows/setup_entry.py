"""Standalone universal Windows Setup entrypoint."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pc_agent.core.device_fingerprint import collect_device_fingerprint
from pc_agent.device_credential import read_device_credential
from pc_agent.enrollment_bootstrap import _derive_hardware_fingerprint
from pc_agent.enrollment_identity import ENROLLMENT_IDENTITY_FILENAME, read_enrollment_device_id
from pc_agent.windows_setup import (
    HttpsSetupTransport,
    SetupClaimError,
    SetupConfig,
    SetupProvisionError,
    UniversalWindowsSetup,
)


EXIT_SUCCESS = 0
EXIT_ALREADY_INSTALLED = 10
EXIT_PREFLIGHT_FAILED = 20
EXIT_INSTALL_FAILED = 21
EXIT_ENROLLMENT_DENIED = 30
EXIT_APPROVAL_TIMEOUT = 31
EXIT_REVIEW_REQUIRED = 32
EXIT_REQUEST_EXPIRED = 33
EXIT_CLAIM_FAILED = 40
EXIT_PROVISIONING_FAILED = 41
EXIT_SERVICE_FAILED = 50
EXIT_WSS_TIMEOUT = 51
EXIT_CONTEXT_TIMEOUT = 52
EXIT_REPAIR_REQUIRED = 60
_SAFE_LOG_DETAIL = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_PROVISIONER_ERROR = re.compile(
    r"^Windows provisioning failed: ([A-Za-z][A-Za-z0-9_]{0,63})$"
)


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


def _classify_installation_state(
    data_root: Path, *, service_installed: bool = True
) -> Literal["clean", "valid", "repairable", "conflicted"]:
    """Fail closed before a rerun can overwrite enrollment-owned local state."""
    credential = data_root / "device-credential"
    identity = data_root / ENROLLMENT_IDENTITY_FILENAME
    if not credential.exists() and not identity.exists():
        return "clean"
    if not credential.is_file() or not identity.is_file():
        return "conflicted"
    try:
        read_device_credential(credential)
        read_enrollment_device_id(identity)
    except ValueError:
        return "conflicted"
    return "valid" if service_installed else "repairable"


def _agent_service_installed() -> bool:
    """Read the fixed service state without accepting a caller-controlled service name."""
    if os.name != "nt":
        return True
    executable = Path(os.environ.get("SystemRoot", r"C:\\Windows")) / "System32" / "sc.exe"
    try:
        completed = subprocess.run(
            [str(executable), "query", "EndpointAgent"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def _write_install_log(
    path: Path, *, step: str, status: str, code: int, detail: str | None = None
) -> None:
    """Append bounded setup telemetry without accepting raw server or secret material."""
    if not (
        _SAFE_LOG_DETAIL.fullmatch(step)
        and _SAFE_LOG_DETAIL.fullmatch(status)
        and isinstance(code, int)
    ):
        raise ValueError("Windows Setup log fields are invalid")
    safe_detail = detail if detail and _SAFE_LOG_DETAIL.fullmatch(detail) else "REDACTED"
    line = (
        f"{datetime.now(UTC).isoformat()} step={step} status={status} "
        f"code={code} detail={safe_detail}\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as target:
        target.write(line)


def _log_path(data_root: Path) -> Path:
    return data_root / "install.log"


def _finish(data_root: Path, *, status: str, code: int, detail: str | None = None) -> int:
    try:
        _write_install_log(
            _log_path(data_root),
            step="SETUP",
            status=status,
            code=code,
            detail=detail,
        )
    except OSError:
        # A logging failure must not change an otherwise bounded installer result.
        pass
    return code


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


def _provisioner_failure_detail(stdout: str, stderr: str) -> str:
    """Return a bounded child failure class, never its untrusted output."""
    for line in (stderr + "\n" + stdout).splitlines():
        match = _PROVISIONER_ERROR.fullmatch(line.strip())
        if match:
            return f"PROVISIONER_{match.group(1).upper()}"
    return "PROVISIONER_EXIT_NONZERO"


def _run_provisioner(
    executable: Path,
    config: SetupConfig,
    data_dir: Path,
    installation_id: str,
    claim: str,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    try:
        completed = run(
            _provisioner_command(executable, config, data_dir, installation_id),
            input=claim + "\n",
            text=True,
            capture_output=True,
            check=False,
            shell=False,
        )
    except OSError as error:
        raise SetupProvisionError(
            "Windows provisioning failed", detail="PROVISIONER_START_FAILED"
        ) from error
    if completed.returncode != 0:
        raise SetupProvisionError(
            "Windows provisioning failed",
            detail=_provisioner_failure_detail(
                str(completed.stdout or ""), str(completed.stderr or "")
            ),
        )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    data_root = _data_root()
    installation_state = _classify_installation_state(
        data_root, service_installed=_agent_service_installed()
    )
    if installation_state == "valid":
        if not args.quiet:
            print("Windows Setup: already_installed")
        return _finish(data_root, status="ALREADY_INSTALLED", code=EXIT_ALREADY_INSTALLED)
    if installation_state == "conflicted":
        print("Windows Setup failed: RepairRequired", file=sys.stderr)
        return _finish(data_root, status="REPAIR_REQUIRED", code=EXIT_REPAIR_REQUIRED)
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
    except Exception as error:
        print(f"Windows Setup failed: {type(error).__name__}", file=sys.stderr)
        return _finish(data_root, status="PREFLIGHT_FAILED", code=EXIT_PREFLIGHT_FAILED)
    try:
        _install_embedded_msi(resources / "EndpointAgent.msi")
        if installation_state == "repairable":
            if not _agent_service_installed():
                return _finish(data_root, status="SERVICE_FAILED", code=EXIT_SERVICE_FAILED)
            return _finish(data_root, status="REPAIRED", code=EXIT_ALREADY_INSTALLED)
        provisioner = _installed_provisioner()
    except Exception as error:
        print(f"Windows Setup failed: {type(error).__name__}", file=sys.stderr)
        return _finish(data_root, status="INSTALL_FAILED", code=EXIT_INSTALL_FAILED)

    installation_id: str | None = None

    def run_provisioner(claim: str) -> None:
        if installation_id is None:
            raise RuntimeError("installation identity unavailable")
        _run_provisioner(provisioner, config, _data_root(), installation_id, claim)

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
    except SetupClaimError:
        return _finish(data_root, status="CLAIM_FAILED", code=EXIT_CLAIM_FAILED)
    except SetupProvisionError as error:
        return _finish(
            data_root,
            status="PROVISIONING_FAILED",
            code=EXIT_PROVISIONING_FAILED,
            detail=error.detail,
        )
    except Exception as error:
        print(f"Windows Setup failed: {type(error).__name__}", file=sys.stderr)
        return _finish(data_root, status="PROVISIONING_FAILED", code=EXIT_PROVISIONING_FAILED)
    if outcome.status == "provisioned":
        return _finish(data_root, status="COMPLETED", code=EXIT_SUCCESS)
    exit_code = {
        "denied": EXIT_ENROLLMENT_DENIED,
        "timed_out": (
            EXIT_WSS_TIMEOUT
            if outcome.reason == "WAITING_WSS"
            else EXIT_CONTEXT_TIMEOUT
            if outcome.reason == "WAITING_CONTEXT"
            else EXIT_APPROVAL_TIMEOUT
        ),
        "waiting_approval": EXIT_APPROVAL_TIMEOUT,
        "review_required": EXIT_REVIEW_REQUIRED,
        "expired": EXIT_REQUEST_EXPIRED,
    }[outcome.status]
    if not args.quiet:
        print(f"Windows Setup: {outcome.status}")
    return _finish(
        data_root,
        status=outcome.status.upper(),
        code=exit_code,
        detail=outcome.reason,
    )


if __name__ == "__main__":
    raise SystemExit(main())
