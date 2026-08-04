"""Enroll the local Windows Endpoint Agent through a one-time protected claim."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import getpass
import ipaddress
import json
from pathlib import Path
import re
import ssl
import subprocess
import sys
from typing import Any, Sequence
from uuid import UUID

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

import httpx

from pc_agent.core.device_fingerprint import collect_device_fingerprint
from pc_agent.enrollment_bootstrap import _derive_hardware_fingerprint
from endpoint_contracts.identity import normalize_install_session_id


ENDPOINT_ORIGIN = "https://endpoint.sosnadmin.local"
DEFAULT_EXECUTABLE = Path(r"C:\Program Files\Endpoint Platform\Agent\endpoint-agent-provision.exe")
DEFAULT_DATA_ROOT = Path(r"C:\ProgramData\Endpoint Platform\Agent")


def _validate_ca(path: Path) -> ssl.SSLContext:
    if path.is_symlink() or not path.is_file():
        raise ValueError("CA file must be a regular file")
    return ssl.create_default_context(cafile=str(path))


def windows_hardware_fingerprint() -> str:
    return _derive_hardware_fingerprint(collect_device_fingerprint)


def _response(response: httpx.Response, status: int, label: str) -> dict[str, Any]:
    if response.status_code != status:
        raise RuntimeError(label)
    try:
        payload = response.json()
    except (json.JSONDecodeError, ValueError) as error:
        raise RuntimeError(label) from error
    if not isinstance(payload, dict):
        raise RuntimeError(label)
    return payload


def _run_provisioner(executable: Path, arguments: list[str], secret: bytes) -> None:
    completed = subprocess.run(
        [str(executable), *arguments], input=secret, capture_output=True, check=False
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("ascii", errors="ignore").strip()
        match = re.fullmatch(
            r"Windows provisioning failed: ([A-Za-z][A-Za-z0-9_]*)", diagnostic
        )
        failure_type = match.group(1) if match is not None else "unknown"
        raise RuntimeError(f"Windows provisioning failed: {failure_type}")


def _validate_pilot_cidr(value: str) -> str:
    network = ipaddress.ip_network(value, strict=True)
    if network.version != 4 or network.prefixlen != 32:
        raise ValueError("Windows pilot CIDR must be one IPv4 address")
    return str(network)


def provision_windows_pilot(
    *,
    ca_file: Path,
    installation_id: str,
    administrator_username: str,
    allowed_cidr: str,
    executable: Path = DEFAULT_EXECUTABLE,
    data_root: Path = DEFAULT_DATA_ROOT,
    administrator_password: str | None = None,
) -> UUID:
    """Create a bound claim and hand it to the installed provisioner via stdin."""
    context = _validate_ca(ca_file)
    if executable.is_symlink() or not executable.is_file():
        raise ValueError("installed provisioning executable is missing")
    installation_id = normalize_install_session_id(installation_id)
    allowed_cidr = _validate_pilot_cidr(allowed_cidr)
    password = administrator_password or getpass.getpass(
        f"Endpoint administrator password for {administrator_username}: "
    )
    fingerprint = windows_hardware_fingerprint()
    campaign_id: str | None = None
    credential_id: str | None = None
    csrf = ""
    with httpx.Client(base_url=ENDPOINT_ORIGIN, verify=context, timeout=20.0) as client:
        try:
            login = _response(client.post("/api/admin/session", json={"username": administrator_username, "password": password}), 201, "administrator authentication failed")
            csrf = login.get("csrf_token", "")
            if not isinstance(csrf, str) or not csrf:
                raise RuntimeError("administrator authentication failed")
            headers = {"X-CSRF-Token": csrf}
            campaign = _response(client.post("/api/admin/enrollment/campaigns", headers=headers, json={
                "expires_at": (datetime.now(UTC) + timedelta(minutes=20)).isoformat(),
                "max_uses": 1, "allowed_cidrs": [allowed_cidr], "target_platform": "windows",
                "policy": {}, "label": "Windows local MSI pilot", "site": "local-windows-pilot",
            }), 201, "Windows pilot campaign creation failed")
            campaign_id = campaign.get("id") if isinstance(campaign.get("id"), str) else None
            if campaign_id is None:
                raise RuntimeError("Windows pilot campaign creation failed")
            credential = _response(client.post("/api/admin/provisioning/test-pilot/credentials", headers=headers, json={
                "campaign_id": campaign_id, "install_session_id": installation_id,
                "hardware_fingerprint": fingerprint,
            }), 201, "Windows pilot credential creation failed")
            credential_id = credential.get("credential_id") if isinstance(credential.get("credential_id"), str) else None
            service_token = credential.get("token")
            if credential_id is None or not isinstance(service_token, str):
                raise RuntimeError("Windows pilot credential creation failed")
            issued = _response(client.post("/api/v1/provisioning/install-claims", headers={"Authorization": f"Bearer {service_token}"}, json={
                "campaign_id": campaign_id, "install_session_id": installation_id,
                "hardware_fingerprint": fingerprint,
            }), 201, "Windows pilot claim issuance failed")
            claim = issued.get("claim")
            if not isinstance(claim, str):
                raise RuntimeError("Windows pilot claim issuance failed")
            _run_provisioner(executable, ["--endpoint-origin", ENDPOINT_ORIGIN, "--ca-file", str(ca_file), "--data-dir", str(data_root), "--installation-id", installation_id], claim.encode("ascii"))
            return UUID(campaign_id)
        finally:
            if csrf:
                headers = {"X-CSRF-Token": csrf}
                if credential_id:
                    client.post(f"/api/admin/provisioning/test-pilot/credentials/{credential_id}/revoke", headers=headers)
                if campaign_id:
                    client.post(f"/api/admin/enrollment/campaigns/{campaign_id}/revoke", headers=headers)
                client.delete("/api/admin/session", headers=headers)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--installation-id", required=True)
    parser.add_argument("--admin-username", required=True)
    parser.add_argument("--allowed-cidr", required=True)
    args = parser.parse_args(argv)
    provision_windows_pilot(ca_file=args.ca_file, installation_id=args.installation_id, administrator_username=args.admin_username, allowed_cidr=args.allowed_cidr)
    print("Windows pilot enrollment completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
