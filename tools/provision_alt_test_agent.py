"""Stage one tightly-scoped Endpoint Platform agent claim on test-agent-lin."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import getpass
import hashlib
import json
from pathlib import Path
import re
import ssl
import subprocess
from typing import Any, Protocol
from uuid import UUID

import httpx

from endpoint_contracts.identity import normalize_install_session_id


TEST_HOST = "test-agent-lin"
ENDPOINT_ORIGIN = "https://endpoint.sosnadmin.local"
_REMOTE_INPUT_ROOT = "/root/input"
_REMOTE_BUNDLE = f"{_REMOTE_INPUT_ROOT}/endpoint-agent-test-pilot-bundle"
_REMOTE_INSTALLER = f"{_REMOTE_INPUT_ROOT}/endpoint-agent-installer"
_REMOTE_CA = f"{_REMOTE_INPUT_ROOT}/sosnadmin-local-ca.crt"
_REMOTE_CLAIM = "/etc/endpoint-agent/provisioning-claim"
_FINGERPRINT_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ALLOWED_AGENT_CIDR = "192.168.101.0/24"


class CommandRunner(Protocol):
    def run_stdin(self, command: str, payload: bytes) -> None: ...

    def run_output(self, command: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class PilotResult:
    """The only non-secret outcome that may be printed by this controller."""

    installation_id: str
    fingerprint: str
    campaign_id: UUID
    claim_expires_at: datetime


class SshRunner:
    """Fixed-host SSH runner that never embeds opaque material in a command."""

    def run_stdin(self, command: str, payload: bytes) -> None:
        subprocess.run(
            ["ssh", TEST_HOST, command], input=payload, check=True, capture_output=True
        )

    def run_output(self, command: str) -> bytes:
        completed = subprocess.run(
            ["ssh", TEST_HOST, command], check=True, capture_output=True
        )
        return completed.stdout


def validate_pilot_target(value: str) -> str:
    if value != TEST_HOST:
        raise ValueError("the controller is restricted to test-agent-lin")
    return value


def parse_hardware_fingerprint(output: bytes) -> str:
    try:
        lines = output.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("hardware fingerprint must be a single canonical line") from error
    if len(lines) != 1 or not _FINGERPRINT_PATTERN.fullmatch(lines[0]):
        raise ValueError("hardware fingerprint must be a single canonical line")
    return lines[0]


def _validate_bundle(bundle: Path) -> None:
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("bundle must be a regular local directory")
    if any(path.is_symlink() for path in bundle.rglob("*")):
        raise ValueError("bundle must not contain symbolic links")
    manifest_path = bundle / "manifest.json"
    launcher = bundle / "launcher"
    agent = bundle / "pc_agent" / "pc_agent"
    if any(path.is_symlink() or not path.is_file() for path in (manifest_path, launcher, agent)):
        raise ValueError("bundle must contain regular manifest, launcher and agent files")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entries = manifest["files"]
        if not isinstance(entries, list):
            raise ValueError("manifest files must be a list")
    except (OSError, TypeError, ValueError, KeyError) as error:
        raise ValueError("bundle manifest is invalid") from error
    manifest_paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("bundle manifest is invalid")
        relative = entry.get("path")
        expected_digest = entry.get("sha256")
        if (
            not isinstance(relative, str)
            or not isinstance(expected_digest, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or relative in manifest_paths
        ):
            raise ValueError("bundle manifest is invalid")
        payload = bundle / relative
        if payload.is_symlink() or not payload.is_file():
            raise ValueError("bundle manifest does not match local payload")
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        if digest != expected_digest:
            raise ValueError("bundle manifest does not match local payload")
        manifest_paths.add(relative)
    actual_paths = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file() and not path.is_symlink() and path != manifest_path
    }
    if manifest_paths != actual_paths:
        raise ValueError("bundle manifest does not match local payload")
    if not {"launcher", "pc_agent/pc_agent"} <= manifest_paths:
        raise ValueError("bundle manifest is missing required payload entries")


def _validate_ca(ca_file: Path) -> ssl.SSLContext:
    if ca_file.is_symlink() or not ca_file.is_file():
        raise ValueError("CA file must be a regular local file")
    try:
        return ssl.create_default_context(cafile=str(ca_file))
    except ssl.SSLError as error:
        raise ValueError("CA file is not a usable trust anchor") from error


def deliver_claim(ssh: CommandRunner, *, claim: str) -> None:
    """Write the claim only through root-owned stdin; never render it in a command."""
    ssh.run_stdin(
        "sudo install -o root -g root -m 0600 /dev/stdin "
        "/etc/endpoint-agent/provisioning-claim",
        claim.encode("ascii"),
    )


def _stage_remote_inputs(bundle: Path, ca_file: Path, ssh: SshRunner) -> None:
    """Copy reviewed non-secret release inputs to the fixed test host paths."""
    ssh.run_output(f"sudo install -d -o root -g root -m 0700 {_REMOTE_INPUT_ROOT}")
    installer = Path(__file__).resolve().parents[1] / "deploy" / "agent" / "alt"
    if installer.is_symlink() or not (installer / "install-endpoint-agent.sh").is_file():
        raise RuntimeError("local ALT installer package is unavailable")
    ssh.run_output(
        "rm -rf -- /tmp/endpoint-agent-test-pilot-bundle "
        "/tmp/endpoint-agent-installer /tmp/sosnadmin-local-ca.crt"
    )
    subprocess.run(
        ["scp", "-r", str(bundle), f"{TEST_HOST}:/tmp/endpoint-agent-test-pilot-bundle"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["scp", "-r", str(installer), f"{TEST_HOST}:/tmp/endpoint-agent-installer"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["scp", str(ca_file), f"{TEST_HOST}:/tmp/sosnadmin-local-ca.crt"],
        check=True,
        capture_output=True,
    )
    ssh.run_output(
        "sudo rm -rf -- "
        f"{_REMOTE_BUNDLE} {_REMOTE_INSTALLER}; "
        f"sudo mv -- /tmp/endpoint-agent-test-pilot-bundle {_REMOTE_BUNDLE}; "
        f"sudo mv -- /tmp/endpoint-agent-installer {_REMOTE_INSTALLER}; "
        f"sudo install -o root -g root -m 0600 /tmp/sosnadmin-local-ca.crt {_REMOTE_CA}; "
        "rm -f -- /tmp/sosnadmin-local-ca.crt"
    )


def _remote_fingerprint(ssh: CommandRunner) -> str:
    return parse_hardware_fingerprint(
        ssh.run_output(f"sudo {_REMOTE_BUNDLE}/pc_agent/pc_agent --print-hardware-fingerprint")
    )


def _response_json(response: httpx.Response, expected_status: int, category: str) -> dict[str, Any]:
    if response.status_code != expected_status:
        raise RuntimeError(category)
    try:
        payload = response.json()
    except (json.JSONDecodeError, ValueError) as error:
        raise RuntimeError(category) from error
    if not isinstance(payload, dict):
        raise RuntimeError(category)
    return payload


def _revoke_safely(
    client: httpx.Client,
    *,
    csrf_token: str,
    credential_id: str | None,
    campaign_id: str | None,
) -> None:
    headers = {"X-CSRF-Token": csrf_token}
    if credential_id:
        client.post(
            f"/api/admin/provisioning/test-pilot/credentials/{credential_id}/revoke",
            headers=headers,
        )
    if campaign_id:
        client.post(
            f"/api/admin/enrollment/campaigns/{campaign_id}/revoke", headers=headers
        )


def issue_and_deliver_claim(
    *,
    ca_file: Path,
    installation_id: str,
    fingerprint: str,
    admin_username: str,
    ssh: CommandRunner,
    admin_password: str | None = None,
) -> PilotResult:
    """Create, use, and revoke the short service bearer without exposing secrets."""
    normalized_installation_id = normalize_install_session_id(installation_id)
    context = _validate_ca(ca_file)
    password = admin_password if admin_password is not None else getpass.getpass(
        f"Endpoint administrator password for {admin_username}: "
    )
    campaign_id: str | None = None
    campaign_uuid: UUID | None = None
    credential_id: str | None = None
    csrf_token = ""
    succeeded = False
    with httpx.Client(base_url=ENDPOINT_ORIGIN, verify=context, timeout=15.0) as client:
        try:
            login = _response_json(
                client.post(
                    "/api/admin/session",
                    json={"username": admin_username, "password": password},
                ),
                201,
                "administrator authentication failed",
            )
            csrf_token = login.get("csrf_token", "")
            if not isinstance(csrf_token, str) or not csrf_token:
                raise RuntimeError("administrator authentication failed")
            headers = {"X-CSRF-Token": csrf_token}
            campaign = _response_json(
                client.post(
                    "/api/admin/enrollment/campaigns",
                    headers=headers,
                    json={
                        "expires_at": (datetime.now(UTC) + timedelta(minutes=20)).isoformat(),
                        "max_uses": 1,
                        "allowed_cidrs": [_ALLOWED_AGENT_CIDR],
                        "target_platform": "linux",
                        "policy": {},
                        "label": "ALT test pilot",
                        "site": "test-agent-lin",
                    },
                ),
                201,
                "test-pilot campaign creation failed",
            )
            campaign_id = campaign.get("id") if isinstance(campaign.get("id"), str) else None
            campaign_token = campaign.get("token")
            if campaign_id is None or not isinstance(campaign_token, str):
                raise RuntimeError("test-pilot campaign creation failed")
            try:
                campaign_uuid = UUID(campaign_id)
            except ValueError as error:
                raise RuntimeError("test-pilot campaign creation failed") from error
            del campaign_token
            credential = _response_json(
                client.post(
                    "/api/admin/provisioning/test-pilot/credentials",
                    headers=headers,
                    json={"install_session_id": normalized_installation_id},
                ),
                201,
                "test-pilot credential creation failed",
            )
            credential_id = credential.get("credential_id") if isinstance(credential.get("credential_id"), str) else None
            service_token = credential.get("token")
            if credential_id is None or not isinstance(service_token, str):
                raise RuntimeError("test-pilot credential creation failed")
            claim_response = _response_json(
                client.post(
                    "/api/v1/provisioning/install-claims",
                    headers={"Authorization": f"Bearer {service_token}"},
                    json={
                        "campaign_id": campaign_id,
                        "install_session_id": normalized_installation_id,
                        "hardware_fingerprint": fingerprint,
                    },
                ),
                201,
                "test-pilot claim issuance failed",
            )
            del service_token
            claim = claim_response.get("claim")
            expiry = claim_response.get("expires_at")
            if not isinstance(claim, str) or not isinstance(expiry, str):
                raise RuntimeError("test-pilot claim issuance failed")
            try:
                expires_at = datetime.fromisoformat(expiry)
            except ValueError as error:
                raise RuntimeError("test-pilot claim issuance failed") from error
            if expires_at.tzinfo is None:
                raise RuntimeError("test-pilot claim issuance failed")
            expires_at = expires_at.astimezone(UTC)
            deliver_claim(ssh, claim=claim)
            del claim
            succeeded = True
            assert campaign_uuid is not None
            return PilotResult(
                installation_id=normalized_installation_id,
                fingerprint=fingerprint,
                campaign_id=campaign_uuid,
                claim_expires_at=expires_at,
            )
        finally:
            if csrf_token:
                _revoke_safely(
                    client,
                    csrf_token=csrf_token,
                    credential_id=credential_id,
                    campaign_id=None if succeeded else campaign_id,
                )
                client.delete("/api/admin/session", headers={"X-CSRF-Token": csrf_token})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--installation-id", required=True)
    parser.add_argument("--admin-username", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _validate_bundle(args.bundle)
    _validate_ca(args.ca_file)
    normalize_install_session_id(args.installation_id)
    validate_pilot_target(TEST_HOST)
    ssh = SshRunner()
    _stage_remote_inputs(args.bundle, args.ca_file, ssh)
    fingerprint = _remote_fingerprint(ssh)
    result = issue_and_deliver_claim(
        ca_file=args.ca_file,
        installation_id=args.installation_id,
        fingerprint=fingerprint,
        admin_username=args.admin_username,
        ssh=ssh,
    )
    print(
        json.dumps(
            {
                "installation_id": result.installation_id,
                "fingerprint": result.fingerprint,
                "campaign_id": str(result.campaign_id),
                "claim_expires_at": result.claim_expires_at.isoformat(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
