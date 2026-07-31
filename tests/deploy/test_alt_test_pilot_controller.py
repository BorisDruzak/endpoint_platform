"""Safety contracts for the fixed-host ALT test-pilot controller."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from tools import provision_alt_test_agent as controller


class _FakeSsh:
    def __init__(self, output: bytes = b"") -> None:
        self.output = output
        self.command: str | None = None
        self.payload: bytes | None = None

    def run_stdin(self, command: str, payload: bytes) -> None:
        self.command = command
        self.payload = payload

    def run_output(self, command: str) -> bytes:
        self.command = command
        return self.output


def test_controller_refuses_every_target_except_test_agent_lin() -> None:
    assert controller.validate_pilot_target("test-agent-lin") == "test-agent-lin"

    with pytest.raises(ValueError, match="test-agent-lin"):
        controller.validate_pilot_target("192.168.100.19")


def test_claim_delivery_uses_root_only_stdin_without_rendering_the_claim() -> None:
    ssh = _FakeSsh()
    marker = "claim-secret-marker"

    controller.deliver_claim(ssh, claim=marker)

    assert ssh.command == (
        "sudo install -o root -g root -m 0600 /dev/stdin "
        "/etc/endpoint-agent/provisioning-claim"
    )
    assert ssh.payload == marker.encode("ascii")
    assert marker not in (ssh.command or "")


def test_remote_fingerprint_must_be_the_single_canonical_line() -> None:
    fingerprint = "sha256:" + "a" * 64
    assert controller.parse_hardware_fingerprint((fingerprint + "\n").encode()) == fingerprint

    with pytest.raises(ValueError, match="single canonical"):
        controller.parse_hardware_fingerprint((fingerprint + "\nextra\n").encode())
    with pytest.raises(ValueError, match="single canonical"):
        controller.parse_hardware_fingerprint(b"sha256:not-a-hash\n")


def test_remote_fingerprint_is_collected_as_the_agent_service_account() -> None:
    """The claim binding must match the identity that later runs enrollment."""
    fingerprint = "sha256:" + "c" * 64
    ssh = _FakeSsh((fingerprint + "\n").encode())

    assert controller._remote_fingerprint(ssh) == fingerprint
    assert ssh.command == (
        "sudo -u endpoint-agent "
        "/root/input/endpoint-agent-test-pilot-bundle/pc_agent/pc_agent "
        "--print-hardware-fingerprint"
    )


def test_controller_prepares_the_service_identity_before_collecting_fingerprint() -> None:
    ssh = _FakeSsh()

    controller._prepare_remote_service_account(ssh)

    assert ssh.command == (
        "sudo /root/input/endpoint-agent-installer/install-endpoint-agent.sh "
        "--prepare-service-account"
    )


def test_parser_accepts_only_local_inputs_and_administrator_name(tmp_path: Path) -> None:
    parser = controller.build_parser()
    parsed = parser.parse_args(
        [
            "--bundle",
            str(tmp_path / "bundle"),
            "--ca-file",
            str(tmp_path / "ca.crt"),
            "--installation-id",
            "alt-test-agent-001",
            "--admin-username",
            "pilot-admin",
        ]
    )

    assert parsed.installation_id == "alt-test-agent-001"
    with pytest.raises(SystemExit):
        parser.parse_args(["--claim", "must-not-be-an-argument"])


def test_claim_failure_revokes_short_service_bearer_and_campaign_without_logging_secrets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    campaign_id = str(uuid4())
    credential_id = str(uuid4())

    class _Response:
        def __init__(self, status_code: int, payload: dict[str, object]) -> None:
            self.status_code = status_code
            self._payload = payload

        def json(self) -> dict[str, object]:
            return self._payload

    class _Client:
        def __init__(self, **_kwargs) -> None:
            self.calls: list[tuple[str, str]] = []

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def post(self, path: str, **_kwargs):
            self.calls.append(("POST", path))
            if path == "/api/admin/session":
                return _Response(201, {"csrf_token": "csrf-token"})
            if path == "/api/admin/enrollment/campaigns":
                return _Response(201, {"id": campaign_id, "token": "campaign-secret"})
            if path == "/api/admin/provisioning/test-pilot/credentials":
                return _Response(201, {"credential_id": credential_id, "token": "service-secret"})
            if path == "/api/v1/provisioning/install-claims":
                return _Response(500, {})
            return _Response(204, {})

        def delete(self, path: str, **_kwargs):
            self.calls.append(("DELETE", path))
            return _Response(204, {})

    fake_client = _Client()
    monkeypatch.setattr(controller, "_validate_ca", lambda _path: object())
    monkeypatch.setattr(controller.httpx, "Client", lambda **_kwargs: fake_client)

    with pytest.raises(RuntimeError, match="claim issuance failed"):
        controller.issue_and_deliver_claim(
            ca_file=tmp_path / "unused-ca.crt",
            installation_id="alt-test-agent-001",
            fingerprint="sha256:" + "b" * 64,
            admin_username="pilot-admin",
            admin_password="password-secret-marker",
            ssh=_FakeSsh(),
        )

    assert ("POST", f"/api/admin/provisioning/test-pilot/credentials/{credential_id}/revoke") in fake_client.calls
    assert ("POST", f"/api/admin/enrollment/campaigns/{campaign_id}/revoke") in fake_client.calls
    assert ("DELETE", "/api/admin/session") in fake_client.calls
    assert all("secret" not in path for _method, path in fake_client.calls)
