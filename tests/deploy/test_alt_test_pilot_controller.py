"""Safety contracts for the fixed-host ALT test-pilot controller."""

from __future__ import annotations

import hashlib
import json
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


def _headless_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "headless-bundle"
    binary = bundle / "endpoint-agent" / "endpoint-agent"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"headless-agent")
    (bundle / "launcher").write_bytes(b"stable-launcher")
    (bundle / "manifest.json").write_text(
        json.dumps({"files": [{"path": "endpoint-agent/endpoint-agent",
                              "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}]}),
        encoding="utf-8",
    )
    return bundle


def test_controller_accepts_headless_bundle_and_selects_its_fingerprint_entrypoint(tmp_path: Path) -> None:
    bundle = _headless_bundle(tmp_path)
    controller._validate_bundle(bundle)
    assert controller._bundle_agent_entrypoint(bundle) == "endpoint-agent/endpoint-agent"
    fingerprint = "sha256:" + "d" * 64
    ssh = _FakeSsh((fingerprint + "\n").encode())
    assert controller._remote_fingerprint(ssh, agent_entrypoint="endpoint-agent/endpoint-agent") == fingerprint
    assert ssh.command == (
        "sudo -u endpoint-agent "
        "/opt/endpoint-agent-test-pilot-bundle/endpoint-agent/endpoint-agent "
        "--print-hardware-fingerprint"
    )


@pytest.mark.parametrize("mutation", ["tamper", "extra", "mixed"])
def test_headless_bundle_rejects_unverified_or_ambiguous_payload(tmp_path: Path, mutation: str) -> None:
    bundle = _headless_bundle(tmp_path)
    if mutation == "tamper":
        (bundle / "endpoint-agent" / "endpoint-agent").write_bytes(b"modified")
    elif mutation == "extra":
        (bundle / "unexpected").write_bytes(b"unlisted")
    else:
        legacy = bundle / "pc_agent" / "pc_agent"
        legacy.parent.mkdir()
        legacy.write_bytes(b"ambiguous-agent")
    with pytest.raises(ValueError):
        controller._validate_bundle(bundle)


def test_headless_claim_uses_native_rpm_credstore_without_changing_legacy_handoff() -> None:
    ssh = _FakeSsh()
    controller.deliver_claim(ssh, claim="claim-marker", agent_entrypoint="endpoint-agent/endpoint-agent")
    assert ssh.command == (
        "sudo install -d -o root -g root -m 0700 /etc/credstore && "
        "sudo install -o root -g root -m 0600 /dev/stdin "
        "/etc/credstore/endpoint-enrollment-claim"
    )
    assert ssh.payload == b"claim-marker"
    assert "claim-marker" not in ssh.command


def test_fingerprint_entrypoint_rejects_shell_input_before_ssh() -> None:
    ssh = _FakeSsh()
    with pytest.raises(ValueError, match="entrypoint"):
        controller._remote_fingerprint(ssh, agent_entrypoint="endpoint-agent/endpoint-agent; touch /tmp/bad")
    assert ssh.command is None


def test_public_bundle_staging_is_reachable_without_exposing_private_inputs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The service UID needs traverse/read access, while private inputs stay root-only."""
    from pathlib import PurePosixPath

    commands: list[str] = []

    class _RecordingSsh(_FakeSsh):
        def run_output(self, command: str) -> bytes:
            commands.append(command)
            return b""

    monkeypatch.setattr(controller.subprocess, "run", lambda *_args, **_kwargs: None)
    controller._stage_remote_inputs(_headless_bundle(tmp_path), tmp_path / "ca.crt", _RecordingSsh())
    bundle = PurePosixPath(controller._REMOTE_BUNDLE)
    assert PurePosixPath("/root") not in bundle.parents
    assert commands[0] == "sudo install -d -o root -g root -m 0700 /root/input"
    assert f"sudo chown -R root:root {bundle}" in commands[-1]
    assert f"sudo chmod -R u=rwX,go=rX {bundle}" in commands[-1]
    assert f"sudo chmod 0755 {bundle} {bundle}/launcher {bundle}/endpoint-agent/endpoint-agent" in commands[-1]
    assert "sudo chmod" not in " ".join(commands).replace(commands[-1], "")


@pytest.mark.parametrize(
    ("entrypoint", "destination"),
    [("pc_agent/pc_agent", "/etc/endpoint-agent/provisioning-claim"),
     ("endpoint-agent/endpoint-agent", "/etc/credstore/endpoint-enrollment-claim")],
)
def test_claim_issuance_preserves_layout_and_revokes_temporary_bearer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, entrypoint: str, destination: str
) -> None:
    campaign_id, credential_id = str(uuid4()), str(uuid4())

    class _Response:
        def __init__(self, status: int, payload: dict[str, object]):
            self.status_code, self.payload = status, payload

        def json(self):
            return self.payload

    class _Client:
        def __init__(self):
            self.calls: list[str] = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, path: str, **_kwargs):
            self.calls.append(path)
            payload = {
                "/api/admin/session": {"csrf_token": "test-csrf"},
                "/api/admin/enrollment/campaigns": {"id": campaign_id, "token": "test-campaign"},
                "/api/admin/provisioning/test-pilot/credentials": {"credential_id": credential_id, "token": "test-service"},
                "/api/v1/provisioning/install-claims": {"claim": "test-claim", "expires_at": "2099-01-01T00:00:00+00:00"},
            }.get(path)
            return _Response(201 if payload else 204, payload or {})

        def delete(self, path: str, **_kwargs):
            self.calls.append(path)
            return _Response(204, {})

    client, ssh = _Client(), _FakeSsh()
    monkeypatch.setattr(controller, "_validate_ca", lambda _path: object())
    monkeypatch.setattr(controller.httpx, "Client", lambda **_kwargs: client)
    result = controller.issue_and_deliver_claim(
        ca_file=tmp_path / "test-ca", installation_id="test-layout",
        fingerprint="sha256:" + "b" * 64, admin_username="test-admin",
        admin_password="test-password", ssh=ssh, agent_entrypoint=entrypoint,
    )
    assert str(result.campaign_id) == campaign_id
    assert ssh.command.endswith(destination)
    assert ssh.payload == b"test-claim"
    assert "test-claim" not in ssh.command
    assert f"/api/admin/provisioning/test-pilot/credentials/{credential_id}/revoke" in client.calls
    assert f"/api/admin/enrollment/campaigns/{campaign_id}/revoke" not in client.calls


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
        "/opt/endpoint-agent-test-pilot-bundle/pc_agent/pc_agent "
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
