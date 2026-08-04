"""Contracts for safe local Windows pilot enrollment."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest

def test_windows_pilot_launcher_resolves_ca_without_non_ascii_path_literal() -> None:
    script = Path(__file__).parents[2] / "tools" / "run-windows-pilot-enrollment.ps1"

    source = script.read_text(encoding="utf-8")

    assert source.isascii()
    assert "Get-ChildItem" in source
    assert "sosnadmin-local-ca.crt" in source
    assert '--allowed-cidr "192.168.100.1/32"' in source


def test_windows_pilot_controller_runs_from_outside_repository(tmp_path: Path) -> None:
    controller = Path(__file__).parents[2] / "tools" / "provision_windows_test_agent.py"

    completed = subprocess.run(
        [sys.executable, str(controller), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_windows_pilot_controller_exposes_only_structured_provisioner_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from tools import provision_windows_test_agent as controller

    secret = b"claim-secret-marker"
    monkeypatch.setattr(
        controller.subprocess,
        "run",
        lambda *_args, **_kwargs: type(
            "Completed", (),
            {
                "returncode": 1,
                "stderr": b"Windows provisioning failed: WindowsAclError\n",
            },
        )(),
    )

    with pytest.raises(RuntimeError, match="WindowsAclError") as error:
        controller._run_provisioner(tmp_path / "endpoint-agent-provision.exe", [], secret)

    assert secret.decode("ascii") not in str(error.value)


def test_windows_pilot_pipes_claim_only_to_provisioner_stdin(
    monkeypatch, tmp_path: Path
) -> None:
    from tools import provision_windows_test_agent as controller

    claim = "claim-secret-marker"
    campaign_id = str(uuid4())
    credential_id = str(uuid4())

    class _Response:
        def __init__(self, status_code, payload=None):
            self.status_code = status_code
            self._payload = payload or {}

        def json(self):
            return self._payload

    class _Client:
        calls = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, path, **kwargs):
            self.calls.append(("POST", path, kwargs))
            if path == "/api/admin/session":
                return _Response(201, {"csrf_token": "csrf"})
            if path == "/api/admin/enrollment/campaigns":
                return _Response(201, {"id": campaign_id, "token": "campaign-token"})
            if path == "/api/admin/provisioning/test-pilot/credentials":
                return _Response(201, {"credential_id": credential_id, "token": "service-token"})
            if path == "/api/v1/provisioning/install-claims":
                return _Response(201, {"claim": claim, "expires_at": "2026-08-03T20:00:00+00:00"})
            if path.endswith("/revoke"):
                return _Response(204)
            raise AssertionError(path)

        def delete(self, path, **kwargs):
            self.calls.append(("DELETE", path, kwargs))
            return _Response(204)

    observed = {}
    monkeypatch.setattr(controller.httpx, "Client", lambda **_kwargs: _Client())
    monkeypatch.setattr(controller, "_validate_ca", lambda _path: object())
    monkeypatch.setattr(controller, "windows_hardware_fingerprint", lambda: "sha256:" + "a" * 64)
    monkeypatch.setattr(
        controller,
        "_run_provisioner",
        lambda executable, arguments, secret: observed.update(
            executable=executable, arguments=arguments, secret=secret
        ),
    )
    executable = tmp_path / "endpoint-agent-provision.exe"
    executable.write_bytes(b"pilot executable")

    controller.provision_windows_pilot(
        ca_file=tmp_path / "ca.crt",
        installation_id="windows-pilot-001",
        administrator_username="pilot-admin",
        administrator_password="password-secret-marker",
        allowed_cidr="10.10.10.2/32",
        executable=executable,
        data_root=tmp_path / "data",
    )

    assert observed["secret"] == claim.encode("ascii")
    assert all(claim not in argument for argument in observed["arguments"])
    campaign_call = next(call for call in _Client.calls if call[1] == "/api/admin/enrollment/campaigns")
    assert campaign_call[2]["json"]["target_platform"] == "windows"
    assert campaign_call[2]["json"]["allowed_cidrs"] == ["10.10.10.2/32"]
