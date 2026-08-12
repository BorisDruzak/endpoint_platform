from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pc_agent.enrollment_bootstrap import EnrollmentOutcome
import pc_agent.linux_enrollment_runtime as runtime


def _write_runtime_inputs(tmp_path: Path) -> tuple[Path, Path]:
    credentials = tmp_path / "credentials"
    credentials.mkdir()
    config = credentials / "endpoint-agent-config"
    config.write_text(
        """schema_version: 1
gateway:
  endpoint: https://endpoint.sosnadmin.local
  ca_file: /etc/endpoint-agent/ca.crt
provisioning:
  installation_id: alt-test-agent-001
  systemd_claim_credential_name: endpoint-enrollment-claim
  permanent_credential_file: /var/lib/endpoint-agent/device-credential
""",
        encoding="utf-8",
    )
    (credentials / "endpoint-agent-ca").write_text("test-ca", encoding="utf-8")
    (credentials / "endpoint-enrollment-claim").write_text(
        "ic_0123456789abcdef0123456789abcdef.abcdefghijklmnopqrstuvwxyzABCDEFG",
        encoding="utf-8",
    )
    return config, credentials


def test_load_config_requires_one_systemd_credentials_directory(tmp_path: Path) -> None:
    config, credentials = _write_runtime_inputs(tmp_path)

    loaded = runtime.load_linux_bootstrap_config(
        config_path=config,
        ca_file=credentials / "endpoint-agent-ca",
        claim_file=credentials / "endpoint-enrollment-claim",
        uid=0,
        gid=0,
    )

    assert loaded.endpoint_url == "https://endpoint.sosnadmin.local"
    assert loaded.installation_id == "alt-test-agent-001"
    assert loaded.ca_file == credentials / "endpoint-agent-ca"


def test_load_config_rejects_credential_paths_from_different_directories(
    tmp_path: Path,
) -> None:
    config, credentials = _write_runtime_inputs(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    ca_file = other / "endpoint-agent-ca"
    ca_file.write_text("test-ca", encoding="utf-8")

    with pytest.raises(ValueError, match="same systemd credentials directory"):
        runtime.load_linux_bootstrap_config(
            config_path=config,
            ca_file=ca_file,
            claim_file=credentials / "endpoint-enrollment-claim",
            uid=0,
            gid=0,
        )


def test_systemd_paths_are_all_or_nothing_and_cannot_be_renamed() -> None:
    environment = {
        "ENDPOINT_AGENT_CONFIG": "/run/endpoint-agent-credentials/endpoint-agent-config",
        "ENDPOINT_AGENT_CA_FILE": "/run/endpoint-agent-credentials/endpoint-agent-ca",
        "ENDPOINT_AGENT_PROVISIONING_HANDOFF_FILE": "/run/endpoint-agent-credentials/endpoint-enrollment-claim",
    }

    assert runtime.systemd_runtime_paths(environment) == (
        Path("/run/endpoint-agent-credentials/endpoint-agent-config"),
        Path("/run/endpoint-agent-credentials/endpoint-agent-ca"),
        Path("/run/endpoint-agent-credentials/endpoint-enrollment-claim"),
    )

    with pytest.raises(ValueError, match="all Endpoint agent systemd credentials"):
        runtime.systemd_runtime_paths({"ENDPOINT_AGENT_CONFIG": environment["ENDPOINT_AGENT_CONFIG"]})

    renamed = dict(environment)
    renamed["ENDPOINT_AGENT_CONFIG"] = "/tmp/endpoint-agent-config"
    with pytest.raises(ValueError, match="fixed systemd paths"):
        runtime.systemd_runtime_paths(renamed)


def test_runtime_gate_uses_existing_bootstrap_with_fixed_credential_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, credentials = _write_runtime_inputs(tmp_path)
    observed: dict[str, object] = {}

    async def fake_bootstrap(credentials_dir, bootstrap_config, probe, **kwargs):
        observed["credentials_dir"] = credentials_dir
        observed["config"] = bootstrap_config
        observed["probe"] = probe
        observed["hardware_fingerprint"] = kwargs["hardware_fingerprint"]
        return EnrollmentOutcome("already_enrolled", "device-1")

    monkeypatch.setattr(runtime, "bootstrap_enrollment", fake_bootstrap)

    outcome = asyncio.run(
        runtime.run_linux_enrollment_gate(
            config_path=config,
            ca_file=credentials / "endpoint-agent-ca",
            claim_file=credentials / "endpoint-enrollment-claim",
            probe=lambda: {"machine": "fixture"},
            uid=0,
            gid=0,
        )
    )

    assert outcome.status == "already_enrolled"
    assert observed["credentials_dir"] == credentials
    assert isinstance(observed["hardware_fingerprint"], str)
    assert observed["hardware_fingerprint"].startswith("sha256:")


def test_fingerprint_is_canonical_and_contains_no_raw_probe_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runtime,
        "_derive_hardware_fingerprint",
        lambda probe: "sha256:" + "a" * 64,
    )

    value = runtime.derive_linux_hardware_fingerprint(lambda: {"serial": "secret"})

    assert value == "sha256:" + "a" * 64
    assert "secret" not in value


def test_enrollment_binding_uses_the_canonical_fingerprint_and_installation_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Claim issuance must receive the exact binding the frozen core later sends."""
    fingerprint = "sha256:" + "b" * 64
    monkeypatch.setattr(runtime, "_derive_hardware_fingerprint", lambda _probe: fingerprint)

    binding = runtime.derive_linux_enrollment_binding(
        "endpoint-test-agent-001", lambda: {"serial": "never exposed"}
    )

    assert binding == {
        "hardware_fingerprint": fingerprint,
        "installation_id": "endpoint-test-agent-001",
    }
