"""Contract tests for the offline ALT Endpoint Agent installation artifact."""

from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "deploy" / "agent" / "alt" / "install-endpoint-agent.sh"
SERVICE = ROOT / "deploy" / "agent" / "alt" / "endpoint-agent.service"
CONFIG = ROOT / "deploy" / "agent" / "alt" / "default-config.yaml"
RUNBOOK = ROOT / "docs" / "runbooks" / "ALT_AGENT_INSTALL.md"


def _text(path: Path) -> str:
    assert path.is_file(), f"missing package artifact: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def test_package_layout_is_fixed_and_inspectable_without_root() -> None:
    completed = subprocess.run(
        ["bash", INSTALLER.as_posix(), "--inspect-layout"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout.splitlines() == [
        "/opt/endpoint-agent",
        "/var/lib/endpoint-agent",
        "/etc/endpoint-agent",
        "/var/log/endpoint-agent",
    ]


def test_installer_requires_https_ca_local_artifact_and_secure_handoff() -> None:
    text = _text(INSTALLER)

    assert "--endpoint" in text
    assert "https://" in text
    assert "--ca-file" in text
    assert "openssl verify" in text
    assert "--handoff-file" in text
    assert "--agent-binary" in text
    assert "--dry-run" in text
    assert "install -o root -g root -m 0600" in text
    assert "stat -c %a" in text
    daemon_reload = text.index("systemctl daemon-reload")
    enable = text.index("systemctl enable endpoint-agent.service")
    restart = text.index("systemctl restart endpoint-agent.service")
    assert daemon_reload < enable < restart
    assert "systemctl enable --now endpoint-agent.service" not in text
    assert "mv -f" in text
    assert "curl | sh" not in text
    assert "verify=False" not in text
    assert "wget " not in text
    assert "curl " not in text


def test_installer_validates_existing_service_identity_and_keeps_claim_exchange_out_of_scope() -> None:
    text = _text(INSTALLER)

    assert "validate_existing_service_account" in text
    assert 'getent passwd "$SERVICE_USER"' in text
    assert 'getent group "$SERVICE_GROUP"' in text
    assert '"$account_gid" == "$group_gid"' in text
    assert "is_nonlogin_shell" in text
    assert "existing group without dedicated service account" in text
    assert "curl " not in text
    assert "wget " not in text
    assert "enroll" not in text.lower()


def test_service_runs_as_dedicated_user_with_durable_paths_and_restart() -> None:
    text = _text(SERVICE)

    for required in (
        "User=endpoint-agent",
        "Group=endpoint-agent",
        "ExecStart=/opt/endpoint-agent/endpoint-agent",
        "Restart=on-failure",
        "RestartSec=5s",
        "StateDirectory=endpoint-agent",
        "LogsDirectory=endpoint-agent",
        "LoadCredential=endpoint-agent-config:/etc/endpoint-agent/config.yaml",
        "LoadCredential=endpoint-agent-ca:/etc/endpoint-agent/ca.crt",
        "LoadCredential=endpoint-agent-provisioning-handoff:/etc/endpoint-agent/provisioning-claim",
        "Environment=ENDPOINT_AGENT_PROVISIONING_HANDOFF_FILE=%d/endpoint-agent-provisioning-handoff",
        "ReadWritePaths=/var/lib/endpoint-agent /var/log/endpoint-agent",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
    ):
        assert required in text


def test_permanent_credential_is_runtime_owned_and_finalize_requires_that_contract() -> None:
    installer = _text(INSTALLER)
    runbook = _text(RUNBOOK)

    assert "require_service_secret_file 'permanent credential'" in installer
    assert "owner=$(stat -c %u \"$path\")" in installer
    assert '[[ "$owner" == "$expected_owner" ]]' in installer
    assert "must be owned by $SERVICE_USER:$SERVICE_GROUP" in installer
    assert "root ownership" not in runbook.lower()
    assert "owned by `endpoint-agent`" in runbook


def test_config_and_runbook_preserve_one_time_token_handoff_boundary() -> None:
    config = _text(CONFIG)
    runbook = _text(RUNBOOK)

    assert 'endpoint: "__ENDPOINT_URL__"' in config
    assert "provisioning_handoff_file" in config
    assert "permanent_credential_file" in config
    assert "campaign token" not in config.lower()
    assert "0600" in runbook
    assert "one-time" in runbook
    assert "permanent credential" in runbook
    assert "delete" in runbook
    assert "test-agent-lin" in runbook
