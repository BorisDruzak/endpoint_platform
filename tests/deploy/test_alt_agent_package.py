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


def test_installer_requires_https_ca_verified_bundle_and_secure_handoff() -> None:
    text = _text(INSTALLER)

    assert "--endpoint" in text
    assert "https://" in text
    assert "--ca-file" in text
    assert "openssl verify" in text
    assert "--handoff-file" in text
    assert "--agent-bundle" in text
    assert "--agent-binary" not in text
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


def test_installer_validates_existing_service_identity_and_keeps_claim_exchange_out_of_scope() -> (
    None
):
    text = _text(INSTALLER)

    assert "validate_existing_service_account" in text
    assert 'getent passwd "$SERVICE_USER"' in text
    assert 'getent group "$SERVICE_GROUP"' in text
    assert '"$account_gid" == "$group_gid"' in text
    assert "is_nonlogin_shell" in text
    assert "existing group without dedicated service account" in text
    assert "curl " not in text
    assert "wget " not in text
    assert "/agent/v1/enroll" not in text


def test_service_runs_as_dedicated_user_with_durable_paths_and_restart() -> None:
    text = _text(SERVICE)

    for required in (
        "User=endpoint-agent",
        "Group=endpoint-agent",
        "ExecStart=/opt/endpoint-agent/launcher",
        "Restart=on-failure",
        "RestartSec=5s",
        "StateDirectory=endpoint-agent",
        "LogsDirectory=endpoint-agent",
        "LoadCredential=endpoint-agent-config:/etc/endpoint-agent/config.yaml",
        "LoadCredential=endpoint-agent-ca:/etc/endpoint-agent/ca.crt",
        "LoadCredential=endpoint-enrollment-claim:/etc/endpoint-agent/provisioning-claim",
        "Environment=ENDPOINT_AGENT_PROVISIONING_HANDOFF_FILE=%d/endpoint-enrollment-claim",
        "ReadWritePaths=/var/lib/endpoint-agent /var/log/endpoint-agent",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
    ):
        assert required in text


def test_permanent_credential_is_runtime_owned_and_finalize_requires_that_contract() -> (
    None
):
    installer = _text(INSTALLER)
    runbook = _text(RUNBOOK)

    assert "require_service_secret_file 'permanent credential'" in installer
    assert 'owner=$(file_owner_uid "$path")' in installer
    assert '[[ "$owner" == "$expected_owner" && "$group" == "$expected_group" ]]' in installer
    assert "must be owned by $SERVICE_USER:$SERVICE_GROUP" in installer
    assert "root ownership" not in runbook.lower()
    assert "owned by `endpoint-agent`" in runbook


def test_finalizer_accepts_only_the_fixed_proven_credential_handoff_protocol() -> None:
    installer = _text(INSTALLER)

    for required in (
        'readonly HANDOFF_REQUEST_TARGET="${DATA_ROOT}/claim-removal-request.json"',
        "readonly CLAIM_CREDENTIAL_NAME=endpoint-enrollment-claim",
        "readonly HANDOFF_REQUEST_SCHEMA_VERSION=endpoint_claim_removal_request_v1",
        "require_safe_parent_components",
        "require_opaque_permanent_credential",
        "validate_handoff_request",
        "credential_sha256",
        "require_root_secret_file 'installed provisioning handoff' \"$HANDOFF_TARGET\"",
        'rm -f -- "$HANDOFF_TARGET" "$HANDOFF_REQUEST_TARGET"',
    ):
        assert required in installer


def test_installer_validates_fixed_destinations_before_any_root_write() -> None:
    installer = _text(INSTALLER)

    for required in (
        "validate_install_destinations",
        "validate_fixed_directory_or_absent \"$INSTALL_ROOT\" root 755",
        "validate_fixed_directory_or_absent \"$CONFIG_ROOT\" root 755",
        "validate_fixed_directory_or_absent \"$DATA_ROOT\" service 750",
        "validate_fixed_directory_or_absent \"$LOG_ROOT\" service 750",
        "validate_fixed_regular_target_or_absent \"$CONFIG_TARGET\" root 600",
        "validate_fixed_regular_target_or_absent \"$CA_TARGET\" root 600",
        "validate_fixed_regular_target_or_absent \"$HANDOFF_TARGET\" root 600",
        "validate_fixed_regular_target_or_absent \"$PERMANENT_CREDENTIAL_TARGET\" service 600",
        "validate_fixed_regular_target_or_absent \"$HANDOFF_REQUEST_TARGET\" service 600",
        'validate_fixed_regular_target_or_absent "/etc/systemd/system/$SERVICE_NAME" root 644',
    ):
        assert required in installer

    install_body = installer[installer.index("install_atomically() {") : installer.index("install_package() {")]
    assert install_body.index("validate_install_destinations") < install_body.index(
        "stage=$(mktemp -d /opt/.endpoint-agent-stage.XXXXXX)"
    )


def test_installer_preflights_the_bundle_before_account_creation_and_move() -> None:
    """Catches an unverified bundle reaching useradd or the final selection move."""
    installer = _text(INSTALLER)

    assert 'readonly LAUNCHER_TARGET="${INSTALL_ROOT}/launcher"' in installer
    assert 'readonly VERSIONS_ROOT="${INSTALL_ROOT}/versions"' in installer
    assert 'readonly CURRENT_TARGET="${INSTALL_ROOT}/current.json"' in installer
    assert 'validate_fixed_regular_target_or_absent "$LAUNCHER_TARGET" root 755' in installer
    assert 'validate_fixed_regular_target_or_absent "$CURRENT_TARGET" root 644' in installer

    package_body = installer[
        installer.index("install_package() {") : installer.index("finalize_handoff() {")
    ]
    assert package_body.index("verify_agent_bundle") < package_body.index(
        "ensure_service_account"
    )

    install_body = installer[
        installer.index("install_atomically() {") : installer.index("install_package() {")
    ]
    final_validation = install_body.rindex("validate_install_destinations")
    launcher_move = install_body.index('mv -f "$launcher_stage" "$LAUNCHER_TARGET"')
    assert final_validation < launcher_move


def test_config_and_runbook_preserve_one_time_token_handoff_boundary() -> None:
    config = _text(CONFIG)
    runbook = _text(RUNBOOK)

    assert 'endpoint: "__ENDPOINT_URL__"' in config
    assert 'systemd_claim_credential_name: "endpoint-enrollment-claim"' in config
    assert "permanent_credential_file" in config
    assert "campaign token" not in config.lower()
    assert "0600" in runbook
    assert "one-time" in runbook
    assert "permanent credential" in runbook
    assert "delete" in runbook
    assert "test-agent-lin" in runbook
