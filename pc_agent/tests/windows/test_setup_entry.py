"""One-file Windows Setup entrypoint boundaries."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import setup_entry
from pc_agent.windows_setup import (
    SetupClaimError,
    SetupConfig,
    SetupOutcome,
    SetupProvisionError,
)


def _write_public_payload(root: Path) -> None:
    (root / "EndpointAgent.msi").write_bytes(b"msi")
    (root / "EndpointAgent.release.json").write_text(json.dumps({
        "schema_version": "endpoint_windows_release_v1",
        "version": "1.0.0",
        "source_revision": "a" * 40,
        "product_code": "{11111111-1111-4111-8111-111111111111}",
        "initial_runtime_tree_sha256": "b" * 64,
        "package_sha256": hashlib.sha256(b"msi").hexdigest(),
    }), encoding="utf-8")
    (root / "Install-EndpointAgentCanary.ps1").write_text("# trusted wrapper fixture", encoding="utf-8")
    (root / "endpoint-ca.crt").write_text("public CA", encoding="ascii")
    (root / "setup-config.json").write_text(
        json.dumps(
            {
                "schema_version": "endpoint_windows_setup_config_v1",
                "endpoint_origin": "https://endpoint.sosnadmin.local",
                "installer_version": "1.0.0",
                "installer_release_id": "1.0.0",
            }
        ),
        encoding="utf-8",
    )


def _set_payload_version(root: Path, version: str) -> None:
    config_path = root / "setup-config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["installer_version"] = version
    config_path.write_text(json.dumps(config), encoding="utf-8")
    manifest_path = root / "EndpointAgent.release.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = version
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def test_setup_entry_installs_embedded_msi_before_enrollment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_public_payload(tmp_path)
    order: list[str] = []
    observed_config: list[object] = []

    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "agent-data")
    monkeypatch.setattr(
        setup_entry,
        "_install_embedded_msi",
        lambda path: order.append(path.name),
    )
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())

    class _Setup:
        def __init__(self, config: object, **_: object) -> None:
            observed_config.append(config)
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            order.append("enrollment")
            return SetupOutcome("provisioned")

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main(["--quiet"]) == 0
    assert order == ["EndpointAgent.msi", "enrollment"]
    assert observed_config[0].endpoint_origin == "https://endpoint.sosnadmin.local"


def test_setup_entry_records_started_before_installing_embedded_msi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_public_payload(tmp_path)
    data_root = tmp_path / "agent-data"
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: data_root)

    def assert_started_before_msi(_: Path) -> None:
        contents = (data_root / "install.log").read_text(encoding="utf-8")
        assert "status=STARTED" in contents

    monkeypatch.setattr(setup_entry, "_install_embedded_msi", assert_started_before_msi)
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())

    class _Setup:
        def __init__(self, _config: object, **_: object) -> None:
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            return SetupOutcome("provisioned")

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main(["--quiet"]) == 0


def test_setup_entry_requires_a_running_service_before_reporting_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A provisioner return alone must never become a false completed result."""
    _write_public_payload(tmp_path)
    data_root = tmp_path / "agent-data"
    diagnostics_root = tmp_path / "installer-diagnostics"
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: data_root)
    monkeypatch.setattr(
        setup_entry, "_diagnostics_root", lambda: diagnostics_root, raising=False
    )
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: None)
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())
    monkeypatch.setattr(
        setup_entry,
        "_wait_for_agent_service_running",
        lambda: False,
        raising=False,
    )

    class _Setup:
        def __init__(self, _config: object, **_: object) -> None:
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            return SetupOutcome("provisioned")

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_SERVICE_FAILED
    result = json.loads(
        (diagnostics_root / "install-result.json").read_text(encoding="utf-8")
    )
    assert result["status"] == "SERVICE_FAILED"
    assert result["detail"] == "SERVICE_NOT_RUNNING"
    assert result["stage"] == "SERVICE"


def test_setup_entry_writes_safe_public_result_for_msi_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An MSI error must leave an operator-readable class without raw exception text."""
    _write_public_payload(tmp_path)
    diagnostics_root = tmp_path / "installer-diagnostics"
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "agent-data")
    monkeypatch.setattr(
        setup_entry, "_diagnostics_root", lambda: diagnostics_root, raising=False
    )
    monkeypatch.setattr(
        setup_entry,
        "_install_embedded_msi",
        lambda _: (_ for _ in ()).throw(RuntimeError("msi error C:/secret/path")),
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_INSTALL_FAILED
    result = json.loads(
        (diagnostics_root / "install-result.json").read_text(encoding="utf-8")
    )
    assert result["status"] == "INSTALL_FAILED"
    assert result["detail"] == "MSI_INSTALL_FAILED"
    assert "secret" not in (diagnostics_root / "install-result.json").read_text(
        encoding="utf-8"
    )


def test_result_write_preserves_installer_outcome_when_diagnostics_acl_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A DACL error must not replace the actual, stable installer result code."""
    monkeypatch.setattr(
        setup_entry,
        "_prepare_diagnostics_root",
        lambda: (_ for _ in ()).throw(OSError("diagnostics ACL failed")),
        raising=False,
    )

    assert (
        setup_entry._finish(
            tmp_path,
            status="INSTALL_FAILED",
            code=setup_entry.EXIT_INSTALL_FAILED,
            stage="MSI",
            detail="MSI_INSTALL_FAILED",
        )
        == setup_entry.EXIT_INSTALL_FAILED
    )


def test_embedded_msi_installation_is_silent_and_windowless(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Removing quiet MSI flags or child window suppression would reintroduce UI flashes."""
    _write_public_payload(tmp_path)
    msi_path = tmp_path / "EndpointAgent.msi"
    captured: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> SimpleNamespace:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(setup_entry.subprocess, "run", fake_run)
    monkeypatch.setattr(
        setup_entry, "_windowless_creation_flags", lambda: 4242, raising=False
    )

    setup_entry._install_embedded_msi(msi_path)

    assert "-WindowStyle" in captured["args"][0]
    assert "Hidden" in captured["args"][0]
    assert captured["kwargs"]["creationflags"] == 4242


def test_provisioner_is_started_without_a_console_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A console-capable provisioner must inherit an explicit no-window flag."""
    captured: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> SimpleNamespace:
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        setup_entry, "_windowless_creation_flags", lambda: 4242, raising=False
    )
    setup_entry._run_provisioner(
        tmp_path / "endpoint-agent-provision.exe",
        SetupConfig(
            endpoint_origin="https://endpoint.sosnadmin.local",
            ca_file=tmp_path / "endpoint-ca.crt",
            installer_version="1.0.0",
            installer_release_id="1.0.0",
        ),
        tmp_path / "agent-data",
        "win-test",
        "ic_safe-claim",
        run=fake_run,
    )

    assert captured["kwargs"]["creationflags"] == 4242


def test_normal_installation_displays_a_concrete_success_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A non-quiet successful install must report its verified result to the user."""
    _write_public_payload(tmp_path)
    displayed: list[tuple[str, int, str]] = []
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "agent-data")
    monkeypatch.setattr(
        setup_entry,
        "_diagnostics_root",
        lambda: tmp_path / "installer-diagnostics",
        raising=False,
    )
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: None)
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())
    monkeypatch.setattr(
        setup_entry,
        "_wait_for_agent_service_running",
        lambda: True,
        raising=False,
    )
    monkeypatch.setattr(
        setup_entry,
        "_show_result_dialog",
        lambda status, code, detail: displayed.append((status, code, detail)),
        raising=False,
    )

    class _Setup:
        def __init__(self, _config: object, **_: object) -> None:
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            return SetupOutcome("provisioned")

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main([]) == setup_entry.EXIT_SUCCESS
    assert displayed == [("COMPLETED", 0, "SERVICE_RUNNING")]


def test_successful_interactive_update_restarts_both_user_companions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An interactive update restores both companions stopped by the MSI."""
    (tmp_path / "enrollment-identity.json").write_text(
        '{"device_id":"550e8400-e29b-41d4-a716-446655440000","schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="ascii",
    )
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")
    resources = tmp_path / "payload"
    resources.mkdir()
    _write_public_payload(resources)
    _set_payload_version(resources, "3.2.56")
    started: list[object] = []

    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: resources)
    monkeypatch.setattr(setup_entry, "_installed_msi_version", lambda: "3.2.55")
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _path: None)
    monkeypatch.setattr(setup_entry, "_wait_for_agent_service_running", lambda: True)
    monkeypatch.setattr(setup_entry, "_is_interactive_windows_session", lambda: True)
    monkeypatch.setattr(
        setup_entry, "_restart_tray_companion", lambda: started.append("tray") or True
    )
    monkeypatch.setattr(
        setup_entry, "_restart_user_sensor_companion", lambda: started.append("sensor") or True
    )

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_SUCCESS
    assert started == ["tray", "sensor"]


def test_interactive_update_reports_user_sensor_start_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(setup_entry, "_is_interactive_windows_session", lambda: True)
    monkeypatch.setattr(setup_entry, "_restart_tray_companion", lambda: True)
    monkeypatch.setattr(setup_entry, "_restart_user_sensor_companion", lambda: False)

    assert setup_entry._service_ready_detail() == "SERVICE_RUNNING_USER_SENSOR_START_FAILED"


def test_successful_system_update_does_not_start_an_invisible_tray(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """SYSTEM/session-0 updates leave tray launch to the interactive user session."""
    monkeypatch.setattr(setup_entry.os, "name", "nt")
    monkeypatch.setenv("SESSIONNAME", "Services")
    monkeypatch.setenv("USERNAME", "SYSTEM")
    monkeypatch.setattr(
        setup_entry,
        "_installed_tray_companion",
        lambda: tmp_path / "EndpointAgentTray.exe",
    )
    monkeypatch.setattr(
        setup_entry.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("session-0 must not start a tray UI"),
    )

    assert setup_entry._restart_tray_companion() is False
    assert setup_entry._restart_user_sensor_companion() is False


def test_interactive_session_detection_uses_windows_session_id_when_env_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A normal desktop launch does not require terminal-only SESSIONNAME."""
    monkeypatch.setattr(setup_entry.os, "name", "nt")
    monkeypatch.delenv("SESSIONNAME", raising=False)
    monkeypatch.setenv("USERNAME", "operator")
    monkeypatch.setattr(setup_entry, "_current_process_session_id", lambda: 1)

    assert setup_entry._is_interactive_windows_session() is True


def test_session_zero_never_starts_the_tray_when_env_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A SYSTEM-like session remains non-interactive even without its env label."""
    monkeypatch.setattr(setup_entry.os, "name", "nt")
    monkeypatch.delenv("SESSIONNAME", raising=False)
    monkeypatch.setenv("USERNAME", "operator")
    monkeypatch.setattr(setup_entry, "_current_process_session_id", lambda: 0)

    assert setup_entry._is_interactive_windows_session() is False


def test_setup_entry_rejects_config_that_contains_extra_material(
    tmp_path: Path,
) -> None:
    _write_public_payload(tmp_path)
    (tmp_path / "setup-config.json").write_text(
        json.dumps(
            {
                "schema_version": "endpoint_windows_setup_config_v1",
                "endpoint_origin": "https://endpoint.sosnadmin.local",
                "installer_version": "1.0.0",
                "installer_release_id": "1.0.0",
                "unexpected": "not allowed",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="configuration is invalid"):
        setup_entry._read_public_setup_config(tmp_path / "setup-config.json")


def test_setup_state_classifies_a_valid_identity_and_credential(tmp_path: Path) -> None:
    identity = tmp_path / "enrollment-identity.json"
    credential = tmp_path / "device-credential"
    identity.write_text(
        '{"device_id":"550e8400-e29b-41d4-a716-446655440000","schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="ascii",
    )
    credential.write_text("a" * 43, encoding="ascii")

    assert setup_entry._classify_installation_state(tmp_path) == "valid"


def test_setup_state_fails_closed_for_incomplete_enrollment_material(
    tmp_path: Path,
) -> None:
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")

    assert setup_entry._classify_installation_state(tmp_path) == "conflicted"


def test_setup_state_marks_valid_identity_without_service_repairable(
    tmp_path: Path,
) -> None:
    (tmp_path / "enrollment-identity.json").write_text(
        '{"device_id":"550e8400-e29b-41d4-a716-446655440000","schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="ascii",
    )
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")

    assert (
        setup_entry._classify_installation_state(tmp_path, service_installed=False)
        == "repairable"
    )


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (SetupOutcome("denied", reason="POLICY_DENIED"), 30),
        (SetupOutcome("timed_out", reason="WAITING_APPROVAL"), 31),
        (SetupOutcome("review_required", reason="DUPLICATE_IDENTITY"), 32),
        (SetupOutcome("expired", reason="REQUEST_EXPIRED"), 33),
    ],
)
def test_setup_entry_maps_terminal_request_outcomes_to_stable_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    outcome: SetupOutcome,
    expected: int,
) -> None:
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "agent-data")
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: None)
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())

    class _Setup:
        def __init__(self, _config: object, **_: object) -> None:
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            return outcome

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main(["--quiet"]) == expected


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (SetupClaimError("claim handoff failed"), setup_entry.EXIT_CLAIM_FAILED),
        (
            SetupProvisionError("provisioning failed"),
            setup_entry.EXIT_PROVISIONING_FAILED,
        ),
    ],
)
def test_setup_entry_distinguishes_claim_and_provisioning_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    error: RuntimeError,
    expected: int,
) -> None:
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "agent-data")
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: None)
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())

    class _Setup:
        def __init__(self, _config: object, **_: object) -> None:
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            raise error

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main(["--quiet"]) == expected


def test_setup_entry_logs_safe_provisioner_failure_detail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_public_payload(tmp_path)
    data_root = tmp_path / "agent-data"
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: data_root)
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: None)
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())

    class _Setup:
        def __init__(self, _config: object, **_: object) -> None:
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            raise SetupProvisionError(
                "Windows provisioning failed", detail="PROVISIONER_WINDOWSACLERROR"
            )

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_PROVISIONING_FAILED
    assert "detail=PROVISIONER_WINDOWSACLERROR" in (
        data_root / "install.log"
    ).read_text(encoding="utf-8")


def test_provisioner_failure_maps_only_its_safe_class_name(
    tmp_path: Path,
) -> None:
    with pytest.raises(SetupProvisionError) as raised:
        setup_entry._run_provisioner(
            tmp_path / "endpoint-agent-provision.exe",
            SetupConfig(
                endpoint_origin="https://endpoint.sosnadmin.local",
                ca_file=tmp_path / "endpoint-ca.crt",
                installer_version="1.0.0",
                installer_release_id="1.0.0",
            ),
            tmp_path / "agent-data",
            "win-test",
            "ic_safe-claim",
            run=lambda *_args, **_kwargs: SimpleNamespace(
                returncode=1,
                stdout="",
                stderr="Windows provisioning failed: WindowsAclError\nC:/secret/path\n",
            ),
        )

    assert raised.value.detail == "PROVISIONER_WINDOWSACLERROR"
    assert "secret" not in raised.value.detail


def test_provisioner_start_failure_is_logged_without_os_error_text(
    tmp_path: Path,
) -> None:
    def fail_to_start(*_args: object, **_kwargs: object) -> object:
        raise OSError("C:/secret/path")

    with pytest.raises(SetupProvisionError) as raised:
        setup_entry._run_provisioner(
            tmp_path / "endpoint-agent-provision.exe",
            SetupConfig(
                endpoint_origin="https://endpoint.sosnadmin.local",
                ca_file=tmp_path / "endpoint-ca.crt",
                installer_version="1.0.0",
                installer_release_id="1.0.0",
            ),
            tmp_path / "agent-data",
            "win-test",
            "ic_safe-claim",
            run=fail_to_start,
        )

    assert raised.value.detail == "PROVISIONER_START_FAILED"
    assert "secret" not in raised.value.detail


def test_install_log_never_persists_secret_detail(tmp_path: Path) -> None:
    log_path = tmp_path / "install.log"
    setup_entry._write_install_log(
        log_path,
        step="ENROLLMENT",
        status="DENIED",
        code=30,
        detail="POLICY_DENIED",
    )

    contents = log_path.read_text(encoding="utf-8")
    assert "POLICY_DENIED" in contents
    assert "ic_" not in contents
    assert "device_token" not in contents


def test_valid_rerun_stops_before_msi_or_enrollment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "enrollment-identity.json").write_text(
        '{"device_id":"550e8400-e29b-41d4-a716-446655440000","schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="ascii",
    )
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path)
    resources = tmp_path / "payload"
    resources.mkdir()
    _write_public_payload(resources)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: resources)
    monkeypatch.setattr(setup_entry, "_installed_msi_version", lambda: "1.0.0")
    monkeypatch.setattr(
        setup_entry,
        "_install_embedded_msi",
        lambda _path: pytest.fail("equal installer must not invoke MSI"),
    )

    assert setup_entry.main(["--quiet"]) == 10


def test_valid_existing_agent_installs_a_strictly_newer_embedded_msi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Removing the valid-state upgrade branch would strand deployed agents."""
    (tmp_path / "enrollment-identity.json").write_text(
        '{"device_id":"550e8400-e29b-41d4-a716-446655440000","schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="ascii",
    )
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")
    resources = tmp_path / "payload"
    resources.mkdir()
    _write_public_payload(resources)
    _set_payload_version(resources, "3.2.49")
    calls: list[str] = []
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: resources)
    monkeypatch.setattr(
        setup_entry, "_installed_msi_version", lambda: "3.2.47", raising=False
    )
    monkeypatch.setattr(
        setup_entry, "_install_embedded_msi", lambda path: calls.append(path.name)
    )
    monkeypatch.setattr(setup_entry, "_wait_for_agent_service_running", lambda: True)
    monkeypatch.setattr(
        setup_entry,
        "UniversalWindowsSetup",
        lambda *_args, **_kwargs: pytest.fail("an update must not re-enroll"),
    )

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_SUCCESS
    assert calls == ["EndpointAgent.msi"]


def test_valid_existing_agent_stops_tray_before_invoking_a_newer_msi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The Setup payload is newer than the MSI-installed helper during an upgrade."""
    (tmp_path / "enrollment-identity.json").write_text(
        '{"device_id":"550e8400-e29b-41d4-a716-446655440000","schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="ascii",
    )
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")
    resources = tmp_path / "payload"
    resources.mkdir()
    _write_public_payload(resources)
    _set_payload_version(resources, "3.2.62")
    order: list[str] = []
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: resources)
    monkeypatch.setattr(setup_entry, "_installed_msi_version", lambda: "3.2.59")
    monkeypatch.setattr(setup_entry, "_stop_tray_before_msi_update", lambda: order.append("tray"))
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: order.append("msi"))
    monkeypatch.setattr(setup_entry, "_wait_for_agent_service_running", lambda: True)

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_SUCCESS
    assert order == ["tray", "msi"]


def test_valid_existing_agent_does_not_install_an_equal_embedded_msi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An equal package is an idempotent rerun, never an MSI churn event."""
    (tmp_path / "enrollment-identity.json").write_text(
        '{"device_id":"550e8400-e29b-41d4-a716-446655440000","schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="ascii",
    )
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")
    resources = tmp_path / "payload"
    resources.mkdir()
    _write_public_payload(resources)
    calls: list[str] = []
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: resources)
    monkeypatch.setattr(
        setup_entry, "_installed_msi_version", lambda: "1.0.0", raising=False
    )
    monkeypatch.setattr(
        setup_entry, "_install_embedded_msi", lambda _path: calls.append("msi")
    )

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_ALREADY_INSTALLED
    assert calls == []


def test_conflicted_rerun_stops_before_msi_or_enrollment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path)
    monkeypatch.setattr(
        setup_entry,
        "_resource_root",
        lambda: pytest.fail("conflicted rerun must not read embedded payload"),
    )

    assert setup_entry.main(["--quiet"]) == 60
