"""One-file Windows Setup entrypoint boundaries."""

from __future__ import annotations

import json
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
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: diagnostics_root, raising=False)
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
    result = json.loads((diagnostics_root / "install-result.json").read_text(encoding="utf-8"))
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
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: diagnostics_root, raising=False)
    monkeypatch.setattr(
        setup_entry,
        "_install_embedded_msi",
        lambda _: (_ for _ in ()).throw(RuntimeError("msi error C:/secret/path")),
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_INSTALL_FAILED
    result = json.loads((diagnostics_root / "install-result.json").read_text(encoding="utf-8"))
    assert result["status"] == "INSTALL_FAILED"
    assert result["detail"] == "MSI_INSTALL_FAILED"
    assert "secret" not in (diagnostics_root / "install-result.json").read_text(encoding="utf-8")


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
    msi_path = tmp_path / "EndpointAgent.msi"
    msi_path.write_bytes(b"msi")
    captured: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> SimpleNamespace:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(setup_entry.subprocess, "run", fake_run)
    monkeypatch.setattr(setup_entry, "_windowless_creation_flags", lambda: 4242, raising=False)

    setup_entry._install_embedded_msi(msi_path)

    assert "/qn" in captured["args"][0]
    assert "/passive" not in captured["args"][0]
    assert captured["kwargs"]["creationflags"] == 4242


def test_provisioner_is_started_without_a_console_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A console-capable provisioner must inherit an explicit no-window flag."""
    captured: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> SimpleNamespace:
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(setup_entry, "_windowless_creation_flags", lambda: 4242, raising=False)
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
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: tmp_path / "installer-diagnostics", raising=False)
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


def test_setup_entry_rejects_config_that_contains_extra_material(tmp_path: Path) -> None:
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


def test_setup_state_fails_closed_for_incomplete_enrollment_material(tmp_path: Path) -> None:
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")

    assert setup_entry._classify_installation_state(tmp_path) == "conflicted"


def test_setup_state_marks_valid_identity_without_service_repairable(tmp_path: Path) -> None:
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
        (SetupProvisionError("provisioning failed"), setup_entry.EXIT_PROVISIONING_FAILED),
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
    monkeypatch.setattr(
        setup_entry,
        "_resource_root",
        lambda: pytest.fail("valid rerun must not read embedded payload"),
    )

    assert setup_entry.main(["--quiet"]) == 10


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
