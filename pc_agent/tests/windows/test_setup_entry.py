"""One-file Windows Setup entrypoint boundaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pc_agent.platform.windows import setup_entry
from pc_agent.windows_setup import SetupClaimError, SetupOutcome, SetupProvisionError


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
