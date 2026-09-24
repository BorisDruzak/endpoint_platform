"""Universal Setup must install only its matching, provenance-capable MSI."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import setup_entry


def _payload(root: Path) -> Path:
    msi = root / "EndpointAgent.msi"
    msi.write_bytes(b"signed msi fixture")
    (root / "endpoint-ca.crt").write_text("public CA", encoding="ascii")
    (root / "setup-config.json").write_text(json.dumps({
        "schema_version": "endpoint_windows_setup_config_v1",
        "endpoint_origin": "https://endpoint.sosnadmin.local",
        "installer_version": "3.2.65",
        "installer_release_id": "3.2.65",
    }), encoding="utf-8")
    (root / "EndpointAgent.release.json").write_text(json.dumps({
        "schema_version": "endpoint_windows_release_v1",
        "version": "3.2.65",
        "source_revision": "a" * 40,
        "product_code": "{11111111-1111-4111-8111-111111111111}",
        "initial_runtime_tree_sha256": "b" * 64,
        "package_sha256": hashlib.sha256(msi.read_bytes()).hexdigest(),
    }), encoding="utf-8")
    (root / "Install-EndpointAgentCanary.ps1").write_text("# trusted wrapper fixture", encoding="utf-8")
    return msi


def test_embedded_msi_install_uses_provenance_wrapper(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    msi = _payload(tmp_path)
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(command)
        assert kwargs["shell"] is False
        assert kwargs["stdin"] is setup_entry.subprocess.DEVNULL
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(setup_entry.subprocess, "run", run)
    setup_entry._install_embedded_msi(msi)

    assert len(calls) == 1
    assert calls[0][-4:] == [
        "-MsiPath", str(msi), "-ReleaseManifest", str(tmp_path / "EndpointAgent.release.json"),
    ]
    assert str(tmp_path / "Install-EndpointAgentCanary.ps1") in calls[0]
    assert "msiexec.exe" not in calls[0]


@pytest.mark.parametrize("defect", ["missing_manifest", "msi_hash", "version", "product_code"])
def test_embedded_msi_rejects_invalid_release_evidence_before_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, defect: str,
) -> None:
    msi = _payload(tmp_path)
    manifest_path = tmp_path / "EndpointAgent.release.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if defect == "missing_manifest":
        manifest_path.unlink()
    else:
        if defect == "msi_hash":
            manifest["package_sha256"] = "0" * 64
        elif defect == "version":
            manifest["version"] = "3.2.64"
        else:
            manifest["product_code"] = "wrong-product-code"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(setup_entry.subprocess, "run", lambda *_a, **_k: pytest.fail("installer started"))
    with pytest.raises(setup_entry.SetupInstallError):
        setup_entry._install_embedded_msi(msi)


def test_embedded_msi_wrapper_failure_cannot_report_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    msi = _payload(tmp_path)
    monkeypatch.setattr(
        setup_entry.subprocess, "run", lambda *_a, **_k: SimpleNamespace(returncode=1),
    )

    with pytest.raises(setup_entry.SetupInstallError, match="Windows Setup MSI installation failed") as caught:
        setup_entry._install_embedded_msi(msi)
    assert caught.value.detail == "MSI_EVIDENCE_FAILED"


def test_setup_upgrade_does_not_report_updated_when_provenance_wrapper_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    payload = tmp_path / "payload"
    payload.mkdir()
    _payload(payload)
    diagnostics = tmp_path / "diagnostics"
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: payload)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "agent-data")
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: diagnostics)
    monkeypatch.setattr(setup_entry, "_classify_installation_state", lambda *_a, **_k: "valid")
    monkeypatch.setattr(setup_entry, "_installed_msi_version", lambda: "3.2.64")
    monkeypatch.setattr(setup_entry, "_stop_tray_before_msi_update", lambda: None)
    monkeypatch.setattr(
        setup_entry.subprocess, "run", lambda *_a, **_k: SimpleNamespace(returncode=1),
    )

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_INSTALL_FAILED
    result = json.loads((diagnostics / "install-result.json").read_text(encoding="utf-8"))
    assert result["status"] == "INSTALL_FAILED"
    assert result["detail"] == "MSI_EVIDENCE_FAILED"


@pytest.mark.parametrize("msi_version", ["3.2.64", None])
def test_newer_zip_selector_does_not_hide_older_or_unproven_installed_msi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, msi_version: str | None,
) -> None:
    payload = tmp_path / "payload"
    payload.mkdir()
    _payload(payload)
    program_files = tmp_path / "Program Files"
    selector = program_files / "Endpoint Platform" / "Agent" / "current.json"
    selector.parent.mkdir(parents=True)
    selector.write_text(json.dumps({"version": "3.2.66"}), encoding="utf-8")
    monkeypatch.setenv("ProgramW6432", str(program_files))
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: payload)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "agent-data")
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: tmp_path / "diagnostics")
    monkeypatch.setattr(setup_entry, "_classify_installation_state", lambda *_a, **_k: "valid")
    monkeypatch.setattr(setup_entry, "_agent_service_installed", lambda: True)
    monkeypatch.setattr(setup_entry, "_installed_msi_version", lambda: msi_version)
    monkeypatch.setattr(setup_entry, "_stop_tray_before_msi_update", lambda: None)
    monkeypatch.setattr(setup_entry, "_wait_for_agent_service_running", lambda: True)
    monkeypatch.setattr(setup_entry, "_service_ready_detail", lambda: "SERVICE_RUNNING")
    commands: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        commands.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(setup_entry.subprocess, "run", run)

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_SUCCESS
    assert len(commands) == 1
    assert str(payload / "Install-EndpointAgentCanary.ps1") in commands[0]
    assert json.loads(selector.read_text(encoding="utf-8"))["version"] == "3.2.66"


@pytest.mark.parametrize("defect", [None, "cache_hash", "product_version", "cache_path"])
def test_installed_msi_version_requires_matching_protected_provenance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, defect: str | None,
) -> None:
    package_bytes = b"verified installed MSI"
    package_hash = hashlib.sha256(package_bytes).hexdigest()
    cache_root = tmp_path / "installer-cache"
    cache_path = cache_root / f"msi-{package_hash}" / "EndpointAgent.msi"
    cache_path.parent.mkdir(parents=True)
    cache_path.write_bytes(b"tampered" if defect == "cache_hash" else package_bytes)
    provenance = {
        "schema_version": "endpoint_windows_installer_provenance_v1",
        "release_manifest_schema_version": "endpoint_windows_release_v1",
        "version": "3.2.64", "product_code": "{11111111-1111-4111-8111-111111111111}",
        "source_revision": "a" * 40, "initial_runtime_tree_sha256": "b" * 64,
        "package_sha256": package_hash,
        "cache_file": f"msi-{package_hash}/EndpointAgent.msi",
    }
    if defect == "cache_path":
        provenance["cache_file"] = "../untrusted.msi"
    (cache_root / "installer-provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
    checked: list[Path] = []

    class Acl:
        def assert_protected_file(self, path: Path) -> None:
            checked.append(path)

    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "PyWin32AclAdapter", Acl)
    monkeypatch.setattr(
        setup_entry, "_installed_product_version",
        lambda _code: "3.2.63" if defect == "product_version" else "3.2.64",
    )

    assert setup_entry._installed_msi_version() == ("3.2.64" if defect is None else None)
    if defect is None:
        assert checked == [cache_root / "installer-provenance.json", cache_path]


def test_equal_setup_rerun_rejects_tampered_embedded_msi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    payload = tmp_path / "payload"
    payload.mkdir()
    msi = _payload(payload)
    msi.write_bytes(b"tampered MSI")
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: payload)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "agent-data")
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: tmp_path / "diagnostics")
    monkeypatch.setattr(setup_entry, "_classify_installation_state", lambda *_a, **_k: "valid")
    monkeypatch.setattr(setup_entry, "_agent_service_installed", lambda: True)
    monkeypatch.setattr(setup_entry, "_installed_msi_version", lambda: "3.2.65")
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda *_a: pytest.fail("tampered MSI installed"))

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_PREFLIGHT_FAILED
