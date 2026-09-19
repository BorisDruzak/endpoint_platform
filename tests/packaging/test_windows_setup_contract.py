"""Contracts for the one-file Windows setup release boundary."""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WINDOWS_PACKAGING = PROJECT_ROOT / "packaging" / "windows"


def test_setup_builder_binds_the_exact_msi_and_public_ca_without_secrets() -> None:
    source = (WINDOWS_PACKAGING / "build-setup.ps1").read_text(encoding="utf-8")

    assert "build-msi.ps1" in source
    assert "[string]$EndpointOrigin" in source
    assert "[string]$EndpointCaFile" in source
    assert "ENDPOINT_SETUP_MSI" in source
    assert "ENDPOINT_SETUP_CA_FILE" in source
    assert "ENDPOINT_SETUP_CONFIG" in source
    assert "EndpointAgentSetup.exe" in source
    assert "setup_sha256" in source
    assert "msi_sha256" in source
    assert "$msiParameters = @{" in source
    assert "build-msi.ps1') @msiParameters" in source
    assert "claim" not in source.lower()
    assert "credential" not in source.lower()


def test_frozen_setup_spec_embeds_only_msi_ca_and_public_configuration() -> None:
    source = (PROJECT_ROOT / "pc_agent" / "pyinstaller_windows_setup.spec").read_text(
        encoding="utf-8"
    )

    assert "ENDPOINT_SETUP_MSI" in source
    assert "ENDPOINT_SETUP_CA_FILE" in source
    assert "ENDPOINT_SETUP_CONFIG" in source
    assert '"EndpointAgent.msi"' in source
    assert '"endpoint-ca.crt"' in source
    assert '"setup-config.json"' in source
    assert "datas=[" in source


def test_setup_entry_installs_embedded_msi_before_using_its_provisioner() -> None:
    source = (PROJECT_ROOT / "pc_agent" / "platform" / "windows" / "setup_entry.py").read_text(
        encoding="utf-8"
    )

    assert "sys._MEIPASS" in source
    assert "EndpointAgent.msi" in source
    assert "msiexec.exe" in source
    assert "endpoint-agent-provision.exe" in source
    assert "setup-config.json" in source
    assert "--endpoint-origin" in source
