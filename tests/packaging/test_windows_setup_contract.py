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
    assert "source_commit" in source
    assert "filename" in source
    assert "agent_version" in source
    assert "authenticode_status" in source
    assert "authenticode_publisher" in source
    assert "CodeSigningCertificateThumbprint" in source
    assert "Set-AuthenticodeSignature" in source
    assert "Get-AuthenticodeSignature" in source
    assert "Set-SetupAuthenticodeSignature -Path $msiPath" in source
    assert "Set-SetupAuthenticodeSignature -Path $releaseSetup" in source
    assert "$releaseMsi = Join-Path $releaseRoot \"EndpointAgent-$Version-x64.msi\"" in source
    assert "Copy-Item -LiteralPath $msiPath -Destination $releaseMsi -Force" in source
    assert "$msiSignature = Get-AuthenticodeSignature -FilePath $releaseMsi" in source
    assert "$msiSha256 = (Get-FileHash -LiteralPath $releaseMsi -Algorithm SHA256)" in source
    assert "$releaseMsiManifest.package_sha256 = $releaseMsiSha256" in source
    assert "$verified = Get-AuthenticodeSignature -FilePath $Path" in source
    assert "Authenticode timestamp failed." in source
    assert "msi_authenticode_status" in source
    assert "msi_authenticode_publisher" in source
    assert "[string]$ExistingMsi" in source
    assert "[string]$ExistingMsiReleaseManifest" in source
    assert "Existing MSI and release manifest must be supplied together." in source
    assert "Existing MSI SHA-256 does not match its release manifest." in source
    assert "msi_source_commit" in source
    assert "$verifiedExistingMsi = Resolve-VerifiedExistingMsi" in source
    assert "Assert-SecretFreeSetupArtifact" in source
    assert "$msiParameters = @{" in source
    assert "build-msi.ps1') @msiParameters" in source
    assert "[switch]$ReusePythonBuild" in source
    assert "$msiParameters.ReusePythonBuild = $true" in source
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


def test_frozen_setup_spec_requires_elevation_for_machine_provisioning() -> None:
    """The installer and its provisioner must share one elevated Windows token."""
    source = (PROJECT_ROOT / "pc_agent" / "pyinstaller_windows_setup.spec").read_text(
        encoding="utf-8"
    )

    assert "uac_admin=True" in source
    assert "console=False" in source


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


def test_runbook_documents_campaign_authority_and_safe_quiet_mode() -> None:
    source = (PROJECT_ROOT / "docs" / "runbooks" / "WINDOWS_UNIVERSAL_ENROLLMENT.md").read_text(
        encoding="utf-8"
    )

    assert "enrollment_mode" in source
    assert "allowed_installer_releases" in source
    assert "campaign_id" in source
    assert "--quiet" in source
    assert "fleet rollout" in source
    assert "ic_" in source
