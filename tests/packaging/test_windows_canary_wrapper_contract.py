"""Release-boundary contract for the strict Windows canary installer wrapper."""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WINDOWS_PACKAGING = PROJECT_ROOT / "packaging" / "windows"
BUILD_SCRIPT = WINDOWS_PACKAGING / "build-msi.ps1"
WRAPPER = WINDOWS_PACKAGING / "Install-EndpointAgentCanary.ps1"


def test_builder_generates_detached_manifest_only_after_final_msi_exists() -> None:
    """Writing the package hash before WiX output would create circular or stale provenance."""
    source = BUILD_SCRIPT.read_text(encoding="utf-8")

    wix_build = "Invoke-Checked $wixCommand.Source $wixArguments $repositoryRoot"
    release_manifest = "EndpointAgent-$Version-x64.release.json"
    final_hash = "Get-FileHash -LiteralPath $msiPath -Algorithm SHA256"

    assert wix_build in source
    assert release_manifest in source
    assert final_hash in source
    assert source.index(wix_build) < source.index(final_hash)
    assert source.index(final_hash) < source.index(release_manifest)


def test_wrapper_accepts_only_detached_release_inputs_and_fixed_cache_paths() -> None:
    """Caller-controlled cache locations or enrollment material would break canary provenance."""
    source = WRAPPER.read_text(encoding="utf-8")
    lowered = source.casefold()

    assert source.count("[Parameter(Mandatory = $true)]") >= 2
    assert "[string]$MsiPath" in source
    assert "[string]$ReleaseManifest" in source
    assert "installer-cache" in source
    assert "installer-provenance.json" in source
    assert "Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256" in source
    assert "msiexec.exe" in source
    assert all(word not in lowered for word in ("claim", "token", "credential", "password"))


def test_wrapper_verifies_cache_hash_and_machine_protection_after_install() -> None:
    """An unchecked cached MSI or ordinary-user-readable evidence cannot satisfy strict preflight."""
    source = WRAPPER.read_text(encoding="utf-8")

    assert "Assert-ProgramDataProtection" in source
    assert "Assert-RegularNonReparseFile" in source
    assert "MSI cache SHA-256 does not match release manifest" in source
    assert "MSI installation failed" in source
