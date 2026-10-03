"""Release-boundary contract for the strict Windows canary installer wrapper."""

from __future__ import annotations

from pathlib import Path
import ast
import re


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WINDOWS_PACKAGING = PROJECT_ROOT / "packaging" / "windows"
BUILD_SCRIPT = WINDOWS_PACKAGING / "build-msi.ps1"
WRAPPER = WINDOWS_PACKAGING / "Install-EndpointAgentCanary.ps1"


def _python_function(relative: str, name: str) -> str:
    source = (PROJECT_ROOT / relative).read_text(encoding="utf-8")
    node = next(
        item
        for item in ast.parse(source).body
        if isinstance(item, ast.FunctionDef) and item.name == name
    )
    return ast.get_source_segment(source, node)


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

    assert source.count("[Parameter(Mandatory = $true)]") >= 2
    assert "[string]$MsiPath" in source
    assert "[string]$ReleaseManifest" in source
    assert "installer-cache" in source
    assert "installer-state" in source
    assert "Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256" in source
    assert "msiexec.exe" in source
    # Native authenticated bridge tokens are expected; enrollment/bearer inputs
    # and their output are forbidden at this detached-package boundary.
    header = source[: source.index("$ErrorActionPreference")]
    assert set(re.findall(r"\[string\]\$(\w+)", header)) == {
        "MsiPath",
        "ReleaseManifest",
        "Operation",
    }
    assert not re.search(
        r"\$(?:claim|password|deviceCredential|enrollmentToken)\b", source, re.I
    )
    assert not re.search(
        r"Write-(?:Output|Host|Verbose|Debug|Warning|Error).*\$(?:bridge\.Token|claim|password|deviceCredential)",
        source,
        re.I,
    )


def test_wrapper_verifies_cache_hash_and_machine_protection_after_install() -> None:
    """Unchecked cache bytes or mutable machine authority cannot satisfy acceptance."""
    source = WRAPPER.read_text(encoding="utf-8")

    assert "Assert-InstalledDataProtection" in source
    assert "Assert-RegularNonReparseFile" in source
    assert "MSI cache SHA-256 does not match release manifest" in source
    assert (
        "$Process.ExitCode -notin @(0,3010,1641) -or -not $Bridge.Policy.NativeComplete -or -not $Bridge.Policy.AllHelpersComplete"
        in source
    )
    assert "Assert-CacheArtifactProtection -Path $executionCachePath" in source
    finish = (
        PROJECT_ROOT / "pc_agent/platform/windows/installer_transaction_bridge.py"
    ).read_text(encoding="utf-8")
    finish = finish[finish.index("elif phase=='finish':") :]
    assert finish.index(
        "verified_foundation_bytes(expected,paths.install_root)"
    ) < finish.index("archive/'completed.json'")


def test_wrapper_checks_installed_product_before_publishing_provenance() -> None:
    source = WRAPPER.read_text(encoding="utf-8")

    install = source.index("$installer = [Diagnostics.Process]::Start($nativeInfo)")
    reconcile = source.index(
        "Invoke-InstallerHelper -Bridge $bridge -Phase 'reconcile'"
    )
    finish = source.index("Invoke-InstallerHelper -Bridge $bridge -Phase 'finish'")
    assert install < reconcile < finish
    implementation = _python_function(
        "pc_agent/platform/windows/installation_provenance.py",
        "reconcile_installed_core",
    )
    assert implementation.index(
        "msi_inventory.verify_installed(expected.package"
    ) < implementation.index("owners / f'{expected.identity.version}.json'")
    assert implementation.index("verify_payload(candidate_root") < implementation.index(
        "owners / f'{expected.identity.version}.json'"
    )


def test_wrapper_stages_provenance_before_atomic_publication() -> None:
    source = WRAPPER.read_text(encoding="utf-8")

    publication = _python_function(
        "pc_agent/platform/windows/installation_provenance.py",
        "reconcile_installed_core",
    )
    assert "durable_state.write_json_atomic(owners /" in publication
    assert "trusted_root=owners, max_bytes=4096, protect=protect_state" in publication
    write = _python_function(
        "pc_agent/platform/windows/durable_state.py", "write_bytes_atomic"
    )
    assert (
        write.index("protect(temporary)")
        < write.index("os.write(descriptor")
        < write.index("os.fsync(descriptor)")
        < write.index("os.replace(temporary, destination)")
        < write.index("flush_directory(destination.parent)")
    )
    assert source.index("-Phase 'finish' | Out-Null") < source.index(
        "Start-ManagedEndpointAgent",
        source.index("$installer = [Diagnostics.Process]::Start"),
    )


def test_wrapper_protects_a_hash_addressed_cache_before_privileged_execution() -> None:
    """A user-controlled ProgramData cache must never reach msiexec as an admin."""
    source = WRAPPER.read_text(encoding="utf-8")

    assert "S-1-5-18" in source
    assert "S-1-5-32-544" in source
    assert "Assert-InstallerCacheProtection" in source
    assert "msi-$($manifest.package_sha256)" in source
    assert source.index(
        "Assert-InstallerCacheProtection -Path $executionCacheRoot"
    ) < source.index("Copy-Item -LiteralPath $MsiPath")
    install = source.index("$installer = [Diagnostics.Process]::Start($nativeInfo)")
    assert (
        source[:install].rindex(
            "Assert-InstallerCacheProtection -Path $executionCacheRoot"
        )
        < install
    )
    assert (
        source.index("$packagePin = [IO.File]::Open($executionCachePath")
        < source.index("-Phase 'inspect'")
        < source.index("$bridge.Policy.MarkQuiescent()")
        < install
    )


def test_wrapper_stops_only_fixed_agent_services_and_restores_core_agent() -> None:
    """An in-use binary must not stall MSI, nor leave the prior agent stopped on failure."""
    source = WRAPPER.read_text(encoding="utf-8")

    assert "$ManagedServiceNames = @('EndpointAgent', 'EndpointAgentUpdater')" in source
    assert "function Stop-ManagedAgentServices" in source
    assert "function Start-ManagedEndpointAgent" in source
    assert "Stop-ManagedAgentServices" in source
    assert "Start-ManagedEndpointAgent" in source
    assert "finally" in source
    install = source.index("$installer = [Diagnostics.Process]::Start($nativeInfo)")
    assert (
        source.index("Stop-ManagedAgentServices -PreviousStates $previousServiceStates")
        < install
    )
    assert source.index("Start-ManagedEndpointAgent", install) > install
    assert (
        "$PreviousStates[$serviceName] -ne 'Running' -or -not $StoppedBySetup.ContainsKey($serviceName)"
        in source
    )
    assert "-not $nativeStarted -and $null -eq $interruptedFence" in source
    assert "-Phase 'verify-settled'" in source


def test_wrapper_starts_only_the_fixed_windows_installer_service_before_msi() -> None:
    """The canary must not depend on demand-start behavior that this VM does not provide."""
    source = WRAPPER.read_text(encoding="utf-8")

    assert "$WindowsInstallerServiceName = 'msiserver'" in source
    assert "function Start-WindowsInstaller" in source
    install = source.index("$installer = [Diagnostics.Process]::Start($nativeInfo)")
    assert (
        source.index("Start-WindowsInstaller", source.index("$previousServiceStates"))
        < install
    )


def test_wrapper_quotes_the_protected_msi_path_for_windows_installer() -> None:
    """Program Files is part of the fixed execution cache, so msiexec needs quotes."""
    source = WRAPPER.read_text(encoding="utf-8")

    assert "@('/i', ('\"{0}\"' -f $executionCachePath), '/qn', '/norestart'" in source
    assert (
        "::StartInfo($msiPath, [string]::Join(' ', $msiArguments), $bridge.LaunchDirectory)"
        in source
    )
