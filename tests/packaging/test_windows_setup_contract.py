"""Contracts for the one-file Windows setup release boundary."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WINDOWS_PACKAGING = PROJECT_ROOT / "packaging" / "windows"


def _run_setup_functions(names: list[str], body: str) -> dict[str, object]:
    """Run only named real builder functions; replace external signing operations."""
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is unavailable")
    source = json.dumps(str(WINDOWS_PACKAGING / "build-setup.ps1"))
    wanted = ", ".join(json.dumps(name) for name in names)
    script = f"""
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile({source}, [ref]$tokens, [ref]$errors)
if ($errors.Count) {{ throw 'Builder has PowerShell parse errors.' }}
$wanted = @({wanted})
$found = @($ast.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $wanted }}, $true))
if ($found.Count -ne $wanted.Count) {{ throw 'Expected builder function is missing.' }}
foreach ($definition in $found) {{ . ([scriptblock]::Create($definition.Extent.Text)) }}
{body}
"""
    result = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", "-"],
        input=script, text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("thumbprint,timestamp,expected_error", [
    ("A" * 40, "", "timestamp"),
    ("", "http://timestamp.digicert.com", "together"),
    ("A" * 40, "https://timestamp.digicert.com", "HTTP"),
    ("A" * 40, "not-a-url", "HTTP"),
    ("A" * 40, "http://user:pass@timestamp.digicert.com", "HTTP"),
    ("A" * 40, "http://timestamp.digicert.com/#fragment", "HTTP"),
])
def test_setup_signing_rejects_invalid_inputs_before_certificate_lookup(
    thumbprint: str, timestamp: str, expected_error: str,
) -> None:
    body = f"""
$script:lookups = 0; $script:signs = 0
function Get-ChildItem {{ $script:lookups++ }}
function Set-AuthenticodeSignature {{ $script:signs++ }}
try {{ Set-SetupAuthenticodeSignature -Path 'fixture.msi' -Thumbprint {json.dumps(thumbprint)} -Timestamp {json.dumps(timestamp)}; $errorText = '' }}
catch {{ $errorText = $_.Exception.Message }}
@{{ error = $errorText; lookups = $script:lookups; signs = $script:signs }} | ConvertTo-Json -Compress
"""
    result = _run_setup_functions(["Assert-SetupSigningInputs", "Set-SetupAuthenticodeSignature"], body)
    assert expected_error.lower() in str(result["error"]).lower()
    assert result["lookups"] == 0
    assert result["signs"] == 0


def test_setup_unsigned_test_mode_skips_certificate_and_signing() -> None:
    body = """
$script:lookups = 0; $script:signs = 0
function Get-ChildItem { $script:lookups++ }
function Set-AuthenticodeSignature { $script:signs++ }
Set-SetupAuthenticodeSignature -Path 'fixture.msi' -Thumbprint '' -Timestamp ''
@{ lookups = $script:lookups; signs = $script:signs } | ConvertTo-Json -Compress
"""
    result = _run_setup_functions(["Assert-SetupSigningInputs", "Set-SetupAuthenticodeSignature"], body)
    assert result == {"lookups": 0, "signs": 0}


@pytest.mark.parametrize("status,has_timestamp,should_pass", [
    ("Valid", False, False), ("UnknownError", True, False), ("Valid", True, True),
])
def test_setup_signing_requires_sha256_valid_signature_and_timestamp(
    status: str, has_timestamp: bool, should_pass: bool,
) -> None:
    body = f"""
$script:signing = $null
function Get-ChildItem {{ [pscustomobject]@{{ HasPrivateKey = $true }} }}
function Set-AuthenticodeSignature {{
    param($LiteralPath, $Certificate, $HashAlgorithm, $TimestampServer)
    $script:signing = @{{ path = $LiteralPath; hash = $HashAlgorithm; timestamp = $TimestampServer }}
}}
function Get-AuthenticodeSignature {{
    param($LiteralPath)
    [pscustomobject]@{{ Status = {json.dumps(status)}; TimeStamperCertificate = {'$true' if has_timestamp else '$null'} }}
}}
try {{ Set-SetupAuthenticodeSignature -Path 'fixture.msi' -Thumbprint ('A' * 40) -Timestamp 'http://timestamp.digicert.com'; $errorText = '' }}
catch {{ $errorText = $_.Exception.Message }}
@{{ error = $errorText; signing = $script:signing }} | ConvertTo-Json -Compress
"""
    result = _run_setup_functions(["Assert-SetupSigningInputs", "Set-SetupAuthenticodeSignature"], body)
    assert result["signing"] == {
        "path": "fixture.msi", "hash": "SHA256", "timestamp": "http://timestamp.digicert.com",
    }
    assert (result["error"] == "") is should_pass
    if not should_pass:
        expected = "timestamp failed" if not has_timestamp else "signing failed"
        assert expected in str(result["error"]).lower()


def test_setup_source_version_rejects_explicit_mismatch_and_pe_overflow(tmp_path: Path) -> None:
    version_file = tmp_path / "version.py"
    version_file.write_text('AGENT_VERSION = "3.2.81"\n', encoding="utf-8")
    body = f"""
$path = {json.dumps(str(version_file))}
try {{ Resolve-SetupSourceVersion -SourcePath $path -ExplicitVersion '3.2.82' | Out-Null; $mismatch = '' }}
catch {{ $mismatch = $_.Exception.Message }}
[IO.File]::WriteAllText($path, 'AGENT_VERSION = "3.2.65536"')
try {{ Resolve-SetupSourceVersion -SourcePath $path -ExplicitVersion '' | Out-Null; $overflow = '' }}
catch {{ $overflow = $_.Exception.Message }}
@{{ mismatch = $mismatch; overflow = $overflow }} | ConvertTo-Json -Compress
"""
    result = _run_setup_functions(["Assert-SemVerTriplet", "Resolve-SetupSourceVersion"], body)
    assert "source" in str(result["mismatch"]).lower()
    assert "16-bit" in str(result["overflow"]).lower()


def test_setup_version_resource_has_source_bound_numeric_and_display_versions(tmp_path: Path) -> None:
    resource = tmp_path / "setup-version-info.txt"
    body = f"""
Write-SetupVersionResource -Version '3.2.82' -Path {json.dumps(str(resource))}
@{{ content = [IO.File]::ReadAllText({json.dumps(str(resource))}) }} | ConvertTo-Json -Compress
"""
    result = _run_setup_functions(["Write-SetupVersionResource"], body)
    def constructor(name: str):
        return lambda *args, **kwargs: {"type": name, "args": args, "kwargs": kwargs}

    constructors = {name: constructor(name) for name in (
        "VSVersionInfo", "FixedFileInfo", "StringFileInfo", "StringTable",
        "StringStruct", "VarFileInfo", "VarStruct",
    )}
    parsed = eval(str(result["content"]), {"__builtins__": {}}, constructors)
    assert parsed["type"] == "VSVersionInfo"
    assert parsed["kwargs"]["ffi"]["kwargs"]["filevers"] == (3, 2, 82, 0)
    assert parsed["kwargs"]["ffi"]["kwargs"]["prodvers"] == (3, 2, 82, 0)
    strings = parsed["kwargs"]["kids"][0]["args"][0][0]["args"][1]
    string_fields = {item["args"][0]: item["args"][1] for item in strings}
    assert string_fields["FileVersion"] == "3.2.82"
    assert string_fields["ProductVersion"] == "3.2.82"
    assert string_fields["OriginalFilename"] == "EndpointAgentSetup.exe"
    translation = parsed["kwargs"]["kids"][1]["args"][0][0]
    assert translation["args"] == ("Translation", [1033, 1200])


def test_setup_preflight_precedes_output_creation_and_restores_version_input() -> None:
    source = (WINDOWS_PACKAGING / "build-setup.ps1").read_text(encoding="utf-8")
    preflight = source.index("Assert-SetupSigningInputs -Thumbprint $CodeSigningCertificateThumbprint")
    version = source.index("$Version = Resolve-SetupSourceVersion")
    output = source.index("New-Item -ItemType Directory -Path $releaseRoot")
    assert preflight < version < output
    assert "$previousVersionFile = $env:ENDPOINT_SETUP_VERSION_FILE" in source
    assert "$env:ENDPOINT_SETUP_VERSION_FILE = $setupVersionFile" in source
    assert "$env:ENDPOINT_SETUP_VERSION_FILE = $previousVersionFile" in source


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
    assert "for ($attempt = 1; $attempt -le 5; $attempt++)" in source
    assert "Start-Sleep -Milliseconds (1000 * $attempt)" in source
    assert "$verified = Get-AuthenticodeSignature -LiteralPath $Path" in source
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


def test_frozen_setup_spec_embeds_msi_release_evidence_and_public_configuration() -> None:
    source = (PROJECT_ROOT / "pc_agent" / "pyinstaller_windows_setup.spec").read_text(
        encoding="utf-8"
    )

    assert "ENDPOINT_SETUP_MSI" in source
    assert "ENDPOINT_SETUP_CA_FILE" in source
    assert "ENDPOINT_SETUP_CONFIG" in source
    assert "ENDPOINT_SETUP_MSI_RELEASE_MANIFEST" in source
    assert "Install-EndpointAgentCanary.ps1" in source
    assert '"EndpointAgent.msi"' in source
    assert '"endpoint-ca.crt"' in source
    assert '"setup-config.json"' in source
    assert '"EndpointAgent.release.json"' in source
    assert "datas=[" in source


def test_setup_builder_requires_and_embeds_canonical_msi_release_manifest() -> None:
    source = (WINDOWS_PACKAGING / "build-setup.ps1").read_text(encoding="utf-8")

    assert "endpoint_windows_release_v1" in source
    assert "ENDPOINT_SETUP_MSI_RELEASE_MANIFEST" in source
    assert "EndpointAgent.release.json" in source
    assert "Install-EndpointAgentCanary.ps1" in source
    assert "MSI release manifest is missing." in source
    assert "$msiSourceCommit = [string]$releaseMsiManifest.source_revision" in source


def test_setup_spec_places_release_evidence_and_wrapper_in_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    names = {
        "ENDPOINT_SETUP_MSI": "EndpointAgent.msi",
        "ENDPOINT_SETUP_CA_FILE": "endpoint-ca.crt",
        "ENDPOINT_SETUP_CONFIG": "setup-config.json",
        "ENDPOINT_SETUP_MSI_RELEASE_MANIFEST": "EndpointAgent.release.json",
        "ENDPOINT_SETUP_VERSION_FILE": "setup-version-info.txt",
    }
    for env_name, filename in names.items():
        file_path = tmp_path / filename
        file_path.write_bytes(b"fixture")
        monkeypatch.setenv(env_name, str(file_path))
    collected: dict[str, object] = {}

    def analysis(*_args: object, **kwargs: object) -> SimpleNamespace:
        collected["datas"] = kwargs["datas"]
        return SimpleNamespace(pure=[], scripts=[], binaries=[], datas=kwargs["datas"])

    def exe(*_args: object, **kwargs: object) -> None:
        collected["exe"] = kwargs

    spec = PROJECT_ROOT / "pc_agent" / "pyinstaller_windows_setup.spec"
    exec(compile(spec.read_text(encoding="utf-8"), str(spec), "exec"), {
        "SPECPATH": str(spec.parent),
        "Analysis": analysis,
        "PYZ": lambda *_a, **_k: None,
        "EXE": exe,
    })

    datas = collected["datas"]
    assert {Path(source).name for source, target in datas if target == "payload"} == {
        "EndpointAgent.msi", "endpoint-ca.crt", "setup-config.json",
        "EndpointAgent.release.json", "Install-EndpointAgentCanary.ps1",
    }
    assert collected["exe"]["version"] == str(tmp_path / "setup-version-info.txt")


def test_frozen_setup_spec_requires_elevation_for_machine_provisioning() -> None:
    """The installer and its provisioner must share one elevated Windows token."""
    source = (PROJECT_ROOT / "pc_agent" / "pyinstaller_windows_setup.spec").read_text(
        encoding="utf-8"
    )

    assert "uac_admin=True" in source
    assert "console=False" in source


def test_installer_helper_executables_are_windowless() -> None:
    """A console subsystem in either helper would flash a command window."""
    for name in (
        "pyinstaller_windows_provision.spec",
        "pyinstaller_windows_service_launcher.spec",
    ):
        source = (PROJECT_ROOT / "pc_agent" / name).read_text(encoding="utf-8")
        assert "console=False" in source


def test_setup_entry_installs_embedded_msi_before_using_its_provisioner() -> None:
    source = (PROJECT_ROOT / "pc_agent" / "platform" / "windows" / "setup_entry.py").read_text(
        encoding="utf-8"
    )

    assert "sys._MEIPASS" in source
    assert "EndpointAgent.msi" in source
    assert "Install-EndpointAgentCanary.ps1" in source
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
    assert "install-result.json" in source
    assert "EndpointAgent" in source
    assert "CMD" in source


def test_setup_wrapper_owns_transaction_through_service_stop_and_provenance():
    source = (WINDOWS_PACKAGING / "Install-EndpointAgentCanary.ps1").read_text(encoding="utf-8")
    acquire = source.index("$updateMutex = New-UpdateTransaction")
    gate = source.index("if (Test-ActiveUpdateState -InstallRoot")
    cache = source.index("$executionCacheRoot =")
    inspect = source.index("$initial = Invoke-InstallerHelper -Bridge $bridge -Phase 'inspect'")
    stop = source.index("Stop-ManagedAgentServices -PreviousStates $previousServiceStates")
    prepare = source.index("Invoke-InstallerHelper -Bridge $bridge -Phase 'prepare' | Out-Null")
    install = source.index("$installer = [Diagnostics.Process]::Start($nativeInfo)")
    reconcile = source.index("Invoke-InstallerHelper -Bridge $bridge -Phase 'reconcile' | Out-Null")
    publish = source.index("Invoke-InstallerHelper -Bridge $bridge -Phase 'finish' | Out-Null")
    release = source.index("$updateMutex.ReleaseMutex()")
    assert acquire < gate < cache < inspect < stop < prepare < install < reconcile < publish < release
    assert "if (-not $transactionOwned) { exit 61 }" in source
    assert "catch [Threading.AbandonedMutexException]" in source
    assert "Write-Error 'UPDATE_STATE_INVALID' -ErrorAction Continue; exit 62" in source
    assert source.count("Assert-UpdateTransactionSecurity -Mutex $updateMutex") == 2
