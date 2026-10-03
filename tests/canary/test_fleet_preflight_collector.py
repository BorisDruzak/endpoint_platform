"""Run the collector's real validation against isolated native boundaries."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from tests.canary.test_verify_installed_windows_agent import _fleet_facts

COLLECTOR = (
    Path(__file__).resolve().parents[2]
    / "tools/canary/Collect-WindowsAgentPreflight.ps1"
)


@pytest.mark.parametrize(
    "defect,want,executed",
    [
        ("valid", "accepted", 1),
        ("signature", "rejected", 0),
        ("timestamp", "rejected", 0),
        ("reparse", "rejected", 0),
        ("exit", "rejected", 1),
        ("bound", "rejected", 1),
        ("schema", "rejected", 1),
        ("target", "rejected", 1),
        ("secret", "rejected", 1),
        ("shape", "rejected", 1),
        ("live_claim", "rejected", 1),
        ("array_scalar", "rejected", 1),
        ("agent_state_array", "rejected", 1),
        ("updater_state_array", "rejected", 1),
        ("agent_mode_array", "rejected", 1),
        ("updater_mode_array", "rejected", 1),
        ("agent_state_object", "rejected", 1),
        ("updater_mode_object", "rejected", 1),
        ("service_nulls", "accepted", 1),
        ("launch_failure", "rejected", 1),
    ],
)
def test_explicit_setup_path_validates_signed_bounded_redacted_read_only_record(
    tmp_path, defect, want, executed
):
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if shell is None:
        pytest.skip("PowerShell unavailable")
    facts = _fleet_facts()
    if defect == "schema":
        facts["schema_version"] = "unexpected"
    elif defect == "target":
        facts["target_version"] = "3.2.18"
    elif defect == "secret":
        facts["credential"]["secret"] = "forbidden-opaque-data"
    elif defect == "shape":
        facts["core"]["verified"] = "true"
    elif defect == "live_claim":
        facts["ca"]["strict_live_tls"] = True
    elif defect == "array_scalar":
        facts["foundation"]["version"] = ["3.2.16"]
    elif defect.endswith("_array") or defect.endswith("_object"):
        service, field, kind = defect.split("_")
        name = "EndpointAgent" if service == "agent" else "EndpointAgentUpdater"
        field = "state" if field == "state" else "start_mode"
        original = facts["services"][name][field]
        facts["services"][name][field] = (
            [original] if kind == "array" else {"value": original}
        )
    elif defect == "service_nulls":
        for service in facts["services"].values():
            service["state"] = service["start_mode"] = None
    raw = json.dumps(facts) if defect != "bound" else "x" * 16385
    source = tmp_path / "run.ps1"
    # Parse exact production functions, replacing only native file/signature
    # and process launch. Production schema/target checks run unchanged.
    script = """
$ErrorActionPreference='Stop'
$ast=[System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$null,[ref]$null)
foreach($name in @('Assert-ExactFleetKeys','Assert-FleetPreflightSchema','Read-CanonicalSetupPreflight')) {
 $function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
 if($null -eq $function) { throw 'Missing production fleet function' }
 Invoke-Expression $function.Extent.Text
}
$global:executions=0
$global:pinned=$false
$global:events=[Collections.Generic.List[string]]::new()
function Open-SetupPreflightPin { param($Path) $global:pinned=$true; $global:events.Add('pin'); @{path=$Path} }
function Close-SetupPreflightPin { param($Pin) $global:pinned=$false; $global:events.Add('close') }
function Get-SafeFileFact { param($Path) @{path=$Path;regular=$true;reparse=($args[0] -eq 'reparse')} }
function Assert-NoReparsePointInPath { param($Path) }
function Get-AuthenticodeSignature { param($FilePath) if(-not $global:pinned){throw 'missing image pin'};$global:events.Add('signature'); @{Status=$global:signature;TimeStamperCertificate=$global:timestamp} }
function Invoke-BoundedSetupPreflight { param($Path) if(-not $global:pinned){throw 'missing launch pin'};$global:events.Add('launch'); $global:executions++; if($global:launchFailure){throw 'modeled launch failure'}; @{exit_code=$global:exitCode;stdout=$global:raw} }
$global:raw=__RAW__
$global:signature=__SIGNATURE__
$global:timestamp=__TIMESTAMP__
$global:exitCode=__EXIT__
$global:launchFailure=__LAUNCH_FAILURE__
__REPARSE__
try { $result=Read-CanonicalSetupPreflight -Path 'C:\\exact\\Setup.exe' -TargetVersion '3.2.16'; $outcome='accepted' } catch { $outcome='rejected' }
@{outcome=$outcome;executions=$global:executions;pinned=$global:pinned;events=@($global:events.ToArray())}|ConvertTo-Json -Compress
"""
    # JSON string is decoded in PowerShell without shell interpolation.
    import base64

    encoded = base64.b64encode(raw.encode()).decode()
    script = script.replace(
        "__RAW__",
        f"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))",
    )
    script = script.replace(
        "__SIGNATURE__", "'Invalid'" if defect == "signature" else "'Valid'"
    )
    script = script.replace(
        "__TIMESTAMP__",
        "$null" if defect == "timestamp" else "'public-timestamp-fixture'",
    )
    script = script.replace("__EXIT__", "20" if defect == "exit" else "0")
    script = script.replace(
        "__LAUNCH_FAILURE__", "$true" if defect == "launch_failure" else "$false"
    )
    script = script.replace(
        "__REPARSE__",
        "function Get-SafeFileFact { param($Path) @{path=$Path;regular=$true;reparse=$true} }"
        if defect == "reparse"
        else "",
    )
    source.write_text(script, encoding="utf-8")
    before = source.read_bytes()
    run = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-File", str(source), str(COLLECTOR)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert run.returncode == 0, run.stderr
    result = json.loads(run.stdout)
    assert result["outcome"] == want and result["executions"] == executed
    assert result["pinned"] is False
    assert result["events"] == (
        []
        if defect == "reparse"
        else ["pin", "signature", "close"]
        if defect in {"signature", "timestamp"}
        else ["pin", "signature", "launch", "close"]
    )
    assert source.read_bytes() == before


def test_own_setup_file_and_namespace_pins_hold_until_disposal(tmp_path):
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if shell is None:
        pytest.skip("PowerShell unavailable")
    directory = tmp_path / "own-setup-directory"
    directory.mkdir()
    setup = directory / "Setup.exe"
    setup.write_bytes(b"own image fixture, no execution")
    script = tmp_path / "pin-test.ps1"
    script.write_text(
        """
$ErrorActionPreference='Stop'
$ast=[System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$null,[ref]$null)
foreach($name in @('Initialize-SetupPreflightPinType','Open-SetupPathHandle','Open-SetupPreflightPin','Close-SetupPreflightPin')) {
 $function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
 if($null -eq $function){throw 'Missing production pin function'}
 Invoke-Expression $function.Extent.Text
}
$pin=Open-SetupPreflightPin -Path $args[1]
$writeBlocked=$false;$namespaceBlocked=$false
try {
 try { $stream=[IO.File]::Open($args[1],[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite);$stream.Dispose() } catch [IO.IOException] { $writeBlocked=$true }
 try { [IO.Directory]::Move($args[2],$args[2]+'-moved');[IO.Directory]::Move($args[2]+'-moved',$args[2]) } catch [IO.IOException] { $namespaceBlocked=$true }
} finally { Close-SetupPreflightPin $pin }
$stream=[IO.File]::Open($args[1],[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite);$stream.Dispose()
[IO.Directory]::Move($args[2],$args[2]+'-moved');[IO.Directory]::Move($args[2]+'-moved',$args[2])
@{write_blocked=$writeBlocked;namespace_blocked=$namespaceBlocked;closed=@($pin.handles|Where-Object {-not $_.IsClosed}).Count -eq 0}|ConvertTo-Json -Compress
""",
        encoding="utf-8",
    )
    run = subprocess.run(
        [
            shell,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script),
            str(COLLECTOR),
            str(setup),
            str(directory),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout) == {
        "write_blocked": True,
        "namespace_blocked": True,
        "closed": True,
    }
    assert setup.read_bytes() == b"own image fixture, no execution"


@pytest.mark.parametrize("service", ["EndpointAgent", "EndpointAgentUpdater"])
@pytest.mark.parametrize("field", ["state", "start_mode"])
@pytest.mark.parametrize("kind", ["string", "null", "array", "object"])
def test_production_service_schema_requires_nullable_scalar_strings(
    tmp_path, service, field, kind
):
    import base64

    shell = shutil.which("powershell") or shutil.which("pwsh")
    if shell is None:
        pytest.skip("PowerShell unavailable")
    facts = _fleet_facts()
    value = facts["services"][service][field]
    facts["services"][service][field] = {
        "string": value,
        "null": None,
        "array": [value],
        "object": {"value": value},
    }[kind]
    encoded = base64.b64encode(json.dumps(facts).encode()).decode()
    script = tmp_path / "schema-test.ps1"
    script.write_text(
        """
$ErrorActionPreference='Stop'
$ast=[System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$null,[ref]$null)
foreach($name in @('Assert-ExactFleetKeys','Assert-FleetPreflightSchema')) {
 $function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
 Invoke-Expression $function.Extent.Text
}
$value=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($args[1]))|ConvertFrom-Json
try { Assert-FleetPreflightSchema $value '3.2.16'; 'accepted' } catch { 'rejected' }
""",
        encoding="utf-8",
    )
    run = subprocess.run(
        [
            shell,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script),
            str(COLLECTOR),
            encoded,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == (
        "accepted" if kind in {"string", "null"} else "rejected"
    )


def test_partial_pin_acquisition_closes_all_acquired_ancestors(tmp_path):
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if shell is None:
        pytest.skip("PowerShell unavailable")
    script = tmp_path / "pin-failure-model.ps1"
    script.write_text(
        """
$ErrorActionPreference='Stop'
$ast=[System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$null,[ref]$null)
foreach($name in @('Open-SetupPreflightPin','Close-SetupPreflightPin')) {
 $function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
 Invoke-Expression $function.Extent.Text
}
Add-Type 'public class PinModel : System.IDisposable { public bool Closed; public string Path; public PinModel(string path){Path=path;} public void Dispose(){Closed=true;} }'
$global:opened=[Collections.Generic.List[PinModel]]::new()
function Open-SetupPathHandle { param($Path,$Directory)
 if(-not $Directory){throw 'modeled image open failure'}
 $handle=[PinModel]::new($Path);$global:opened.Add($handle);return $handle
}
try { Open-SetupPreflightPin 'C:\\own\\nested\\Setup.exe';throw 'unexpected acquisition' } catch { }
@{paths=@($global:opened|ForEach-Object {$_.Path});all_closed=@($global:opened|Where-Object {-not $_.Closed}).Count -eq 0}|ConvertTo-Json -Compress
""",
        encoding="utf-8",
    )
    run = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-File", str(script), str(COLLECTOR)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout) == {
        "paths": ["C:\\", "C:\\own", "C:\\own\\nested"],
        "all_closed": True,
    }


@pytest.mark.parametrize(
    "destination", ["artifact", "existing", "install", "data", "state", "cache"]
)
def test_report_writes_only_explicit_new_artifact(tmp_path, destination):
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if shell is None:
        pytest.skip("PowerShell unavailable")
    install = tmp_path / "machine/Agent"
    data = tmp_path / "data"
    install.mkdir(parents=True)
    data.mkdir()
    targets = {
        "artifact": tmp_path / "evidence/new.json",
        "existing": tmp_path / "existing.json",
        "install": install / "report.json",
        "data": data / "report.json",
        "state": install.parent / "installer-state/report.json",
        "cache": install.parent / "installer-cache/report.json",
    }
    targets["existing"].write_bytes(b"preserve existing artifact")
    script = tmp_path / "report-test.ps1"
    script.write_text(
        """
$ErrorActionPreference='Stop'
$ast=[System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$null,[ref]$null)
foreach($name in @('Write-PreflightReport','Assert-NoReparsePointInPath')) {
 $function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
 Invoke-Expression $function.Extent.Text
}
$ExpectedInstallRoot=$args[1];$ExpectedDataRoot=$args[2];$OutputPath=$args[3]
try { Write-PreflightReport @{safe=$true};'accepted' } catch { 'rejected' }
""",
        encoding="utf-8",
    )
    before = {
        str(p.relative_to(tmp_path)): p.read_bytes()
        for p in tmp_path.rglob("*")
        if p.is_file()
    }
    run = subprocess.run(
        [
            shell,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script),
            str(COLLECTOR),
            str(install),
            str(data),
            str(targets[destination]),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == (
        "accepted" if destination == "artifact" else "rejected"
    )
    after = {
        str(p.relative_to(tmp_path)): p.read_bytes()
        for p in tmp_path.rglob("*")
        if p.is_file()
    }
    if destination == "artifact":
        assert json.loads(after.pop("evidence\\new.json")) == {"safe": True}
    assert after == before
