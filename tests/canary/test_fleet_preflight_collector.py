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
function Get-SafeFileFact { param($Path) @{path=$Path;regular=$true;reparse=($args[0] -eq 'reparse')} }
function Assert-NoReparsePointInPath { param($Path) }
function Get-AuthenticodeSignature { param($FilePath) @{Status=$global:signature;TimeStamperCertificate=$global:timestamp} }
function Invoke-BoundedSetupPreflight { param($Path) $global:executions++; @{exit_code=$global:exitCode;stdout=$global:raw} }
$global:raw=__RAW__
$global:signature=__SIGNATURE__
$global:timestamp=__TIMESTAMP__
$global:exitCode=__EXIT__
__REPARSE__
try { $result=Read-CanonicalSetupPreflight -Path 'C:\\exact\\Setup.exe' -TargetVersion '3.2.16'; $outcome='accepted' } catch { $outcome='rejected' }
@{outcome=$outcome;executions=$global:executions}|ConvertTo-Json -Compress
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
    assert json.loads(run.stdout) == {"outcome": want, "executions": executed}
    assert source.read_bytes() == before


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
