"""Exercise settled Setup cache retirement against real files."""

import os
from pathlib import Path
import subprocess

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "packaging/windows/EndpointSetupUpdater.ps1"


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1 Setup client")
def test_only_settled_verified_setup_downloads_are_retired(tmp_path):
    harness = tmp_path / "retention.ps1"
    harness.write_text(r"""
param($Script,$Root)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Utility/Microsoft.PowerShell.Utility.psd1')
$tokens=$null
$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Updater source parse failed'}
foreach($name in @('Assert-NoReparse','Get-JobRoot','Test-TerminalPhase','Remove-SettledSetupDownload')){
 $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
 Invoke-Expression $function.Extent.Text
}
function Assert-AdministrativePath($path){}
$script:StateRoot=$Root
$assignment='22222222-2222-4222-8222-222222222222'
$jobRoot=Get-JobRoot $assignment
$null=New-Item -ItemType Directory -Path $jobRoot -Force
$setup=Join-Path $jobRoot 'Setup.exe'
$marker=Join-Path $jobRoot 'native-started.json'
$journal=Join-Path $jobRoot 'job.json'
[IO.File]::WriteAllText($journal,'persistent audit')
foreach($scenario in @('applied','unknown','ack_pending','not_started','changed','marker_conflict','recovery_required')){
 [IO.File]::WriteAllText($setup,'setup')
 [IO.File]::WriteAllText($marker,'native marker')
 $job=@{assignment_id=$assignment;phase='applied';native_started=$true;native_exit=0;report=$null;
  release=@{size=5;sha256=(Get-FileHash -LiteralPath $setup).Hash.ToLowerInvariant()}}
 switch($scenario){
  'unknown' {$job.native_exit=$null}
  'ack_pending' {$job.report=@{phase='applied'}}
  'not_started' {$job.phase='blocked';$job.native_started=$false;$job.native_exit=$null;[IO.File]::Delete($marker)}
  'changed' {[IO.File]::WriteAllText($setup,'other')}
  'marker_conflict' {[IO.File]::Delete($marker)}
  'recovery_required' {$job.phase='recovery_required'}
 }
 Remove-SettledSetupDownload $job
 Remove-SettledSetupDownload $job
 if((Test-Path -LiteralPath $setup) -eq ($scenario -in @('applied','not_started'))){throw "Unexpected retention outcome: $scenario"}
 if([IO.File]::ReadAllText($journal) -cne 'persistent audit'){throw 'Audit altered'}
 if($scenario -notin @('not_started','marker_conflict') -and [IO.File]::ReadAllText($marker) -cne 'native marker'){throw 'Marker altered'}
}
""", encoding="ascii")
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    completed = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-File", str(harness), str(SCRIPT), str(tmp_path)],
        capture_output=True, text=True, timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
