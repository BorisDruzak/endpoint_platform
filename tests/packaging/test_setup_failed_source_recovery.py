import json
import os
from pathlib import Path
import subprocess

import pytest
from endpoint_contracts.setup_updates import SetupProgressV1


@pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell native observer')
@pytest.mark.parametrize('fault', ['none', 'fresh', 'changed_source', 'changed_zip', 'pending', 'private', 'unknown_exit'])
def test_failed_native_is_settled_only_after_verified_unchanged_source(tmp_path, fault):
    harness = tmp_path / 'recovery.ps1'
    harness.write_text(r'''
param($Script,$Root,$Fault)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){Invoke-Expression $f.Extent.Text}
$script:InstallerState=$Root;$script:Phase=$null;$script:Proof=$null;$script:Restores=0;$script:History=@();$script:Wire=Join-Path $Root 'wire.json'
$before=[pscustomobject]@{foundation=[pscustomobject]@{version='3.2.158';source_revision=('a'*40);package_sha256=('b'*64);native_verified=$true};core=[pscustomobject]@{version='3.2.157';source_revision=('c'*40);package_sha256=('d'*64);origin='zip';verified=$true};pending=@{active_or_degraded=$false}}
$job=[pscustomobject]@{native_exit=$(if($Fault -ceq 'unknown_exit'){$null}else{21});before=$before;phase='recovery_required';attempt_id='11111111-1111-4111-8111-111111111111';companions=@();soak=$null;previous_native_id=$null}
if($Fault -ceq 'fresh'){$job.phase='installing'}
function Read-SetupPreflight($setup){$after=$before|ConvertTo-Json -Depth 12|ConvertFrom-Json;if($Fault -ceq 'changed_source'){$after.core.source_revision='d'*40};if($Fault -ceq 'changed_zip'){$after.core.package_sha256='e'*64};return $after}
function Test-CoreOrNativeBusy{return ($Fault -ceq 'pending')}
function Restore-Companions($job){$script:Restores++;return $true}
function New-NativeProof($job,$after,$outcome,$code,$restored){return [ordered]@{foundation_version='3.2.158';core_version='3.2.157';source_revision=('a'*40);msi_sha256=('b'*64);native_phase=$outcome;exit_code=$code;native_verified=$true;core_verified=$true;provenance_verified=$true;pending=$false;services_verified=$true;companions_restored=$restored;private=@{credential=($Fault -cne 'private');identity=$true;origin=$true;ca=$true}}}
function Observe-InstalledRuntime($job,$expectedVersion){if($expectedVersion -cne '3.2.157'){throw 'source version observation differs'};return @{duration_seconds=180;samples=6;sensor_count=1;sensor_cpu_percent_max=0;services_stable=$true;companions_stable=$true;connected=$true}}
function Send-Progress($job,$phase,$proof,$safeCode){$script:History+=$phase;$job.phase=$phase;$script:Phase=$phase;$script:Proof=$proof;@{attempt_id=$job.attempt_id;phase=$phase;proof=$proof;safe_code=$safeCode}|ConvertTo-Json -Depth 20 -Compress|Set-Content -LiteralPath $script:Wire}
Complete-NativeJob $job 'never executed'
if($Fault -cin @('none','fresh')){
 if($script:Phase -cne 'failed' -or $script:Restores -ne 1 -or $script:Proof.native_phase -cne 'unchanged' -or $script:Proof.exit_code -ne 21){throw 'source recovery not honestly settled'}
 if($Fault -ceq 'fresh' -and $script:History[0] -cne 'recovery_required'){throw 'native exit skipped recovery acknowledgement'}
}elseif($script:Phase -cne 'recovery_required'){throw 'unverified source released native hold'}
Write-Output 'PASS'
''', encoding='utf-8')
    script = Path(__file__).parents[2] / 'packaging/windows/EndpointSetupUpdater.ps1'
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(script), str(tmp_path), fault], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    SetupProgressV1.model_validate(json.loads((tmp_path / 'wire.json').read_text(encoding='utf-8-sig')))


@pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell observation')
def test_source_observation_checks_source_version_and_does_not_reuse_target_cache(tmp_path):
    harness = tmp_path / 'soak.ps1'
    harness.write_text(r'''
param($Script,$Root)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){Invoke-Expression $f.Extent.Text}
$script:ProgramData=$Root;$script:Reads=0
function Get-CimInstance($ClassName){if($ClassName -ceq 'Win32_ComputerSystem'){return @{NumberOfLogicalProcessors=2}};return @(@{Name='EndpointAgent';ProcessId=100},@{Name='EndpointBrowserPolicy';ProcessId=101})}
function Get-CompanionEvidence{return @()}
function Get-Process{return @()}
function Start-Sleep{}
function Read-BoundedJson{$script:Reads++;return @{version='3.2.157';agent_state='running';endpoint_state='connected';observed_at=[DateTimeOffset]::UtcNow.ToString('o')}}
function Write-PrivateJson{}
function Get-JobRoot{return $Root}
function Save-Job{}
$cached=@{duration_seconds=200;samples=6;services_stable=$true;companions_stable=$true;connected=$true}
$job=[pscustomobject]@{soak=$cached;release=@{version='3.2.158'};assignment_id='test'}
$source=Observe-InstalledRuntime $job '3.2.157'
if(!$source.connected -or $script:Reads -ne 6){throw 'source observation expected target or reused cached epoch'}
$wrong=Observe-InstalledRuntime $job '3.2.158'
if($wrong.connected){throw 'wrong version accepted as connected'}
''', encoding='utf-8')
    script = Path(__file__).parents[2] / 'packaging/windows/EndpointSetupUpdater.ps1'
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(script), str(tmp_path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
