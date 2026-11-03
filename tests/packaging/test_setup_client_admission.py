import json
import os
from pathlib import Path
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / 'packaging/windows/EndpointSetupUpdater.ps1'


@pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell mutex admission')
def test_mutex_security_uses_sid_identities_without_account_name_translation(tmp_path):
    harness = tmp_path / 'mutex.ps1'
    harness.write_text(r'''
param($Script)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
$f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'New-ClientMutexSecurity'},$true)
if(!$f){throw 'mutex factory missing'};Invoke-Expression $f.Extent.Text
$acl=New-ClientMutexSecurity
$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
if($rules.Count -ne 2 -or !$acl.AreAccessRulesProtected){throw 'mutex policy differs'}
foreach($rule in $rules){if($rule.IdentityReference.Value -cnotin @('S-1-5-18','S-1-5-32-544') -or $rule.MutexRights -ne 'FullControl'){throw 'mutex policy differs'}}
Write-Output 'PASS'
''')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != 'nt', reason='PowerShell recovery policy')
def test_cancelled_job_does_not_retry_or_launch_and_permanent_failures_are_bounded(tmp_path):
    harness = tmp_path / 'recovery.ps1'
    harness.write_text(r'''
param($Script)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
foreach($name in @('Sync-ServerJob','Get-PermanentFailureCode')){
 $f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
 if(!$f){throw ('missing '+$name)};Invoke-Expression $f.Extent.Text
}
function Invoke-EndpointJson {return [pscustomobject]@{phase='cancelled'}}
function Save-Job($job){}
$job=[pscustomobject]@{assignment_id='a';phase='verified';native_started=$false;report='pending'}
Sync-ServerJob $job
if($job.phase -cne 'cancelled' -or $null -ne $job.report){throw 'cancel not reconciled'}
if((Get-PermanentFailureCode 'setup_source_newer_than_target') -cne 'setup_source_newer_than_target'){throw 'permanent failure not classified'}
if($null -ne (Get-PermanentFailureCode 'arbitrary unsafe diagnostic')){throw 'unbounded error escaped'}
Write-Output 'PASS'
''')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_signed_client_source_exists_and_only_fixed_install_run_modes():
    assert SCRIPT.is_file()
    source = SCRIPT.read_text(encoding='utf-8-sig')
    assert "ValidateSet('Install','Run')" in source
    assert 'ExecutionPolicy Bypass' not in source


@pytest.mark.skipif(os.name != 'nt', reason='PowerShell source admission')
def test_native_source_admission_rejects_unknown_and_newer_core(tmp_path):
    fixture = dict(eligibility='READY_FOR_SETUP_UPGRADE', schema_version='endpoint_windows_fleet_preflight_v1',
        target_version='3.2.158', foundation=dict(native_verified=True, version='3.2.156'),
        core=dict(verified=True, version='3.2.156'), provenance=dict(verified=True, conflict=False),
        pending=dict(active_or_degraded=False), disk=dict(sufficient=True),
        services=dict(EndpointAgent=dict(identity_valid=True, state='running'),
                      EndpointAgentUpdater=dict(identity_valid=True)))
    path = tmp_path / 'preflight.json'
    path.write_text(json.dumps(fixture))
    harness = tmp_path / 'admission.ps1'
    harness.write_text(r'''
param($Script,$Fixture)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'script parse failed'}
$functions=$ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -cin @('Assert-FullSetupSource')},$true)
if($functions.Count -ne 1){throw 'admission missing'}
foreach($f in $functions){Invoke-Expression $f.Extent.Text}
$baseline=Get-Content -Raw -LiteralPath $Fixture|ConvertFrom-Json
$release=[pscustomobject]@{version='3.2.158';source_revision=('b'*40);msi_sha256=('c'*64)}
$null=Assert-FullSetupSource $baseline $release
$changes=@({param($p)$p.core.version='3.2.159'}, {param($p)$p.pending.active_or_degraded=$true},
 {param($p)$p.provenance.conflict=$true}, {param($p)$p.foundation.native_verified=$false},
 {param($p)$p.services.EndpointAgent.identity_valid=$false}, {param($p)$p.disk.sufficient=$false},
 {param($p)$p.pending.active_or_degraded=$null}, {param($p)$p.eligibility='PROVENANCE_CONFLICT'})
foreach($change in $changes){$p=Get-Content -Raw -LiteralPath $Fixture|ConvertFrom-Json;& $change $p;$refused=$false;try{$null=Assert-FullSetupSource $p $release}catch{$refused=$true};if(!$refused){throw 'unsafe source admitted'}}
Write-Output 'PASS8'
''')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT), str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'PASS8' in result.stdout


@pytest.mark.skipif(os.name != 'nt', reason='native PowerShell helpers')
def test_source_hashes_survive_rollback_and_missing_sensor_is_detected(tmp_path):
    harness = tmp_path / 'helpers.ps1'
    harness.write_text(r'''
param($Script)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
foreach($name in @('Get-CompanionExpectedHash','Get-CompanionEvidence')){
 $f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
 if(!$f){throw ('missing helper '+$name)};Invoke-Expression $f.Extent.Text
}
$script:AgentRoot='C:\Program Files\Endpoint Platform\Agent'
$session=[pscustomobject]@{name='EndpointUserSensor.exe';session=2;sid='S-1-5-21-1-2-3-1001';sha256=('a'*64)}
$job=[pscustomobject]@{native_exit=67;release=[pscustomobject]@{sensor_sha256=('b'*64)};companions=@($session)}
if((Get-CompanionExpectedHash $job $session) -cne ('a'*64)){throw 'rollback selected target hash'}
$job.native_exit=0;if((Get-CompanionExpectedHash $job $session) -cne ('b'*64)){throw 'normal update selected source hash'}
function Get-LiveSessionSid($id){return 'S-1-5-21-1-2-3-1001'}
function Get-CimInstance {param($ClassName,$Filter) return @()}
$refused=$false;try{$null=Get-CompanionEvidence $job}catch{$refused=$true}
if(!$refused){throw 'missing sensor accepted'}
Write-Output 'PASS'
''')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != 'nt', reason='native NTFS evidence')
def test_file_evidence_is_stable_and_rejects_hardlinked_private_material(tmp_path):
    sample = tmp_path / 'sample'
    sample.write_bytes(b'non-secret fixture')
    harness = tmp_path / 'evidence.ps1'
    harness.write_text(r'''
param($Script,$Sample,$Link)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
$f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Initialize-FileEvidence'},$true)
Invoke-Expression $f.Extent.Text;Initialize-FileEvidence
$before=[EndpointSetupFileEvidence]::Read($Sample);$after=[EndpointSetupFileEvidence]::Read($Sample)
if($before -cne $after -or $before.Split('|').Count -ne 4){throw 'native evidence unstable'}
New-Item -ItemType HardLink -Path $Link -Target $Sample|Out-Null
$refused=$false;try{$null=[EndpointSetupFileEvidence]::Read($Sample)}catch{$refused=$true}
if(!$refused){throw 'hardlinked private leaf accepted'}
Write-Output 'PASS'
''')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT), str(sample), str(tmp_path / 'alias')], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
