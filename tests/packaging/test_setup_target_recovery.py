"""A recovered target closes only as FAILED21 with original authority/history."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from endpoint_contracts.setup_updates import SetupProgressV1


SCRIPT = Path(__file__).resolve().parents[2] / 'packaging/windows/EndpointSetupUpdater.ps1'
OPERATION = '22222222-2222-4222-8222-222222222222'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


@pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell5.1 observer')
@pytest.mark.parametrize('fault', [
    'none', 'cached_soak', 'unknown_exit', 'different_exit', 'not_accepted',
    'old_operation', 'unrelated_owner', 'wrong_source', 'missing_finish',
    'bad_finish', 'wrong_grant', 'selector_changed', 'hold', 'busy', 'target_zip',
    'target_digest', 'private', 'no_user', 'companion_digest', 'no_sensor',
    'short_soak', 'unstable', 'changed_after_soak', 'missing_completion', 'wrong_completion', 'hello_identity',
])
def test_recovered_target_requires_original_authority_fresh_proof_and_preserved_history(tmp_path, fault):
    target = dict(version='3.2.169', source_revision='a' * 40, package_sha256='b' * 64)
    source = dict(version='3.2.158', source_revision='c' * 40, package_sha256='d' * 64)
    owner = dict(pid=1234, created=134383746580000000, sid='S-1-5-18', elevated=True, hash='9' * 64)
    binding = dict(operation_id=OPERATION, candidate_version=target['version'],
                   candidate_source_revision=target['source_revision'], candidate_tree_sha256='7' * 64,
                   old_release=source, new_release=target)
    if fault == 'wrong_source': binding['old_release'] = {**source, 'package_sha256': '0' * 64}
    if fault == 'unrelated_owner': owner['created'] = 134384000000000000
    stage = dict(schema_version='endpoint_windows_staged_update_v1', phase='accepted', binding=binding,
                 binding_sha256=hashlib.sha256(canonical(binding)).hexdigest(), owner=owner)
    if fault == 'not_accepted': stage['phase'] = 'trial'
    transaction = tmp_path / 'transactions' / OPERATION
    transaction.mkdir(parents=True)
    agent = tmp_path / 'Agent'
    agent.mkdir()
    selected = b'{"exact":"selected"}'
    previous = b'{"exact":"previous"}'
    (agent / 'current.json').write_bytes(selected)
    (agent / 'previous.json').write_bytes(previous)
    completion = dict(transaction_id=OPERATION, operation='install', phase='complete', startup_restored=True,
                      package=dict(version=target['version'], source_revision=target['source_revision'], sha256=target['package_sha256']))
    if fault == 'wrong_completion': completion['phase'] = 'msi-complete'
    grant = dict(schema_version=1, transaction_id=OPERATION, package=target, owner=owner,
                 completion=completion, completion_relative=f'transactions/{OPERATION}/completed.json',
                 selection=dict(selected_sha256=hashlib.sha256(selected).hexdigest(),
                                previous_sha256=hashlib.sha256(previous).hexdigest(), tree_sha256='7' * 64))
    if fault == 'wrong_grant': grant['package'] = {**target, 'source_revision': '0' * 40}
    finished = dict(schema_version=1, grant_sha256=hashlib.sha256(canonical(grant)).hexdigest())
    if fault == 'bad_finish': finished['grant_sha256'] = '0' * 64
    for leaf, value in [(tmp_path / 'staged-update.json', stage),
                        (transaction / 'native-continuation-grant.json', grant),
                        (transaction / 'native-continuation-finished.json', finished),
                        (transaction / 'completed.json', completion)]:
        leaf.write_bytes(canonical(value))
    if fault == 'missing_finish': (transaction / 'native-continuation-finished.json').unlink()
    if fault == 'missing_completion': (transaction / 'completed.json').unlink()
    if fault == 'selector_changed': (agent / 'current.json').write_bytes(b'{"different":true}')
    if fault == 'hold': (tmp_path / 'native-continuation.json').write_text('{}')
    harness = tmp_path / 'target.ps1'
    harness.write_text(r'''
param($Script,$Root,$Fault)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse failed'}
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){Invoke-Expression $f.Extent.Text}
$script:InstallerState=$Root;$script:AgentRoot=Join-Path $Root 'Agent';$script:Wire=Join-Path $Root 'wire.json'
$script:Phase=$null;$script:Restores=0;$script:Observations=0;$script:Preflights=0;$script:Refreshes=0;$script:DeviceId='55555555-5555-4555-8555-555555555555'
$before=[pscustomobject]@{foundation=[pscustomobject]@{version='3.2.158';source_revision=('c'*40);package_sha256=('d'*64)};core=@{version='3.2.164';source_revision=('8'*40);package_sha256=('6'*64);origin='zip'}}
$script:PrivateBaseline=@{'device-credential'='credential';'enrollment-identity.json'='identity';'endpoint-origin'='origin';'endpoint-ca.crt'='ca'}
$job=[pscustomobject]@{device_id=$script:DeviceId;assignment_id='33333333-3333-4333-8333-333333333333';attempt_id='44444444-4444-4444-8444-444444444444';native_started=$true;native_created='2026-11-05T17:50:44Z';native_ended='2026-11-05T17:56:28Z';native_exit=21;native_stage='accepted';before=$before;private_before=$script:PrivateBaseline;phase='recovery_required';previous_native_id=$null;report=$null;soak=$null;
 release=@{version='3.2.169';source_revision=('a'*40);msi_sha256=('b'*64);tray_sha256=('e'*64);sensor_sha256=('f'*64)};
 companions=@(@{session=2;sid='S-1-5-21-100';name='EndpointAgentTray.exe';sha256=('1'*64)})}
if($Fault -ceq 'old_operation'){$job.previous_native_id='22222222-2222-4222-8222-222222222222'}
if($Fault -ceq 'unknown_exit'){$job.native_exit=$null}
if($Fault -ceq 'different_exit'){$job.native_exit=16}
if($Fault -ceq 'cached_soak'){$job.soak=@{duration_seconds=999;samples=99;sensor_count=99;services_stable=$true;companions_stable=$true;connected=$true}}
$script:History=$job|Select-Object * -ExcludeProperty phase,report,soak|ConvertTo-Json -Depth 30 -Compress
function Assert-NoReparse($p){}
function Assert-AdministrativePath($p){}
function Save-Job($j){$h=$j|Select-Object * -ExcludeProperty phase,report,soak|ConvertTo-Json -Depth 30 -Compress;if($h -cne $script:History){throw 'source/native/private/companion history changed'}}
function Test-CoreOrNativeBusy{return ($Fault -ceq 'busy')}
function Assert-FullSetupSource($after,$release){return $true}
function Read-SetupPreflight($setup){
 $script:Preflights++
 $core=@{version='3.2.169';source_revision=('a'*40);package_sha256=('b'*64);origin='msi';verified=$true}
 if($Fault -ceq 'target_zip'){$core.origin='zip'}
 if($Fault -ceq 'target_digest' -or ($Fault -ceq 'changed_after_soak' -and $script:Preflights -gt 1)){$core.package_sha256='0'*64}
 return [pscustomobject]@{eligibility='ALREADY_CURRENT';foundation=@{version='3.2.169';source_revision=('a'*40);package_sha256=('b'*64);native_verified=$true};core=$core;provenance=@{verified=$true;conflict=$false};pending=@{active_or_degraded=$false};services=@{EndpointAgent=@{identity_valid=$true;state='running';start_mode='automatic'};EndpointAgentUpdater=@{identity_valid=$true;start_mode='manual'}}}
}
function Get-PrivateSnapshot{$p=@{};foreach($k in $script:PrivateBaseline.Keys){$p[$k]=$script:PrivateBaseline[$k]};if($Fault -ceq 'private'){$p['device-credential']='changed'};return $p}
function Get-CimInstance{return @{State='Running';StartName='LocalSystem'}}
function Get-CompanionSessions{
 if($Fault -ceq 'no_user'){return @()}
 return @(@{session=2;sid='S-1-5-21-100';name='EndpointAgentTray.exe';sha256=$(if($Fault -ceq 'companion_digest'){'0'*64}else{'e'*64})},@{session=2;sid='S-1-5-21-100';name='EndpointUserSensor.exe';sha256=('f'*64)})
}
function Restore-Companions($context){$script:Restores++;if($context.native_exit -ne 21 -or $context.companions[0].sha256 -cne ('e'*64)){throw 'target companion context not bound'};return $true}
function Observe-InstalledRuntime($j,$expectedVersion,$context){
 $script:Observations++;if($expectedVersion -cne '3.2.169' -or !$context -or $context.companions[0].sha256 -cne ('e'*64)){throw 'fresh target observation context missing'}
 Save-Job $j
 return @{duration_seconds=$(if($Fault -ceq 'short_soak'){179}else{180});samples=6;sensor_count=$(if($Fault -ceq 'no_sensor'){0}else{1});sensor_cpu_percent_max=0;services_stable=($Fault -cne 'unstable');companions_stable=$true;connected=$true}
}
function Get-ClientHello{return @{ready=$true;client_version='1.0.7';core_version='3.2.169';foundation_version='3.2.169'}}
function Invoke-EndpointJson($method,$path,$body){if($method -cne 'POST' -or $path -cne '/agent/v1/setup-updates/hello' -or $script:Observations -ne 1 -or !$body.ready){throw 'fresh post-soak hello missing'};$script:Refreshes++;return @{device_id=$(if($Fault -ceq 'hello_identity'){'66666666-6666-4666-8666-666666666666'}else{$script:DeviceId})}}
function Send-Progress($j,$phase,$proof,$safeCode){$script:Phase=$phase;$j.phase=$phase;Save-Job $j;@{attempt_id=$j.attempt_id;phase=$phase;proof=$proof;safe_code=$safeCode}|ConvertTo-Json -Depth 25 -Compress|Set-Content $script:Wire}
try{Complete-NativeJob $job 'never executed'}catch{if($Fault -cne 'hello_identity' -or $_.Exception.Message -cne 'setup_hello_device_differs'){throw};Send-Progress $job 'recovery_required' $null 'native_exit_requires_recovery'}
if($Fault -cin @('none','cached_soak')){
 if($script:Phase -cne 'failed' -or $script:Restores -ne 1 -or $script:Observations -ne 1 -or $script:Preflights -lt 2 -or $script:Refreshes -ne 1){throw ('recovered target was not honestly settled: '+$script:Phase+','+$script:Restores+','+$script:Observations+','+$script:Preflights+','+$script:Refreshes)}
}elseif($script:Phase -cne 'recovery_required'){throw 'unverified target released original hold'}
Save-Job $job
''', encoding='utf-8')
    # A Python child of PowerShell7 otherwise inherits its incompatible module
    # path; let Windows PowerShell5.1 discover its own Get-FileHash module.
    environment = {key: value for key, value in os.environ.items() if key.lower() != 'psmodulepath'}
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT), str(tmp_path), fault],
                            capture_output=True, text=True, timeout=20, env=environment)
    assert result.returncode == 0, result.stdout + result.stderr
    report = SetupProgressV1.model_validate(json.loads((tmp_path / 'wire.json').read_text(encoding='utf-8-sig')))
    if fault in {'none', 'cached_soak'}:
        assert report.phase == 'failed' and report.safe_code == 'native_failed_target_recovered'
        assert report.proof.exit_code == 21 and report.proof.native_phase == 'accepted'
    else:
        assert report.phase == 'recovery_required'


@pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell observer sampling')
@pytest.mark.parametrize('fault', ['none', 'sensor_gap', 'session_replaced', 'initial_scope_absent'])
def test_target_soak_requires_sensor_and_same_companion_scope_at_every_sample(tmp_path, fault):
    harness = tmp_path / 'sampling.ps1'
    harness.write_text(r'''
param($Script,$Root,$Fault)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){Invoke-Expression $f.Extent.Text}
$script:ProgramData=$Root;$script:StateRoot=$Root;$script:Sample=0
$job=[pscustomobject]@{assignment_id='33333333-3333-4333-8333-333333333333';release=@{version='3.2.169'};companions=@('original source');soak=$null}
$context=[pscustomobject]@{tag='target scope';companions=@(@{session=2;sid='S-1-5-21-100';name='EndpointUserSensor.exe'},@{session=2;sid='S-1-5-21-100';name='EndpointAgentTray.exe'})}
function Get-CimInstance($class){if($class -ceq 'Win32_ComputerSystem'){return @{NumberOfLogicalProcessors=2}};return @(@{Name='EndpointAgent';ProcessId=100},@{Name='EndpointBrowserPolicy';ProcessId=101})}
function Start-Sleep{$script:Sample++}
function Get-Process{if($Fault -ceq 'sensor_gap' -and $script:Sample -eq 3){return @()};return @([pscustomobject]@{Id=10;CPU=0;StartTime=[datetime]::Parse('2026-11-05T17:50:44Z')})}
function Get-LiveSessionSid($id){if($Fault -ceq 'session_replaced' -and $script:Sample -ge 3){return 'S-1-5-21-200'};return 'S-1-5-21-100'}
function Get-CompanionEvidence($c){if($c.tag -cne 'target scope'){throw 'wrong context'};if($Fault -ceq 'initial_scope_absent' -or ($Fault -ceq 'session_replaced' -and $script:Sample -ge 3)){return @()};return @(@{session=2;sid='S-1-5-21-100';name='EndpointUserSensor.exe';pid=10;created='fixed'},@{session=2;sid='S-1-5-21-100';name='EndpointAgentTray.exe';pid=11;created='fixed'})}
function Read-BoundedJson{return @{version='3.2.169';agent_state='running';endpoint_state='connected';observed_at=[DateTimeOffset]::UtcNow.ToString('o')}}
function Write-PrivateJson{}
function Save-Job($j){if($j.companions[0] -cne 'original source'){throw 'history replaced'}}
$soak=Observe-InstalledRuntime $job '3.2.169' $context
if($script:Sample -ne 6 -or $soak.sensor_count -ne 1){throw 'test did not exercise all samples/final active sensor'}
if($soak.companions_stable -ne ($Fault -ceq 'none')){throw 'interrupted target user scope accepted'}
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT), str(tmp_path), fault],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
