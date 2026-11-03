"""Windows PowerShell5.1 state-machine admission with actual atomic file I/O.

Native execution and HTTP are deliberately replaced; this is not live acceptance.
"""
import os
from pathlib import Path
import subprocess
import pytest

SCRIPT = Path(__file__).resolve().parents[2] / 'packaging/windows/EndpointSetupUpdater.ps1'


@pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell5.1 file journal')
@pytest.mark.parametrize('fault', ['ack_loss', 'private_changed', 'native_failed'])
def test_client_report_ack_loss_retries_report_without_a_second_native_launch(tmp_path, fault):
    harness = tmp_path / 'journal.ps1'
    harness.write_text(r'''
param($Script,$Root,$Fault)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'source parse failed'}
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){Invoke-Expression $f.Extent.Text}
$script:StateRoot=$Root;$script:ClientRoot=$Root;$script:InstallerState=Join-Path $Root 'installer-state'
$script:ProgramData=$Root;$script:AgentRoot=$Root;$script:ClientVersion='1.0.2'
$script:DeviceId='11111111-1111-4111-8111-111111111111';$script:NativeStarts=0;$script:AppliedReports=0;$script:RemotePhase='assigned'
$script:Assignment='22222222-2222-4222-8222-222222222222';$script:Revision='b'*40;$script:Msi='c'*64
function Assert-System{}
function Assert-AdministrativePath($path){}
function Assert-SignedFile($path,$sha){}
function Initialize-EndpointClient{}
function New-AdministrativeDirectory($path){New-Item -ItemType Directory -Path $path -Force|Out-Null}
function Get-ClientHello{return @{ready=$true;core_version='3.2.157';foundation_version='3.2.158';client_version='1.0.2'}}
function Get-CompanionSessions{return @()}
function Restore-Companions($job){return $true}
function Get-PrivateSnapshot{$value=if($Fault -ceq 'private_changed' -and $script:NativeStarts){'changed'}else{'credential metadata'};return @{'device-credential'=$value;'enrollment-identity.json'='identity metadata';'endpoint-origin'='origin metadata';'endpoint-ca.crt'='CA metadata'}}
function Get-CimInstance{return [pscustomobject]@{State='Running';StartName='LocalSystem'}}
function Test-CoreOrNativeBusy{return $false}
function Get-SetupArtifact($job,$path){[IO.File]::WriteAllText($path,'inert test fixture')}
function Read-SetupPreflight($path){
 $version=if($script:NativeStarts){'3.2.158'}else{'3.2.157'}
 $eligibility=if($script:NativeStarts){'ALREADY_CURRENT'}else{'READY_FOR_SETUP_UPGRADE'}
 return [pscustomobject]@{schema_version='endpoint_windows_fleet_preflight_v1';target_version='3.2.158';eligibility=$eligibility;
  foundation=@{version='3.2.158';native_verified=$true;source_revision=$script:Revision;package_sha256=$script:Msi};
  core=@{version=$version;verified=$true;origin='msi';source_revision=$script:Revision;package_sha256=$script:Msi};
  provenance=@{verified=$true;conflict=$false};pending=@{active_or_degraded=$false};disk=@{sufficient=$true};
  services=@{EndpointAgent=@{identity_valid=$true;state='running';start_mode='automatic'};EndpointAgentUpdater=@{identity_valid=$true;start_mode='manual'}}}
}
function Observe-InstalledRuntime($job){return @{duration_seconds=180;samples=6;sensor_count=1;sensor_cpu_percent_max=0;services_stable=$true;companions_stable=$true;connected=$true}}
function Invoke-NativeSetup($job,$path){$script:NativeStarts++;$job.native_started=$true;$job.native_exit=$(if($Fault -ceq 'native_failed'){16}else{0});Save-Job $job}
function Invoke-EndpointJson($method,$path,$body){
 if($path -ceq '/agent/v1/setup-updates/hello'){return @{device_id=$script:DeviceId}}
 if($path.EndsWith('/status')){return @{phase=$script:RemotePhase}}
 if($path.EndsWith('/progress')){
  $script:RemotePhase=$body.phase
  if($body.phase -ceq 'applied'){$script:AppliedReports++;if($Fault -ceq 'ack_loss' -and $script:AppliedReports -eq 1){throw 'simulated_response_lost_after_commit'}}
  return @{assignment_id=$script:Assignment;attempt_id=$body.attempt_id;phase=$body.phase}
 }
 if($path.EndsWith('/recommendation')){
  if($script:RemotePhase -ceq 'applied'){return $null}
  return [pscustomobject]@{schema_version='windows_setup_recommendation_v1';device_id=$script:DeviceId;assignment_id=$script:Assignment;
   release=[pscustomobject]@{schema_version='windows_setup_release_v1';version='3.2.158';artifact_name='Setup.exe';size=10;sha256=('a'*64);msi_sha256=$script:Msi;source_revision=$script:Revision;tray_sha256=('d'*64);sensor_sha256=('e'*64)}}
 }
 throw 'unexpected API operation'
}
$lost=$false
try{Invoke-SetupClient}catch{if($_.Exception.Message -ceq 'simulated_response_lost_after_commit'){$lost=$true}else{throw}}
if($script:NativeStarts -ne 1){throw 'first native attempt not observed'}
$cached=Get-ActiveJob
if($Fault -ceq 'ack_loss'){
 if(!$lost -or $cached.phase -cne 'verifying' -or $cached.report.phase -cne 'applied'){throw 'retry authority not durable'}
}elseif($cached.phase -cne 'recovery_required' -or $script:AppliedReports -ne 0){throw 'unhealthy native outcome released ownership or reported applied'}
Invoke-SetupClient
$settled=Get-ActiveJob
if($script:NativeStarts -ne 1){throw 'native operation replayed'}
if($Fault -ceq 'ack_loss'){
 if($script:AppliedReports -ne 2 -or $settled.phase -cne 'applied' -or $null -ne $settled.report){throw 'lost report did not settle'}
}elseif($settled.phase -cne 'recovery_required' -or $script:AppliedReports -ne 0){throw 'unsafe native outcome stopped holding ownership'}
Write-Output 'PASS: one native launch; two reports; durable accepted result'
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT), str(tmp_path / 'state'), fault], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
