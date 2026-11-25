"""Run real PowerShell helpers; substitute only WTS/process/SCM boundaries."""
import os
from pathlib import Path
import subprocess
import pytest

SCRIPT = Path(__file__).resolve().parents[2] / 'packaging/windows/EndpointSetupUpdater.ps1'
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='PowerShell5.1 Windows helper tests')


@pytest.mark.parametrize('existing', [False, True])
def test_logged_in_user_without_source_companions_is_planned(tmp_path, existing):
    root=tmp_path/'agent';root.mkdir()
    for name in ('EndpointUserSensor.exe','EndpointAgentTray.exe'):(root/name).write_bytes(b'fixed test payload')
    harness=tmp_path/'plan.ps1'
    harness.write_text(r'''
param($Script,$Root,$Existing)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
foreach($name in @('Get-CompanionSessions')){
 $f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
 Invoke-Expression $f.Extent.Text
}
$script:AgentRoot=$Root
function Get-LoggedOnUserSessions{return @(@{session=2;sid='S-1-5-21-1-2-3-1001'},@{session=0;sid='S-1-5-18'},@{session=3;sid='S-1-5-18'})}
function Get-LiveSessionSid($session){if($session -eq 2){return 'S-1-5-21-1-2-3-1001'};return 'S-1-5-18'}
function Assert-NoReparse($path){}
function Get-CimInstance{
 if($Existing -ceq 'True'){return [pscustomobject]@{SessionId=2;Name='EndpointUserSensor.exe';ExecutablePath=(Join-Path $Root 'EndpointUserSensor.exe')}}
 return @()
}
function Invoke-CimMethod{return [pscustomobject]@{ReturnValue=0;Sid='S-1-5-21-1-2-3-1001'}}
$planned=@(Get-CompanionSessions)
if($planned.Count -ne 2){throw ('ordinary user startup omitted or duplicated: '+$planned.Count)}
foreach($item in $planned){if($item.session -ne 2 -or $item.sid -cne 'S-1-5-21-1-2-3-1001' -or $item.sha256 -cnotmatch '^[0-9a-f]{64}$'){throw 'invalid source session admitted'}}
Write-Output 'PASS'
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-File',str(harness),str(SCRIPT),str(root),str(existing)],capture_output=True,text=True)
    assert result.returncode==0,result.stdout+result.stderr


@pytest.mark.parametrize('fault',['none','busy','wrong_target','native_failed','recovery'])
def test_late_logon_repair_requires_an_accepted_idle_exact_target(tmp_path,fault):
    harness=tmp_path/'maintain.ps1'
    harness.write_text(r'''
param($Script,$Fault)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
$f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Maintain-UserCompanions'},$true)
if(!$f){throw 'late logon maintenance missing'};Invoke-Expression $f.Extent.Text
$script:AgentRoot='C:\Program Files\Endpoint Platform\Agent';$script:InstallerState='C:\Program Files\Endpoint Platform\installer-state'
$script:restores=0;$script:saves=0
$job=[pscustomobject]@{phase='applied';native_exit=0;companions=@();release=[pscustomobject]@{version='3.2.158';source_revision=('a'*40);msi_sha256=('b'*64);tray_sha256=('c'*64);sensor_sha256=('d'*64)};soak=[pscustomobject]@{duration_seconds=181;samples=6;services_stable=$true;companions_stable=$true;connected=$true}}
if($Fault -ceq 'native_failed'){$job.native_exit=21}
if($Fault -ceq 'recovery'){$job.phase='recovery_required'}
function Test-CoreOrNativeBusy{return ($Fault -ceq 'busy')}
function Enter-CompanionExclusion{return [pscustomobject]@{held=$true}}
function Exit-CompanionExclusion($lease){}
function Get-Service{return [pscustomobject]@{Status='Running'}}
function Read-BoundedJson($path,$limit){
 if($path.EndsWith('foundation.json')){return [pscustomobject]@{schema_version=1;release=[pscustomobject]@{version='3.2.158';source_revision=('a'*40);package_sha256=('b'*64)}}}
 return [pscustomobject]@{version=$(if($Fault -ceq 'wrong_target'){'3.2.163'}else{'3.2.158'});source_revision=('a'*40)}
}
function Get-CompanionSessions{return @(@{name='EndpointUserSensor.exe';session=2;sid='S-1-5-21-1-2-3-1001';sha256=('d'*64)})}
function Restore-Companions($j){if($j.companions.Count -ne 1){throw 'late session not persisted'};$script:restores++;return $true}
function Save-Job($j){$script:saves++}
$null=Maintain-UserCompanions $job
$expected=if($Fault -ceq 'none'){1}else{0}
if($script:restores -ne $expected -or $script:saves -ne $expected){throw 'unverified native state started companions or valid target omitted late session'}
Write-Output 'PASS'
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-File',str(harness),str(SCRIPT),fault],capture_output=True,text=True)
    assert result.returncode==0,result.stdout+result.stderr


def test_maintenance_cannot_starve_polling_and_retains_native_exclusion(tmp_path):
    harness=tmp_path/'isolation.ps1'
    harness.write_text(r'''
param($Script)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
foreach($name in @('Maintain-UserCompanions','Invoke-CompanionMaintenance')){
 $f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
 if(!$f){throw ('missing boundary '+$name)};Invoke-Expression $f.Extent.Text
}
$script:held=$false;$script:reported=0
function Enter-CompanionExclusion{$script:held=$true;return [pscustomobject]@{held=$true}}
function Exit-CompanionExclusion($lease){$script:held=$false}
function Test-CoreOrNativeBusy{return $false}
function Get-Service{return [pscustomobject]@{Status='Running'}}
function Read-BoundedJson($path,$limit){if($path.EndsWith('foundation.json')){return @{schema_version=1;release=@{version='3.2.158';source_revision=('a'*40);package_sha256=('b'*64)}}};return @{version='3.2.158';source_revision=('a'*40)}}
function Get-CompanionSessions{return @()}
function Save-Job($job){}
function Restore-Companions($job){if(!$script:held){throw 'canonical exclusion missing'};throw 'companion_user_differs'}
function Save-ClientStatus($code,$job){if($code -cne 'user_companion_unavailable'){throw 'unsafe diagnostic'};$script:reported++}
$script:AgentRoot='C:\agent';$script:InstallerState='C:\state'
$job=@{phase='applied';native_exit=0;release=@{version='3.2.158';source_revision=('a'*40);msi_sha256=('b'*64)};soak=@{duration_seconds=181;samples=6;services_stable=$true;companions_stable=$true;connected=$true};companions=@()}
$result=Invoke-CompanionMaintenance $job
if($result -ne $false -or $script:reported -ne 1 -or $script:held){throw 'maintenance starved next poll or leaked exclusion'}
Write-Output 'PASS'
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-File',str(harness),str(SCRIPT)],capture_output=True,text=True)
    assert result.returncode==0,result.stdout+result.stderr
