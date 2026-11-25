"""Real task registration, with launch and process observation replaced.

The temporary task has no trigger and is never run. This exercises the Windows
UserId boundary which mocked companion-maintenance tests cannot validate.
"""
import os
from pathlib import Path
import subprocess

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / 'packaging/windows/EndpointSetupUpdater.ps1'


@pytest.mark.skipif(os.name != 'nt', reason='Windows task registration')
def test_restore_registers_resolved_account_but_launch_keeps_exact_session_sid(tmp_path):
    harness = tmp_path / 'registration.ps1'
    harness.write_text(r'''
param($Script,$Root)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
Import-Module ScheduledTasks -ErrorAction Stop
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'source parse failed'}
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){Invoke-Expression $f.Extent.Text}
$global:EndpointTestIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
$global:EndpointTestExpectedSid=$global:EndpointTestIdentity.User.Value
$script:AgentRoot=$Root;$global:EndpointTestLaunched=$false;$global:EndpointTestRegistered=0
$global:EndpointTestTaskName=$null;$global:EndpointTestAssignment=[guid]::NewGuid().ToString()
function Initialize-SessionIdentity {}
function Get-LiveSessionSid([int]$session){return $global:EndpointTestExpectedSid}
function Assert-NoReparse($path){}
function Get-CompanionExpectedHash($job,$session){return ('a'*64)}
function Get-FileHash($LiteralPath){return [pscustomobject]@{Hash=('a'*64)}}
function Start-Sleep($Seconds){}
function Get-CimInstance($ClassName,$Filter){
 if($global:EndpointTestLaunched){return [pscustomobject]@{ProcessId=123;ParentProcessId=1;SessionId=1;ExecutablePath=(Join-Path $script:AgentRoot 'EndpointUserSensor.exe')}}
}
function Invoke-CimMethod($InputObject,$MethodName){return [pscustomobject]@{ReturnValue=0;Sid=$global:EndpointTestExpectedSid}}
function Register-ScheduledTask($TaskName,$Action,$Settings,$Principal,$Description){
 $global:EndpointTestTaskName=$TaskName
 $result=ScheduledTasks\Register-ScheduledTask -TaskName $TaskName -Action $Action -Settings $Settings -Principal $Principal -Description $Description -ErrorAction Stop
 $global:EndpointTestRegistered++
 if($Principal.UserId -ine $global:EndpointTestIdentity.Name -or $Principal.LogonType -ne 'Interactive' -or $Principal.RunLevel -ne 'Limited'){throw 'principal differs'}
 return $result
}
$global:EndpointTestFakeTask=New-Object psobject
$global:EndpointTestFakeTask|Add-Member ScriptMethod SetSecurityDescriptor {param($sddl,$flags) if($sddl -cne 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'){throw 'task ACL differs'}}
$global:EndpointTestFakeTask|Add-Member ScriptMethod RunEx {param($launchArgs,$flags,$session,$sid) if($flags -ne 12 -or $session -ne 1 -or $sid -cne $global:EndpointTestExpectedSid){throw 'session/SID launch binding lost'};$global:EndpointTestLaunched=$true}
$global:EndpointTestFakeFolder=New-Object psobject
$global:EndpointTestFakeFolder|Add-Member ScriptMethod GetTask {param($name) if($name -cne $global:EndpointTestTaskName){throw ('wrong task: '+$name+' expected '+$global:EndpointTestTaskName)};return $global:EndpointTestFakeTask}
$global:EndpointTestFakeScheduler=New-Object psobject
$global:EndpointTestFakeScheduler|Add-Member ScriptMethod Connect {}
$global:EndpointTestFakeScheduler|Add-Member ScriptMethod GetFolder {param($path) return $global:EndpointTestFakeFolder}
function New-Object($ComObject){if($ComObject -cne 'Schedule.Service'){throw 'unexpected COM'};return $global:EndpointTestFakeScheduler}
$job=[pscustomobject]@{assignment_id=$global:EndpointTestAssignment;companions=@([pscustomobject]@{name='EndpointUserSensor.exe';session=1;sid=$global:EndpointTestExpectedSid})}
try {
 if(!(Restore-Companions $job)){throw 'restoration false'}
 if(!$global:EndpointTestLaunched -or $global:EndpointTestRegistered -ne 1){throw 'registration or mocked launch missing'}
 if(Get-ScheduledTask -TaskName $global:EndpointTestTaskName -ErrorAction SilentlyContinue){throw 'owned task not cleaned'}
 'PASS'
} finally {
 # The production finally must clean its owned task; this safety cleanup also
 # covers a failed assertion after the real registration in this test harness.
 if($global:EndpointTestTaskName -and (Get-ScheduledTask -TaskName $global:EndpointTestTaskName -ErrorAction SilentlyContinue)){
  Unregister-ScheduledTask -TaskName $global:EndpointTestTaskName -Confirm:$false
 }
}
''', encoding='utf-8')
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT), str(tmp_path)],
        capture_output=True, text=True, timeout=45,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'PASS' in result.stdout


@pytest.mark.skipif(os.name != 'nt', reason='Windows identity translation')
def test_unresolvable_companion_principal_has_fixed_error_without_fallback(tmp_path):
    harness = tmp_path / 'unresolved.ps1'
    harness.write_text(r'''
param($Script)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
$f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Get-CompanionTaskAccount'},$true)
if(!$f){throw 'principal resolver absent'};Invoke-Expression $f.Extent.Text
foreach($sid in @('', 'invalid', 'S-1-5-21-1-2-3-2147483000')){
 $refused=$false
 try{$null=Get-CompanionTaskAccount $sid}catch{if($_.Exception.Message -ceq 'companion_principal_unavailable'){$refused=$true}}
 if(!$refused){throw 'principal lookup did not fail closed'}
}
'PASS'
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT)],
                            capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
