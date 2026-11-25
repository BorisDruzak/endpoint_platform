"""Windows Setup preflight and native admission checks."""

import os
from pathlib import Path
import subprocess

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "packaging/windows/EndpointSetupUpdater.ps1"


def test_factory_setup_validates_recovery_inputs_before_creating_native_fence():
    source = SCRIPT.with_name("Install-EndpointAgentCanary.ps1").read_text(encoding="utf-8")
    recovery_inputs = source.index("Copy-InstallerRecoveryInputs -Bridge $bridge -SetupImage $SetupImagePath")
    native_prepare = source.index("$preparation=Invoke-InstallerHelper -Bridge $bridge -Phase 'prepare'")
    assert recovery_inputs < native_prepare


@pytest.mark.skipif(os.name != "nt", reason="Windows jobs and anonymous pipes")
def test_repeated_preflight_failure_reaps_children_and_bounds_output(tmp_path):
    harness = tmp_path / "preflight-harness.ps1"
    harness.write_text(r"""
param($Script, $Root)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$errors = $null
$tokens = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
if($errors.Count){ throw 'Setup client syntax error' }
foreach($name in @('Initialize-SetupPreflightProcess','Read-SetupPreflight')){
 $function = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
 Invoke-Expression $function.Extent.Text
}
Initialize-SetupPreflightProcess
$image = Join-Path $Root 'test preflight.exe'
Add-Type -OutputType ConsoleApplication -OutputAssembly $image -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
public static class PreflightFixture {
 public static void Main(string[] args) {
  if(args[0]=="child"){Thread.Sleep(60000);return;}
  if(args[0]!="--preflight" || args[1]!="--quiet")Environment.Exit(2);
  string mode=Environment.GetEnvironmentVariable("ENDPOINT_TEST_PREFLIGHT");
  if(mode=="ok"){Console.Write("{\"ready\":true}");return;}
  string exe=Assembly.GetExecutingAssembly().Location;
  using(var child=Process.Start(new ProcessStartInfo(exe,"child"){UseShellExecute=false,CreateNoWindow=true})) {
   File.WriteAllText(exe+".pids",Process.GetCurrentProcess().Id+":"+child.Id);
  }
  if(mode=="descendant")return;
  if(mode=="stdout")Console.Write(new string('x',65536));
  if(mode=="stderr")Console.Error.Write(new string('x',65536));
  Thread.Sleep(60000);
 }
}
'@
$env:ENDPOINT_TEST_PREFLIGHT = 'ok'
if(!(Read-SetupPreflight $image).ready){throw 'Valid preflight result missing'}
foreach($case in @('hang','descendant','stdout','stderr','hang','stdout')){
 $env:ENDPOINT_TEST_PREFLIGHT = $case
 Remove-Item -LiteralPath ($image+'.pids') -ErrorAction SilentlyContinue
 $clock = [Diagnostics.Stopwatch]::StartNew()
 $observed = $null
 try{ [void][EndpointSetupPreflightProcess]::Run($image,1200) }
 catch{ $observed = $_.Exception.GetBaseException().Message }
 $expected = if($case -in @('hang','descendant')){'preflight_observation_expired'}else{'preflight_unavailable'}
 if($observed -cne $expected -or $clock.ElapsedMilliseconds -gt 6000){throw "Unexpected result for $case : $observed"}
 foreach($pidText in [IO.File]::ReadAllText($image+'.pids').Split(':')){
  $child = Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue
  if($child){
   try{if(!$child.WaitForExit(1000)){throw "Leaked process $pidText for $case"}}
   finally{$child.Dispose()}
  }
 }
}
""", encoding="ascii")
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    completed = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-File", str(harness), str(SCRIPT), str(tmp_path)],
        capture_output=True, text=True, timeout=40,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr

@pytest.mark.skipif(os.name != "nt", reason="PowerShell 5.1")
def test_failed_core_recovery_scm_boundary_and_no_unowned_stop(tmp_path):
    harness = tmp_path / "failed-core.ps1"
    harness.write_text(r"""
param($Script)
$ErrorActionPreference='Stop'
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$null,[ref]$null)
foreach($name in @('Get-FailedCoreObservation','Stop-ManagedAgentServices','Restore-StagedRollbackCore')){
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    if($null -eq $node){throw "missing function $name"}
    Invoke-Expression $node.Extent.Text
}
$root='C:\Program Files\Endpoint Platform\Agent'
$script:scm=[pscustomobject]@{State='Stopped';ProcessId=0;ExitCode=1066;ServiceSpecificExitCode=1;StartMode='Auto';StartName='NT AUTHORITY\LocalService';PathName=('"'+(Join-Path $root 'endpoint-agent-service.exe')+'" --agent-service')}
function Get-CimInstance { return $script:scm }
function Get-Service { param($Name,$ErrorAction) if($Name -eq 'EndpointAgent'){return [pscustomobject]@{Status=[ServiceProcess.ServiceControllerStatus]::Running}} }
function Stop-Service { throw 'unowned_stop' }
function Start-ManagedEndpointAgent { $script:numberStarted++ }
$stable=Get-FailedCoreObservation $root
foreach($case in @(@('ExitCode',0),@('ServiceSpecificExitCode',0),@('StartMode','Disabled'),@('ProcessId',43),
                   @('State','Running'),@('StartName','LocalSystem'),@('PathName','C:\foreign.exe --agent-service'))){
    $key=$case[0];$old=$script:scm.$key;$script:scm.$key=$case[1]
    $errorName=$null
    try { $null=Get-FailedCoreObservation $root } catch { $errorName=$_.Exception.Message }
    if($errorName -ne 'FAILED_CORE_RECOVERY_INELIGIBLE'){throw "invalid SCM admission $key"}
    $script:scm.$key=$old
}
$script:scm.State='Running'
$errorName=$null
try { Stop-ManagedAgentServices -PreviousStates @{EndpointAgent='Stopped'} -StoppedBySetup @{} -AssertCoreAlreadyStopped {if((Get-FailedCoreObservation $root) -cne $stable){throw 'UPDATE_IN_PROGRESS'}} }
catch { $errorName=$_.Exception.Message }
if($errorName -ne 'FAILED_CORE_RECOVERY_INELIGIBLE'){throw "wrong stop result $errorName"}
$script:scm.State='Stopped'
$script:scm.ExitCode=0
$script:numberStarted=0
Restore-StagedRollbackCore @{EndpointAgent='Stopped'}
if($script:numberStarted -ne 0){throw 'stopped predecessor was started'}
$script:scm.State='Running'
$errorName=$null
try { Restore-StagedRollbackCore @{EndpointAgent='Stopped'} } catch { $errorName=$_.Exception.Message }
if($errorName -ne 'RECOVERY_REQUIRED' -or $script:numberStarted -ne 0){throw 'rollback raced into foreign running service'}
Restore-StagedRollbackCore @{EndpointAgent='Running'}
if($script:numberStarted -ne 1){throw 'running predecessor was not started'}

# Execute the actual wrapper's preparation and compound-dispatch statements.
# The trusted native helper changes Auto to Disabled under the owner fence.
$source=[IO.File]::ReadAllText($Script)
$replaceStart=$source.IndexOf("    } elseif ("+[char]36+"intent -eq 'install' -and "+[char]36+"null -eq "+[char]36+"interruptedFence")
if($replaceStart -lt 0){throw 'missing fresh replace branch'}
$replace=$source.Substring($replaceStart)
$fresh=$replace.Substring(0,$replace.IndexOf([char]36+'newFence='))
$old=[regex]::Matches($fresh,'(?m)^(?<code>            \$oldBridge\.Policy\.MarkQuiescent\(\)\r?\n(?:            if[^\r\n]+\r?\n)?            Invoke-InstallerHelper \$oldBridge ''prepare'' \| Out-Null)')
$successor=[regex]::Match($replace,'(?m)^(?<code>(?:    if \(\$RecoverFailedCore\)[^\r\n]+\r?\n)?    \$preparation=Invoke-InstallerHelper -Bridge \$bridge -Phase ''prepare'')')
$dispatch=[regex]::Match($replace,'(?m)^(?<code>    Start-WindowsInstaller\r?\n(?:    [^\r\n]+\r?\n)*?    \} else \{)\r?$')
if($old.Count -ne 2 -or !$successor.Success -or !$dispatch.Success){throw 'missing fresh replace preparation/dispatch'}
$script:scm.State='Stopped';$script:scm.StartMode='Auto';$script:scm.ExitCode=1066
$RecoverFailedCore=$true
$script:stages=@()
$assertFailedCoreStillStopped={
    $null=Get-FailedCoreObservation $root
    $script:stages+='admit-auto'
}
$policy=[pscustomobject]@{}
$policy | Add-Member -MemberType ScriptMethod -Name MarkQuiescent -Value {}
$oldBridge=[pscustomobject]@{Policy=$policy;Role='old'}
$bridge=[pscustomobject]@{Role='successor'}
function Invoke-InstallerHelper { param($Bridge,$Phase)
    if($Phase -ne 'prepare'){throw 'bad native prepare'}
    if($Bridge.Role -eq 'old'){
        if($script:scm.StartMode -eq 'Disabled'){
            if($script:stages[-1] -ne 'old-owned-quarantine'){throw 'native recovery prepare without old ownership'}
            $script:stages+='old-authenticated-prepare'
        } else {
            if($script:scm.StartMode -ne 'Auto' -or ($script:stages -join ',') -ne 'admit-auto'){throw 'missing final Auto check before old prepare'}
            $script:scm.StartMode='Disabled'
            $script:stages+='old-owned-quarantine'
        }
    } else {
        if($script:scm.StartMode -ne 'Disabled'){throw 'successor lacks old quarantine'}
        $script:stages+='successor-prepare'
    }
}
function Start-WindowsInstaller { $script:stages+='start-installer' }
function Invoke-CompoundFoundationUpgrade {
    if($script:scm.StartMode -ne 'Disabled' -or !$nativeStarted){throw 'missing native quarantine'}
    $script:stages+='native'
}
$compoundDetails=@{}
$manifest=@{product_code='test'}
foreach($step in $old){Invoke-Expression $step.Groups['code'].Value}
Invoke-Expression $successor.Groups['code'].Value
Invoke-Expression ($dispatch.Groups['code'].Value + [Environment]::NewLine + '}')
if(($script:stages -join ',') -ne 'admit-auto,old-owned-quarantine,old-authenticated-prepare,successor-prepare,start-installer,native'){throw 'native transition order'}
""", encoding="utf-8")
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-File", str(harness),
         str(SCRIPT.with_name("Install-EndpointAgentCanary.ps1"))],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
