"""Real PowerShell JSON shapes and completed-forward recovery boundaries."""
import os
from pathlib import Path
import subprocess

import pytest


SOURCE = Path(__file__).resolve().parents[3] / "packaging/windows/Install-EndpointAgentCanary.ps1"


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell orchestration")
@pytest.mark.parametrize("case", ["trial", "prepared", "switching", "foreign-fence", "json-services"])
def test_recovery_uses_actual_json_and_lifecycle_shapes(tmp_path, case):
    script = tmp_path / "recovery-roundtrip.ps1"
    script.write_text(r'''param($Source,$Case)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
foreach($name in @('Get-StagedForwardRecoveryLocator','ConvertTo-StagedServiceStates','Invoke-StagedRecovery')){
 $node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 if(!$node){throw ('missing '+$name)};Invoke-Expression $node.Extent.Text
}
if($Case -eq 'json-services'){
 Add-Type 'namespace EndpointInstallerBridge {public static class NativeTransaction {public static object EstablishSettlement(object owner){return new object();}}}'
 $policy=[pscustomobject]@{};$policy|Add-Member ScriptMethod AuthorizeStagedRecovery {}; $policy|Add-Member ScriptMethod MarkQuiescent {}
 $bridge=@{Owner=[pscustomobject]@{};Policy=$policy};$script:operation='11111111-1111-4111-8111-111111111111'
 function Invoke-InstallerHelper {param($Bridge,$Phase)
  if($Phase -eq 'inspect-staged-recovery'){return ('{"operation_id":"'+$script:operation+'","service_states":{"EndpointAgent":"Running","EndpointAgentUpdater":"Stopped","EndpointBrowserPolicy":"Running"},"old_release":{}}'|ConvertFrom-Json)}
  if($Phase -eq 'recover-staged-owner'){return [pscustomobject]@{operation_id=$script:operation;action='rollback-required'}}
  throw 'unexpected helper'
 }
 function Get-ManagedAgentServiceStates {return @{EndpointAgent='Stopped';EndpointAgentUpdater='Stopped';EndpointBrowserPolicy='Stopped'}}
 function Stop-ManagedAgentServices {}
 function Invoke-StagedFoundationRollback {param([hashtable]$ServiceStates)
  if($ServiceStates.Count -ne 3 -or $ServiceStates.EndpointAgent -cne 'Running'){throw 'lost original service states'}
  return 'rolled-back'
 }
 function Complete-StagedTerminalCleanup {param($Bridge,[hashtable]$ServiceStates,$StateRoot);if($ServiceStates.EndpointAgent -cne 'Running'){throw 'lost cleanup states'}}
 $result=Invoke-StagedRecovery -Bridge $bridge -Manifest @{} -HelperPath 'helper' -HelperHash ('a'*64) -StateRoot 'state' -CacheRoot 'cache' -OperationId $script:operation -InstallRoot 'install' -CandidateMedia $null
 if($result -ne 67){throw 'rollback lost'}
}else{
 $script:reads=0
 function Read-CompoundRecoveryLocator {param($Root,$Manifest);$script:reads++;return @{locator=$true}}
 $phase=if($Case -eq 'foreign-fence'){'trial'}else{$Case}
 $fence=if($Case -eq 'foreign-fence'){@{foreign=$true}}else{$null}
 if($Case -eq 'foreign-fence'){
  $denied=$false;try{Get-StagedForwardRecoveryLocator -Phase $phase -Fence $fence -Root 'state' -Manifest @{}|Out-Null}catch{$denied=$true};if(!$denied){throw 'foreign native fence admitted'}
 }else{
  $result=Get-StagedForwardRecoveryLocator -Phase $phase -Fence $fence -Root 'state' -Manifest @{}
  if($phase -eq 'switching'){if($null -eq $result -or $script:reads -ne 1){throw 'unfinished native recovery lost'}}
  elseif($null -ne $result -or $script:reads -ne 0){throw 'historical compound marker treated as unfinished'}
 }
}
'passed'
''', encoding="utf-8")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(script), str(SOURCE), case], capture_output=True, text=True, timeout=40)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "passed"


@pytest.mark.skipif(os.name != "nt", reason="real wrapper entry guard")
@pytest.mark.parametrize('operation,expected', [('RecoverStagedUpdate', 0), ('RecoverInterruptedInstall', 0), ('Install', 61)])
def test_wrapper_classifies_staged_fence_before_rejecting_foreign_native(tmp_path, operation, expected):
    script = tmp_path / 'entry.ps1'
    script.write_text(r'''param($Source,$Operation)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$nodes=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -like '*interruptedFence*Operation*RecoverInterruptedInstall*' -and $n.Extent.Text -match 'exit 61' -and $n.Extent.Text -notmatch 'recoveryLocator'},$true))
if($nodes.Count -ne 1){throw 'entry guard not identified'}
$interruptedFence=@{surviving=$true}
Invoke-Expression $nodes[0].Extent.Text
'passed'
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(SOURCE), operation], capture_output=True, text=True, timeout=30)
    assert result.returncode == expected, result.stderr


@pytest.mark.skipif(os.name != 'nt', reason='actual terminal recovery orchestration')
@pytest.mark.parametrize('outcome', ['restored', 'unavailable'])
def test_terminal_recovery_restores_agent_before_removing_task(tmp_path, outcome):
    script = tmp_path / 'terminal.ps1'
    script.write_text(r'''param($Source,$Outcome)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
foreach($name in @('ConvertTo-StagedServiceStates','Invoke-StagedRecovery','Complete-StagedTerminalCleanup')){
 $node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true);Invoke-Expression $node.Extent.Text
}
Add-Type 'namespace EndpointInstallerBridge {public static class NativeTransaction {public static object EstablishSettlement(object owner){return new object();}}}'
$script:operation='11111111-1111-4111-8111-111111111111';$script:agent=$false;$script:removed=$false;$script:failure=($Outcome -eq 'unavailable')
$policy=[pscustomobject]@{};$policy|Add-Member ScriptMethod AuthorizeStagedRecovery {}; $bridge=@{Owner=[pscustomobject]@{};Policy=$policy;TransactionId=$script:operation}
function Invoke-InstallerHelper {param($Bridge,$Phase)
 switch($Phase){
  'inspect-staged-recovery' {return [pscustomobject]@{operation_id=$script:operation;service_states=([pscustomobject]@{EndpointAgent='Running';EndpointAgentUpdater='Stopped';EndpointBrowserPolicy='Running'})}}
  'recover-staged-owner' {return [pscustomobject]@{operation_id=$script:operation;action='preparation-cancelled'}}
  'restore-staged-companions' {return [pscustomobject]@{services=([pscustomobject]@{EndpointAgent=$(if($script:agent){'running'}else{'not-running'});EndpointAgentUpdater='not-required';EndpointBrowserPolicy='running'});users='session-unavailable'}}
  default {throw 'unexpected helper'}
 }
}
function Start-VerifiedBrowserPolicy {}
function Start-ManagedEndpointAgent {if(!$script:failure){$script:agent=$true}}
function Remove-StagedRecoveryTask {if(!$script:agent){throw 'task removed before Agent restoration'};$script:removed=$true}
$failed=$false;try{$result=Invoke-StagedRecovery -Bridge $bridge -Manifest @{} -HelperPath 'helper' -HelperHash ('a'*64) -StateRoot 'state' -CacheRoot 'cache' -OperationId $script:operation -InstallRoot 'install' -CandidateMedia $null}catch{$failed=$true}
if($script:failure){if(!$failed -or $script:removed){throw 'unavailable Agent lost recovery mechanism'}}
elseif($failed -or !$script:agent -or !$script:removed -or $result -ne 67){throw 'terminal recovery failed to restore required services'}
'passed'
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(SOURCE), outcome], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == 'passed'
