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
