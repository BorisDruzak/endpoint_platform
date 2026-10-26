"""Trial deadline cleanup uses real owned workers, never mutating/native peers."""
import os
from pathlib import Path
import subprocess

import pytest


_HARNESS = r'''param($Source,$Case)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'source parse failure'}
foreach($name in @('Initialize-InstallerBridgeTypes','Invoke-InstallerOwnerPump',
 'Invoke-StagedHealthTrial','Get-StagedMonotonicSeconds','Assert-InstallerPumpDeadline',
 'Complete-StagedTrialHelperFailure','Assert-InstallerWarmLaunchReply','Start-InstallerWarmPhase')){
 $node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
 if($node){Invoke-Expression $node.Extent.Text}
}
Initialize-InstallerBridgeTypes
$exe=Join-Path $PSHOME 'powershell.exe'
$hash=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
$global:workers=[Collections.Generic.List[Diagnostics.Process]]::new()
function New-Worker {
 $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Start-Sleep -Seconds 60'))
 $p=Start-Process -FilePath $exe -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',$encoded) -WindowStyle Hidden -PassThru
 $handle=$p.Handle
 $global:workers.Add($p)
 return $p
}
$worker=New-Worker
$native=[EndpointInstallerBridge.NativeProcess]::new($worker.Id)
$owner=[EndpointInstallerBridge.NativeProcess]::new($PID)
$policy=[pscustomobject]@{Lost=$false}
$policy|Add-Member ScriptMethod OwnerLost {$this.Lost=$true}
$bridge=@{HelperHash=$hash;HelperPath=$exe;Owner=$owner;Policy=$policy;Peers=@();
 SessionId=[Guid]::NewGuid().ToString('D');TransactionId=[Guid]::NewGuid().ToString('D');LaunchDirectory=$PWD.Path}
try {
 if($Case -in @('readonly-boundary','mutating-begin-boundary')){
  # The real phase starts just before the 180s boundary; its pump sees time
  # just after it. Only the clock/conversation transport is controlled here.
  $global:clockCalls=0;$global:acceptCalls=0
  function Get-StagedMonotonicSeconds {
   $global:clockCalls++
   if($global:clockCalls -eq 1){return 0.0}
   if($global:clockCalls -eq 2){return 179.999}
   return 180.001
  }
  function New-InstallerConversation {return [pscustomobject]@{}}
  function Invoke-InstallerConversationStep {return $false}
  $channel=[pscustomobject]@{}
  $channel|Add-Member ScriptMethod WaitForActivity {param($ms)}
  $bridge.Channel=$channel
  function Start-VerifiedTrialServices {}
  function Invoke-InstallerHelper {
   param($Bridge,$Phase)
   if($Phase -eq 'accept-staged-trial'){$global:acceptCalls++;throw 'accept after deadline'}
   if($Phase -eq 'begin-staged-trial' -and $Case -eq 'readonly-boundary'){
    return [pscustomobject]@{result='staged-trial';operation_id=$Bridge.TransactionId;attempt_id=[Guid]::NewGuid().ToString('D')}
   }
   return Invoke-InstallerOwnerPump -Bridge $Bridge -Process $worker -Phase $Phase
  }
  $failure=$null;$decision=$null
  try{$decision=Invoke-StagedHealthTrial -Bridge $bridge -InstallRoot 'C:\fixture'}catch{$failure=$_.Exception.Message}
  $worker.Refresh()
  if($Case -eq 'mutating-begin-boundary'){
   if($failure -notlike '*RECOVERY_REQUIRED*' -or $worker.HasExited -or !$bridge.StagedHelperUnsettled){throw 'mutating helper killed or concurrent rollback admitted'}
  }else{
   if($failure -or $decision -cne 'rollback'){throw 'deadline did not request rollback'}
   if(!$worker.HasExited){throw 'timed-out read-only worker remains alive'}
   # Exercise the real next warm-launch function with a genuine next child.
   # The transport has the production broker's no-live-previous-child rule.
   $broker=@{Owner=$owner;Peer=$owner;Sequence=0;HelperHash=$hash;HelperPath=$exe;
    TransactionId=$bridge.TransactionId;LaunchDirectory=$PWD.Path;Previous=$worker}
   function Assert-ExistingPathChain {}
   function Assert-InstallerCacheProtection {}
   function Send-InstallerBridgePacket {
    param($Broker,$Packet)
    $Broker.Previous.Refresh()
    if(!$Broker.Previous.HasExited){throw 'WARM_BROKER_BUSY'}
    $next=New-Worker
    $nextIdentity=[EndpointInstallerBridge.NativeProcess]::new($next.Id)
    try{$global:reply=[pscustomobject]@{sequence=[int]$Packet.sequence;pid=[int]$next.Id;created=[long]$nextIdentity.Identity.Created}}finally{$nextIdentity.Dispose()}
   }
   function Receive-InstallerLaunchPacket {return $global:reply}
   $next=Start-InstallerWarmPhase -Broker $broker -Bridge $bridge -Phase 'inspect-staged-state'
   try{if($next.HasExited){throw 'next warm request did not launch a live child'}}finally{$next.Dispose()}
  }
  if($bridge.ContainsKey('StagedDeadline') -or $global:acceptCalls){throw 'deadline retained or acceptance extended by cleanup'}
 }else{
  $phase='observe-staged-trial';$msi=$false;$candidate=$native
  switch($Case){
   'mutating-accept'{$phase='accept-staged-trial'}
   'mutating-begin'{$phase='begin-staged-trial'}
   'native-msi'{$msi=$true}
   'wrong-hash'{$bridge.HelperHash='b'*64}
   'wrong-image'{$bridge.HelperPath='C:\foreign\helper.exe'}
   'wrong-pid'{$foreign=New-Worker;$candidate=[EndpointInstallerBridge.NativeProcess]::new($foreign.Id)}
   'wrong-creation'{
    $candidate=[pscustomobject]@{Alive=$true;ImagePath=$native.ImagePath;
     Identity=[pscustomobject]@{Pid=$native.Identity.Pid;Created=($native.Identity.Created+1);Hash=$native.Identity.Hash;Sid=$native.Identity.Sid;Elevated=$native.Identity.Elevated}}
   }
  }
  try{$settled=Complete-StagedTrialHelperFailure -Bridge $bridge -Process $worker -Launched $candidate -Phase $phase -Msi:$msi}finally{if($Case -eq 'wrong-pid'){$candidate.Dispose()}}
  $worker.Refresh()
  if($settled -or $worker.HasExited){throw 'mutating/native or mismatched worker was force-terminated'}
 }
 Write-Output 'passed'
}finally{
 $native.Dispose();$owner.Dispose()
 foreach($p in $global:workers){try{if(!$p.HasExited){$p.Kill();$p.WaitForExit(5000)|Out-Null}}finally{$p.Dispose()}}
}
'''


@pytest.mark.skipif(os.name != "nt", reason="real Windows process identity and cleanup")
@pytest.mark.parametrize("case", [
    "readonly-boundary", "mutating-begin-boundary", "mutating-accept",
    "mutating-begin", "native-msi", "wrong-hash", "wrong-image",
    "wrong-pid", "wrong-creation",
])
def test_trial_cleanup_preserves_owned_worker_and_mutation_boundaries(tmp_path, case):
    source = Path(__file__).resolve().parents[2] / "packaging/windows/Install-EndpointAgentCanary.ps1"
    script = tmp_path / "trial-cleanup.ps1"
    script.write_text(_HARNESS, encoding="utf-8")
    environment = dict(os.environ)
    environment["PSModulePath"] = str(
        Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/Modules"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(script), str(source), case],
        capture_output=True, text=True, timeout=35, env=environment,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "passed"
