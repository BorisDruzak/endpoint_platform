"""Exercise the real owner-thread policy's two-package commit boundary."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.skipif(os.name != 'nt', reason='compiled native owner policy')
@pytest.mark.parametrize('case', ['pending', 'cross-helper', 'double-script', 'early-end',
    'commit', 'reboot', 'owner-loss', 'owner-binding', 'missing-commit', 'rollback',
    'old-recovery', 'new-recovery', 'old-finalization', 'new-finalization',
    'bound-old-recovery', 'bound-new-recovery', 'bound-old-finalization', 'bound-new-finalization',
    'unrecorded-old', 'unrecorded-new', 'early-retire', 'boundary-replay',
    'recovery-commit','recovery-flag-loss','partial-recovery',
    'successor-repair','repair-flag-loss','repair-reboot'])
def test_compound_owner_policy(tmp_path, case):
    source = Path(__file__).resolve().parents[3]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path/'compound-policy.ps1'
    script.write_text(r'''param($Source,$Case)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'source parse failed'}
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $node.Extent.Text
Initialize-InstallerBridgeTypes
function Identity($id,$hash,$sid='S-1-5-18'){
 [EndpointInstallerBridge.Identity]::new($id,([long]$id*10),$hash,$sid,$true)
}
function Reject([scriptblock]$action){$failed=$false;try{& $action|Out-Null}catch{$failed=$true};if(!$failed){throw 'unsafe transition accepted'}}
function Admit($policy,$peer,$phase,$action='begin'){
 $challenge=$policy.Issue($peer,$phase,$action,('9'*64),$policy.SessionId)
 $policy.Accept($peer,$challenge,$policy.Sign('request',$challenge))|Out-Null
}
$owner=Identity 100 ('a'*64)
$old=[EndpointInstallerBridge.Policy]::new('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222',('c'*64),'uninstall',$owner,('b'*64),[byte[]](1..32))
$new=[EndpointInstallerBridge.Policy]::new('33333333-3333-4333-8333-333333333333','44444444-4444-4444-8444-444444444444',('e'*64),'install',$owner,('f'*64),[byte[]](33..64))
if($Case.StartsWith('recovery-')){$old.Recovery=$true;$new.Recovery=$true}
if($Case -eq 'partial-recovery'){$new.Recovery=$true}
if($Case -in @('successor-repair','repair-flag-loss','repair-reboot')){$new.Recovery=$true}
foreach($policy in @($old,$new)){
 $policy.MarkQuiescent();$helper=Identity $(if($policy -eq $old){200}else{201}) $policy.HelperHash
 $policy.RegisterHelper($helper,'prepare');Admit $policy $helper 'prepare';Admit $policy $helper 'prepare' 'complete'
}
if($Case -in @('old-recovery','new-recovery','old-finalization','new-finalization')){
 $policy=$(if($Case.StartsWith('old-')){$old}else{$new})
 if($Case.EndsWith('recovery')){$policy.Recovery=$true}else{$policy.UninstallFinalization=$true}
 Reject {[EndpointInstallerBridge.CompoundPolicy]::new($old,$new)}
 Write-Output 'passed';exit
}
if($Case -in @('successor-repair','repair-flag-loss','repair-reboot')){
 $repair=[EndpointInstallerBridge.SuccessorRepairPolicy]::new($new,$old.PackageHash)
 $repair.BeginNative();$repair.BeginScript()
 if($Case -eq 'repair-flag-loss'){
  $new.Recovery=$false;Reject {$new.Issue((Identity 210 ('f'*64)),'msi-preflight','begin',('9'*64),$new.SessionId)}
  Write-Output 'passed';exit
 }
 foreach($phase in @('msi-preflight','recover-enter','foundation-config')){
  $id=@{'msi-preflight'=212;'recover-enter'=213;'foundation-config'=214}[$phase]
  $peer=Identity $id ('f'*64);Admit $new $peer $phase;Admit $new $peer $phase 'complete'
 }
 if($Case -eq 'repair-reboot'){Reject {$repair.ScriptReturned(3010)};Reject {$new.RegisterHelper((Identity 230 ('f'*64)),'compound-retire')};Write-Output 'passed';exit}
 $repair.ScriptReturned(0)
 Reject {$new.RegisterHelper((Identity 230 ('f'*64)),'compound-retire')}
 function RepairRecord($phase,$id){$peer=Identity $id ('f'*64);$new.RegisterHelper($peer,$phase);Admit $new $peer $phase;Admit $new $peer $phase 'complete'}
 Reject {$repair.BeginEnd($true)}
 RepairRecord 'compound-repair-returned' 231
 $repair.BeginEnd($true)
 $peer=Identity 215 ('f'*64);Admit $new $peer 'msi-complete';Admit $new $peer 'msi-complete' 'complete'
 $repair.EndReturned(0)
 foreach($phase in @('compound-repair-commit','compound-retire','reconcile','finish','compound-complete')){
  $id=@{'compound-repair-commit'=232;'compound-retire'=233;'reconcile'=234;'finish'=235;'compound-complete'=236}[$phase]
  RepairRecord $phase $id
 }
 if($old.NativeEntered -or $old.NativeComplete -or !$repair.ReadyToPublish){throw 'repair fabricated old scope or missed real new completion'}
 Write-Output 'passed';exit
}
if($Case -eq 'partial-recovery'){
 Reject {[EndpointInstallerBridge.CompoundPolicy]::CreateRecovery($old,$new)}
 Write-Output 'passed';exit
}
if($Case.StartsWith('recovery-')){$compound=[EndpointInstallerBridge.CompoundPolicy]::CreateRecovery($old,$new)}
else{$compound=[EndpointInstallerBridge.CompoundPolicy]::new($old,$new)}
function Record($phase,$id){
 $peer=Identity $id ('f'*64);$new.RegisterHelper($peer,$phase)
 Admit $new $peer $phase;Admit $new $peer $phase 'complete'
}
if($Case.StartsWith('bound-')){
 $compound.BeginNative();$compound.BeginOldScript()
 $policy=$(if($Case.StartsWith('bound-old-')){$old}else{$new})
 if($Case.EndsWith('recovery')){$policy.Recovery=$true}else{$policy.UninstallFinalization=$true}
 Reject {$compound.BeginEnd($false)}
 Reject {$old.Issue((Identity 210 ('b'*64)),'msi-preflight','begin',('9'*64),$old.SessionId)}
 Reject {$new.RegisterHelper((Identity 219 ('f'*64)),'finish')}
 Write-Output 'passed';exit
}
function Old-Script{
 $compound.BeginOldScript()
 $preflight=Identity 210 ('b'*64);Admit $old $preflight 'msi-preflight';Admit $old $preflight 'msi-preflight' 'complete'
 $enter=Identity 211 ('b'*64);$phase=$(if($old.Recovery){'recover-enter'}else{'msi-enter'});Admit $old $enter $phase;Admit $old $enter $phase 'complete'
 $compound.OldScriptReturned(0)
 if($Case -ne 'unrecorded-old'){Record 'compound-old-returned' 230}
}
function New-Script{
 $compound.BeginNewScript()
 foreach($phase in @('msi-preflight',$(if($new.Recovery){'recover-enter'}else{'msi-enter'}),'foundation-config')){
  $id=@{'msi-preflight'=212;'msi-enter'=213;'recover-enter'=213;'foundation-config'=214}[$phase]
  $peer=Identity $id ('f'*64);Admit $new $peer $phase;Admit $new $peer $phase 'complete'
 }
 $compound.NewScriptReturned(0)
 if($Case -ne 'unrecorded-new'){Record 'compound-new-returned' 231}
}
function Complete-Native{
 $compound.BeginEnd($true)
 $peer=Identity 215 ('b'*64);Admit $old $peer 'msi-complete';Admit $old $peer 'msi-complete' 'complete'
 $peer=Identity 216 ('f'*64);Admit $new $peer 'msi-complete';Admit $new $peer 'msi-complete' 'complete'
 $compound.EndReturned(0)
}
switch($Case){
 'recovery-commit'{$compound.BeginNative();Old-Script;New-Script;Complete-Native;if(!$compound.Committed){throw 'recovery commit absent'};Record 'compound-commit' 232;Record 'compound-retire' 233}
 'recovery-flag-loss'{$compound.BeginNative();$compound.BeginOldScript();$new.Recovery=$false;Reject {$old.Issue((Identity 210 ('b'*64)),'msi-preflight','begin',('9'*64),$old.SessionId)};Reject {$compound.BeginEnd($false)}}
 'unrecorded-old'{$compound.BeginNative();Old-Script;Reject {$compound.BeginNewScript()}}
 'unrecorded-new'{$compound.BeginNative();Old-Script;New-Script;Reject {$compound.BeginEnd($true)}}
 'early-retire'{$compound.BeginNative();Old-Script;New-Script;Reject {$new.RegisterHelper((Identity 240 ('f'*64)),'compound-retire')}}
 'boundary-replay'{$compound.BeginNative();Old-Script;Reject {$new.RegisterHelper((Identity 240 ('f'*64)),'compound-old-returned')}}
 'owner-binding'{
  $other=[EndpointInstallerBridge.Policy]::new('55555555-5555-4555-8555-555555555555','66666666-6666-4666-8666-666666666666',('6'*64),'install',(Identity 101 ('a'*64)),('7'*64),[byte[]](1..32))
  Reject {[EndpointInstallerBridge.CompoundPolicy]::new($old,$other)}
 }
 'early-end'{$compound.BeginNative();Reject {$compound.BeginEnd($true)}}
 'owner-loss'{$compound.BeginNative();Old-Script;$compound.OwnerLost();Reject {$compound.BeginNewScript()};Reject {$new.Issue((Identity 217 ('f'*64)),'msi-preflight','begin',('9'*64),$new.SessionId)}}
 'cross-helper'{$compound.BeginNative();$compound.BeginOldScript();Reject {$old.Issue((Identity 217 ('f'*64)),'msi-preflight','begin',('9'*64),$old.SessionId)};Reject {$new.Issue((Identity 218 ('b'*64)),'msi-preflight','begin',('9'*64),$new.SessionId)}}
 'double-script'{$compound.BeginNative();Old-Script;Reject {$compound.BeginOldScript()};New-Script;Reject {$compound.BeginNewScript()}}
 'pending'{$compound.BeginNative();Old-Script;New-Script;Reject {$new.RegisterHelper((Identity 219 ('f'*64)),'finish')};Reject {$old.Issue((Identity 220 ('b'*64)),'msi-complete','begin',('9'*64),$old.SessionId)}}
 'reboot'{$compound.BeginNative();$compound.BeginOldScript();Reject {$compound.OldScriptReturned(3010)};Reject {$compound.BeginNewScript()}}
 'missing-commit'{$compound.BeginNative();Old-Script;New-Script;$compound.BeginEnd($true);Reject {$compound.EndReturned(0)};Reject {$new.RegisterHelper((Identity 219 ('f'*64)),'finish')}}
 'rollback'{$compound.BeginNative();Old-Script;$compound.BeginNewScript();$compound.NewScriptReturned(1603);$compound.BeginEnd($false);$compound.EndReturned(0);Reject {$new.RegisterHelper((Identity 219 ('f'*64)),'finish')};if($compound.Committed){throw 'rollback claimed commit'}}
 'commit'{$compound.BeginNative();Old-Script;New-Script;Complete-Native;if(!$compound.Committed){throw 'commit absent'};Reject {$new.RegisterHelper((Identity 219 ('f'*64)),'reconcile')};Record 'compound-commit' 232;Record 'compound-retire' 233;$new.RegisterHelper((Identity 219 ('f'*64)),'reconcile');Reject {$old.RegisterHelper((Identity 220 ('b'*64)),'reconcile')}}
}
Write-Output 'passed'
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source),case], capture_output=True,text=True,timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'
