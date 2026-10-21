"""Compiled reverse policy must never become a general downgrade capability."""
import os
from pathlib import Path
import subprocess
import pytest


@pytest.mark.skipif(os.name != 'nt', reason='compiled Windows owner policy')
@pytest.mark.parametrize('case', ['valid', 'valid-legacy', 'unprepared-control', 'arbitrary-legacy', 'same-package', 'wrong-owner'])
def test_reverse_policy_preconditions_and_dynamic_restoration(tmp_path, case):
    source = Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'reverse-policy.ps1'
    script.write_text(r'''param($Source,$Case)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $node.Extent.Text;Initialize-InstallerBridgeTypes
function Reject([scriptblock]$Action){$denied=$false;try{& $Action|Out-Null}catch{$denied=$true};if(!$denied){throw 'unsafe reverse admission'}}
$owner=[EndpointInstallerBridge.Identity]::new(100,1000,('a'*64),'S-1-5-18',$true)
$other=[EndpointInstallerBridge.Identity]::new(101,1001,('a'*64),'S-1-5-18',$true)
function Policy($Transaction,$Session,$Package,$Helper,$Identity){
 $p=[EndpointInstallerBridge.Policy]::new($Transaction,$Session,$Package,'install',$Identity,$Helper,[byte[]](1..32))
 $p.MarkQuiescent();return $p
}
function Complete($Policy,$Phase,$PeerId,$Helper){
 $peer=[EndpointInstallerBridge.Identity]::new($PeerId,($PeerId*10),$Helper,'S-1-5-18',$true)
 $Policy.RegisterHelper($peer,$Phase)
 foreach($action in @('begin','mutation','complete')){
  $grant=$Policy.Issue($peer,$Phase,$action,('f'*64),$Policy.SessionId)
  $Policy.Accept($peer,$grant,$Policy.Sign('request',$grant))|Out-Null
 }
 $Policy.MarkHelperExited($peer,0)
}
$control=Policy '11111111-1111-4111-8111-111111111111' '22222222-2222-4222-8222-222222222222' ('c'*64) ('b'*64) $owner
if($Case -ne 'unprepared-control'){Complete $control 'prepare-foundation-rollback' 200 ('b'*64)}
if($Case -eq 'unprepared-control'){Reject {$control.AuthorizeStagedReversePlan(('f'*64),('d'*64),('e'*64))}}
elseif($Case -eq 'arbitrary-legacy'){Reject {$control.AuthorizeStagedReversePlan(('f'*64),('d'*64),$null)}}
elseif($Case -eq 'same-package'){Reject {$control.AuthorizeStagedReversePlan(('f'*64),('c'*64),('e'*64))}}
else{
 if($Case -eq 'valid-legacy'){$control.AuthorizeStagedReversePlan(('f'*64),'2f7d778799f1e32645af7936dfaf3f090d6ad4df5bb883827ea8a0a5d859f72a',$null)}
 else{$control.AuthorizeStagedReversePlan(('f'*64),('d'*64),('e'*64))}
 $removal=[EndpointInstallerBridge.Policy]::new('33333333-3333-4333-8333-333333333333','44444444-4444-4444-8444-444444444444',('c'*64),'uninstall',$owner,('b'*64),[byte[]](1..32))
 $removal.MarkQuiescent();Complete $removal 'prepare' 201 ('b'*64)
 $restore=if($Case -eq 'valid-legacy'){$null}else{Policy '55555555-5555-4555-8555-555555555555' '66666666-6666-4666-8666-666666666666' ('d'*64) ('e'*64) $(if($Case -eq 'wrong-owner'){$other}else{$owner})}
 if($Case -eq 'wrong-owner'){Reject {[EndpointInstallerBridge.StagedRollbackPolicy]::new($control,$removal,$restore)}}
 else{
  $policy=[EndpointInstallerBridge.StagedRollbackPolicy]::new($control,$removal,$restore)
  if($policy.State -cne 'prepared'){throw 'wrong reverse phase'}
  $failure=$null
  try{[EndpointInstallerBridge.NativeTransaction]::new($policy,$null,$null,$null,'{AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA}')|Out-Null}catch{$failure=$_.Exception.ToString()}
  if(!$failure -or !$failure.Contains('OWNER_AUTH_FAILED')){throw 'reverse driver did not enforce physical ownership'}
  if($null -ne $restore){Reject {$restore.RegisterHelper(([EndpointInstallerBridge.Identity]::new(202,2020,('e'*64),'S-1-5-18',$true)),'prepare')}}
  Reject {$policy.BeginRestorationScript()}
  $policy.BeginNative();Reject {$policy.BeginRestorationScript()}
  $policy.OwnerLost();Reject {$policy.BeginRemovalScript()}
 }
}
'passed'
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source), case],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'


@pytest.mark.skipif(os.name != 'nt', reason='actual owner orchestration')
def test_lost_trial_reply_does_not_stop_durable_accepted_candidate(tmp_path):
    source = Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'accepted-owner.ps1'
    script.write_text(r'''param($Source)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-StagedFoundationRollback'},$true)
if(!$node){throw 'missing reverse owner'}
Invoke-Expression $node.Extent.Text
$resource=[pscustomobject]@{};$resource|Add-Member ScriptMethod Dispose {}
$policy=[pscustomobject]@{};$policy|Add-Member ScriptMethod OwnerLost {}
$script:phases=@()
function New-InstallerBridge {return @{TransactionId='11111111-1111-4111-8111-111111111111';Policy=$policy;Channel=$resource;Owner=$resource;Peers=@()}}
function Invoke-InstallerHelper {param($Bridge,$Phase)
 $script:phases+=$Phase
 if($Phase -cne 'inspect-staged-state'){throw 'accepted candidate modified'}
 return [pscustomobject]@{operation_id=$Bridge.TransactionId;phase='accepted'}
}
function Stop-ManagedAgentServices {throw 'accepted candidate stopped'}
$result=Invoke-StagedFoundationRollback -Manifest @{} -HelperPath 'helper' -HelperHash ('a'*64) -StateRoot 'state' -CacheRoot 'cache' -ServiceStates @{} -Selection ([pscustomobject]@{foundation_release=@{package_sha256=('b'*64)}}) -CandidateMedia $null -OperationId '11111111-1111-4111-8111-111111111111' -InstallRoot 'install'
if($result -cne 'accepted' -or [string]::Join(',',$script:phases) -cne 'inspect-staged-state'){throw 'accepted authority lost'}
'passed'
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'
