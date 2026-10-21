"""The real PowerShell trial loop must retain monotonic owner-side deadlines."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.skipif(os.name != 'nt', reason='actual PowerShell owner loop')
@pytest.mark.parametrize('scenario', ['accept', 'no-proof', 'crash', 'reconnect'])
def test_owner_trial_window_and_deadline(tmp_path, scenario):
    source = Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'trial-owner.ps1'
    script.write_text(r'''param($Source,$Scenario)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parser errors'}
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-StagedHealthTrial'},$true)
if(!$node){throw 'missing trial loop'}
Invoke-Expression $node.Extent.Text
$script:now=0;$script:accepted=$false
function Get-StagedMonotonicSeconds {return $script:now}
function Start-Sleep {param($Seconds);$script:now+=$Seconds}
function Start-VerifiedBrowserPolicy { }
function Start-ManagedEndpointAgent { }
function Assert-StagedCandidateRunning {param($Observation,$InstallRoot)
 if($Scenario -eq 'crash' -and $script:now -ge 12){throw 'candidate stopped'}
}
function Invoke-InstallerHelper {param($Bridge,$Phase)
 if($Phase -eq 'begin-staged-trial'){return [pscustomobject]@{result='staged-trial';operation_id=$Bridge.TransactionId;attempt_id='33333333-3333-4333-8333-333333333333'}}
 if($Phase -eq 'accept-staged-trial'){$script:accepted=$true;return [pscustomobject]@{result='staged-accepted';operation_id=$Bridge.TransactionId;attempt_id='33333333-3333-4333-8333-333333333333'}}
 if($Phase -ne 'observe-staged-trial'){throw 'unexpected phase'}
 $nonce=if($Scenario -eq 'no-proof'){$null}elseif($Scenario -eq 'reconnect' -and $script:now -ge 45){'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'}else{'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'}
 return [pscustomobject]@{result='staged-observation';operation_id=$Bridge.TransactionId;attempt_id='33333333-3333-4333-8333-333333333333';decision='accept';connection_nonce=$nonce;pid=10;candidate_version='3.2.999'}
}
$bridge=@{TransactionId='11111111-1111-4111-8111-111111111111'}
$result=Invoke-StagedHealthTrial -Bridge $bridge -InstallRoot 'fixed-root'
if($Scenario -eq 'accept'){
 if($result -cne 'accepted' -or !$script:accepted -or $script:now -lt 60 -or $script:now -gt 63){throw 'short trial'}
}elseif($Scenario -eq 'reconnect'){
 if($result -cne 'accepted' -or !$script:accepted -or $script:now -lt 105){throw 'nonce did not reset stable timer'}
}else{
 if($result -cne 'rollback' -or $script:accepted){throw 'failed trial accepted'}
 if($Scenario -eq 'no-proof' -and $script:now -ne 180){throw 'deadline changed'}
 if($Scenario -eq 'crash' -and $script:now -ge 60){throw 'crash ignored'}
}
'passed'
''', encoding='utf-8')
    completed = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script),
                                str(source), scenario], capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == 'passed'


@pytest.mark.skipif(os.name != 'nt', reason='actual compiled capability policy')
def test_trial_policy_grants_no_native_or_observation_mutation(tmp_path):
    source = Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'trial-policy.ps1'
    script.write_text(r'''param($Source)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $node.Extent.Text;Initialize-InstallerBridgeTypes
function Reject([scriptblock]$Action){$denied=$false;try{& $Action|Out-Null}catch{$denied=$true};if(!$denied){throw 'unsafe trial policy'}}
$owner=[EndpointInstallerBridge.Identity]::new(100,1000,('a'*64),'S-1-5-18',$true)
$peer=[EndpointInstallerBridge.Identity]::new(200,2000,('b'*64),'S-1-5-18',$true)
$policy=[EndpointInstallerBridge.Policy]::new('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222',('c'*64),'install',$owner,('b'*64),[byte[]](1..32))
Reject {$policy.RegisterHelper($peer,'begin-staged-trial')}
$policy.MarkQuiescent();$policy.RegisterHelper($peer,'begin-staged-trial')
foreach($action in @('begin','mutation','complete')){
 $grant=$policy.Issue($peer,'begin-staged-trial',$action,('d'*64),$policy.SessionId)
 $policy.Accept($peer,$grant,$policy.Sign('request',$grant))|Out-Null
}
$policy.MarkHelperExited($peer,0)
Reject {$policy.RegisterMsi($peer,'install')}
$observer=[EndpointInstallerBridge.Identity]::new(201,2001,('b'*64),'S-1-5-18',$true)
$policy.RegisterHelper($observer,'observe-staged-trial')
$grant=$policy.Issue($observer,'observe-staged-trial','begin',('d'*64),$policy.SessionId)
$policy.Accept($observer,$grant,$policy.Sign('request',$grant))|Out-Null
Reject {$policy.Issue($observer,'observe-staged-trial','mutation',('d'*64),$policy.SessionId)}
'passed'
''', encoding='utf-8')
    completed = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source)],
        capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == 'passed'
