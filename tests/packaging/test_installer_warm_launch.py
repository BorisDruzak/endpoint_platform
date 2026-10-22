"""Warm workers retain exact physical identity and parent checks."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.skipif(os.name != 'nt', reason='actual PowerShell launch guard')
@pytest.mark.parametrize('case', ['valid', 'owner-loss', 'peer-loss', 'creation', 'hash', 'parent',
                                 'image', 'sid', 'elevation', 'extra-key', 'sequence', 'boolean-pid'])
def test_warm_launch_reply_is_bound_to_new_child_and_live_owner(tmp_path, case):
    source = Path(__file__).resolve().parents[2] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'warm.ps1'
    script.write_text(r'''param($Source,$Case)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-InstallerWarmLaunchReply'},$true)
if($null -eq $node){throw 'WARM_LAUNCH_GUARD_MISSING'}
Invoke-Expression $node.Extent.Text
$owner=[pscustomobject]@{Alive=($Case -ne 'owner-loss');Identity=[pscustomobject]@{Sid='S-1-5-18'}}
$peer=[pscustomobject]@{Alive=($Case -ne 'peer-loss')}
$bridge=@{Owner=$owner}
$broker=@{Owner=$owner;Peer=$peer;Sequence=1;HelperHash=('a'*64);HelperPath='C:\Trusted\helper.exe'}
$candidate=[pscustomobject]@{Alive=$true;Identity=[pscustomobject]@{Pid=101;Created=[long]12345678901234567;Hash=('a'*64);Sid='S-1-5-18';Elevated=$true};ImagePath=$broker.HelperPath}
$candidate|Add-Member ScriptMethod DirectChildOf {param($p)return $Case -ne 'parent'}
$packet=[pscustomobject]@{pid=101;created=[long]12345678901234567;sequence=1}
switch($Case){
 'creation'{$packet.created++} 'hash'{$candidate.Identity.Hash='b'*64}
 'image'{$candidate.ImagePath='C:\Foreign\helper.exe'} 'sid'{$candidate.Identity.Sid='S-1-5-32-545'}
 'elevation'{$candidate.Identity.Elevated=$false} 'extra-key'{$packet|Add-Member NoteProperty path 'untrusted.exe'}
 'sequence'{$packet.sequence=2} 'boolean-pid'{$packet.pid=$true}
}
$failed=$false
try{Assert-InstallerWarmLaunchReply $broker $bridge $packet $candidate}catch{if($_.Exception.Message -notlike '*OWNER_AUTH_FAILED*'){throw};$failed=$true}
if(($Case -eq 'valid') -eq $failed){throw 'incorrect warm launch verdict'}
Write-Output 'passed'
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script),
                             str(source), case], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'


@pytest.mark.skipif(os.name != 'nt', reason='actual owner cleanup function')
def test_cleanup_stops_verified_inner_before_terminating_outer(tmp_path):
    source = Path(__file__).resolve().parents[2] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'stop-warm.ps1'
    script.write_text(r'''param($Source)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Stop-InstallerLaunchBroker'},$true)
Invoke-Expression $node.Extent.Text
$global:innerStopped=$false;$global:outerKilled=$false;$global:channelClosed=$false
function Send-InstallerBridgePacket {throw 'closing broken launcher channel'}
function Stop-InstallerLaunchPeer {param($Broker)if(!$global:channelClosed){throw 'peer killed before channel closed'};$global:innerStopped=$true}
$process=[pscustomobject]@{}
$process|Add-Member ScriptMethod WaitForExit {param($ms)return $global:innerStopped}
$process|Add-Member ScriptMethod Kill {$global:outerKilled=$true}
$process|Add-Member ScriptMethod Dispose {}
$channel=[pscustomobject]@{};$channel|Add-Member ScriptMethod Dispose {$global:channelClosed=$true}
function Identity { $v=[pscustomobject]@{Alive=$true;Identity=[pscustomobject]@{Hash=('a'*64)}};$v|Add-Member ScriptMethod Dispose {};return $v }
$broker=@{Process=$process;Channel=$channel;Peer=(Identity);Owner=(Identity);Launched=(Identity);Sequence=0;HelperHash=('a'*64)}
Stop-InstallerLaunchBroker $broker
if(!$global:innerStopped -or $global:outerKilled){throw 'inner leaked or outer killed first'}
Write-Output 'passed'
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'
