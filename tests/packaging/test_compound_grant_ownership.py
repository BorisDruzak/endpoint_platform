"""A native owner-transfer event must be checked at the actual grant boundary."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.skipif(os.name!='nt',reason='actual PowerShell conversation')
def test_native_owner_loss_blocks_accept_and_grant(tmp_path):
    source=Path(__file__).resolve().parents[2]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'grant.ps1'
    script.write_text(r'''param($Source)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-InstallerConversationStep'},$true)
Invoke-Expression $node.Extent.Text
$global:accepted=$false;$global:sent=$false
$driver=[pscustomobject]@{};$driver|Add-Member ScriptMethod CheckOwnership {throw 'OWNER_AUTH_FAILED'}
$policy=[pscustomobject]@{};$policy|Add-Member ScriptMethod Accept {$global:accepted=$true;return 'unsafe'}
$channel=[pscustomobject]@{}
$channel|Add-Member ScriptMethod Poll {return [Text.Encoding]::ASCII.GetBytes('{"proof":"test"}')}
$channel|Add-Member ScriptMethod PeerPid {return 200}
$peer=[pscustomobject]@{Alive=$true;Identity=[pscustomobject]@{Pid=200}}
$bridge=@{Owner=[pscustomobject]@{Alive=$true};Policy=$policy;Channel=$channel;NativeDriver=$driver}
$state=@{Bridge=$bridge;Launched=$null;Phase='native';Native=$true;Peer=$peer;
 Challenge=[pscustomobject]@{Action='begin'};Payload=$null;Acknowledgement=$null;Completed=$false;Result=$null}
function Send-InstallerBridgePacket {$global:sent=$true}
$failed=$false;try{Invoke-InstallerConversationStep $state|Out-Null}catch{$failed=$_.Exception.Message -like '*OWNER_AUTH_FAILED*'}
if(!$failed -or $global:accepted -or $global:sent){throw 'owner transfer reached grant'}
Write-Output 'passed'
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source)],capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='passed'
