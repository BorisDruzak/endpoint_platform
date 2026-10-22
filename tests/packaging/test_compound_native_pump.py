"""Both delayed-commit channels must progress before native settlement."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.skipif(os.name!='nt',reason='actual PowerShell pump')
@pytest.mark.parametrize('case',['two-channels','pending-ack','owner-loss'])
def test_compound_pump_preserves_owner_and_drains_both_channels(tmp_path,case):
    source=Path(__file__).resolve().parents[2]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'pump.ps1'
    script.write_text(r'''param($Source,$Case)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse failure'}
$types=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $types.Extent.Text
Initialize-InstallerBridgeTypes
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-CompoundNativePump'},$true)
if($null -eq $node){throw 'compound pump missing'}
Invoke-Expression $node.Extent.Text
$global:observed=[Collections.Generic.List[string]]::new();$global:ownerChecks=0
$fixtureCompletion=[Threading.Tasks.TaskCompletionSource[uint32]]::new()
if($Case -eq 'pending-ack'){$fixtureCompletion.SetResult([uint32]0)}
$driver=[pscustomobject]@{PendingTask=$fixtureCompletion.Task}
$driver|Add-Member ScriptMethod CheckOwnership { $global:ownerChecks++;if($Case -eq 'owner-loss' -and $global:ownerChecks -ge 2){throw 'OWNER_AUTH_FAILED'} }
$driver|Add-Member ScriptMethod IsNativeClosurePending {return $false}
$channels=@(foreach($index in 1..2){[EndpointInstallerBridge.Channel]::new(('EndpointInstaller-'+[Guid]::NewGuid().ToString('D')+'-'+[Guid]::NewGuid().ToString('N')))})
$old=@{Label='old';Bridge=@{Peers=@();Channel=$channels[0]};Acknowledgement=$(if($Case -eq 'pending-ack'){1}else{$null});Challenge=$null}
$new=@{Label='new';Bridge=@{Peers=@();Channel=$channels[1]};Acknowledgement=$null;Challenge=$null}
function Invoke-InstallerConversationStep {
 param($State)
 $global:observed.Add($State.Label)
 if($global:observed.Count -ge 3){$State.Acknowledgement=$null}
 if($global:observed.Count -ge 4 -and !$fixtureCompletion.Task.IsCompleted){$fixtureCompletion.SetResult([uint32]0)}
 return $false
}
$failed=$false
try{Invoke-CompoundNativePump -Driver $driver -Conversations @($old,$new)}catch{if($_.Exception.Message -notlike '*OWNER_AUTH_FAILED*'){throw};$failed=$true}finally{foreach($channel in $channels){$channel.Dispose()}}
if($Case -eq 'owner-loss'){if(!$failed){throw 'lost owner admitted'}}else{
 if($failed -or $global:ownerChecks -lt 2 -or [string]::Join(',',@($global:observed|Select-Object -First 4)) -cne 'old,new,old,new'){throw 'premature settlement or missing channel'}
}
Write-Output 'passed'
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source),case],capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='passed'
