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
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-CompoundNativePump'},$true)
if($null -eq $node){throw 'compound pump missing'}
Invoke-Expression $node.Extent.Text
$global:observed=[Collections.Generic.List[string]]::new();$global:ownerChecks=0
$pending=[pscustomobject]@{}
$pending|Add-Member ScriptProperty IsCompleted { $global:observed.Count -ge $(if($Case -eq 'pending-ack'){0}else{4}) }
$driver=[pscustomobject]@{PendingTask=$pending}
$driver|Add-Member ScriptMethod CheckOwnership { $global:ownerChecks++;if($Case -eq 'owner-loss' -and $global:ownerChecks -ge 2){throw 'OWNER_AUTH_FAILED'} }
$old=@{Label='old';Bridge=@{Peers=@()};Acknowledgement=$(if($Case -eq 'pending-ack'){1}else{$null});Challenge=$null}
$new=@{Label='new';Bridge=@{Peers=@()};Acknowledgement=$null;Challenge=$null}
function Invoke-InstallerConversationStep {
 param($State)
 $global:observed.Add($State.Label)
 if($global:observed.Count -ge 3){$State.Acknowledgement=$null}
 return $false
}
$failed=$false
try{Invoke-CompoundNativePump -Driver $driver -Conversations @($old,$new)}catch{if($_.Exception.Message -notlike '*OWNER_AUTH_FAILED*'){throw};$failed=$true}
if($Case -eq 'owner-loss'){if(!$failed){throw 'lost owner admitted'}}else{
 if($failed -or $global:ownerChecks -lt 2 -or [string]::Join(',',@($global:observed|Select-Object -First 4)) -cne 'old,new,old,new'){throw 'premature settlement or missing channel'}
}
Write-Output 'passed'
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source),case],capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='passed'
