"""Absent native products must remain fresh ADDLOCAL during bounded recovery."""
import json
import os
from pathlib import Path
import subprocess
import pytest


@pytest.mark.skipif(os.name!='nt',reason='actual PowerShell wrapper argument selection')
@pytest.mark.parametrize('state,valid,reinstall',[(-1,True,False),(5,True,True),(1,False,False),(2,False,False)])
def test_recovery_reinstall_depends_on_observed_native_product(tmp_path,state,valid,reinstall):
    source=Path(__file__).resolve().parents[2]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'arguments.ps1'
    script.write_text(r'''param($Source,[int]$State)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'wrapper parse failed'}
$nodes=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$null -ne $interruptedFence' -and $n.Extent.Text.Contains("'REINSTALL=ALL'")},$true))
if($nodes.Count -ne 1){throw 'recovery install argument branch ambiguous'}
$interruptedFence=@{operation='install'};$preparation=@{new_product_state=$State}
$msiArguments=@('ADDLOCAL=EndpointAgentFeature,EndpointAgentInitialRuntimeFeature')
$rejected=$false
try{Invoke-Expression $nodes[0].Extent.Text}catch{$rejected=$true}
@{rejected=$rejected;observed_state=$State;arguments=@($msiArguments)}|ConvertTo-Json -Compress
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source),'-State',str(state)],capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    value=json.loads(result.stdout)
    assert value['observed_state']==state
    assert value['rejected'] is not valid
    assert ('REINSTALL=ALL' in value['arguments']) is reinstall


@pytest.mark.skipif(os.name!='nt',reason='actual PowerShell wrapper legacy routing')
@pytest.mark.parametrize('kind,skipped',[('canonical-legacy',True),('modern',False),('missing',False),('unknown',False)])
def test_only_authenticated_legacy_kind_skips_old_binary_callbacks(tmp_path,kind,skipped):
    source=Path(__file__).resolve().parents[2]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'routing.ps1'
    script.write_text(r'''param($Source,$Kind)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'wrapper parse failed'}
$nodes=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$oldManifest.package_sha256 -cne $manifest.package_sha256' -and $n.Extent.Text.Contains('$initial.foundation_kind')},$true))
if($nodes.Count -ne 1){throw 'old foundation routing ambiguous'}
$oldManifest=@{version='3.2.81';product_code='{11111111-1111-4111-8111-111111111111}';package_sha256=('a'*64)}
$manifest=@{version='3.2.97';product_code='{22222222-2222-4222-8222-222222222222}';package_sha256=('b'*64)}
$initial=[pscustomobject]@{};if($Kind -ne 'missing'){$initial|Add-Member -NotePropertyName foundation_kind -NotePropertyValue $Kind}
$installerStateRoot='unused';$executionCacheRoot='unused';$script:oldCallbacks=$false
$oldPackagePin=$null;$oldHelperPin=$null;$preloadedOldHash=$null
function Get-CompoundOldMedia {$script:oldCallbacks=$true;throw 'modeled missing old Binary: no fallback permitted'}
$rejected=$false
try{Invoke-Expression $nodes[0].Extent.Text}catch{$rejected=$true}
@{old_callbacks=$script:oldCallbacks;rejected=$rejected}|ConvertTo-Json -Compress
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source),kind],capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    value=json.loads(result.stdout)
    assert value['old_callbacks'] is not skipped
    assert value['rejected'] is not skipped
