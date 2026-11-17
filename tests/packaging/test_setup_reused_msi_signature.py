import os
from pathlib import Path
import subprocess
import pytest


@pytest.mark.skipif(os.name!='nt',reason='Windows PowerShell signing admission')
def test_verified_reused_msi_is_not_signed_again(tmp_path):
    script=Path(__file__).resolve().parents[2]/'packaging/windows/build-setup.ps1'
    harness=tmp_path/'reuse.ps1'
    harness.write_text(r'''
param($Script)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
$f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Finalize-SetupMsiSignature'},$true)
if(!$f){throw 'signature reuse admission missing'};Invoke-Expression $f.Extent.Text
$script:SignCalls=0;$script:WrongSigner=$false
function Set-SetupAuthenticodeSignature {param($Path,$Thumbprint,$Timestamp)$script:SignCalls++}
function Get-AuthenticodeSignature {param($LiteralPath)return @{Status='Valid';TimeStamperCertificate=$true;SignerCertificate=@{Thumbprint=$(if($script:WrongSigner){'B'*40}else{'A'*40})}}}
Finalize-SetupMsiSignature -Path 'fixture.msi' -Thumbprint ('A'*40) -Timestamp 'http://timestamp.test' -ReuseExisting $true
if($script:SignCalls -ne 0){throw 'immutable reused MSI was re-signed'}
$script:WrongSigner=$true;$refused=$false
try{Finalize-SetupMsiSignature -Path 'fixture.msi' -Thumbprint ('A'*40) -Timestamp 'http://timestamp.test' -ReuseExisting $true}catch{$refused=$true}
if(!$refused){throw 'foreign MSI publisher accepted'}
Finalize-SetupMsiSignature -Path 'new.msi' -Thumbprint ('A'*40) -Timestamp 'http://timestamp.test' -ReuseExisting $false
if($script:SignCalls -ne 1){throw 'new MSI was not signed'}
Write-Output 'PASS'
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-File',str(harness),str(script)],capture_output=True,text=True)
    assert result.returncode==0,result.stdout+result.stderr
