"""Foreground notification is optional and runs after native owner release."""
from pathlib import Path
import shutil
import subprocess

import pytest

SOURCE=Path(__file__).resolve().parents[2]/'packaging/windows/Install-EndpointAgentCanary.ps1'


@pytest.mark.parametrize('outcome', ['delivered','pending','throw','changed-helper'])
def test_notification_stage_preserves_verified_helper_and_optional_outcome(tmp_path,outcome):
    powershell=shutil.which('powershell.exe') or shutil.which('pwsh')
    if not powershell:
        pytest.skip('PowerShell wrapper')
    helper=tmp_path/'fixture.exe';helper.write_bytes(b'known extracted helper fixture')
    script=tmp_path/'notification-wrapper.ps1'
    script.write_text(r'''param($Source,$Helper,$Outcome)
$ErrorActionPreference='Stop'
$env:PSModulePath=Join-Path $PSHOME 'Modules'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'wrapper parse failure'}
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-InstallationNotification'},$true)
if(!$node){throw 'notification stage missing'}
Invoke-Expression $node.Extent.Text
function Assert-ExistingPathChain {param($Path)}
function Assert-CacheArtifactProtection {param($Path)}
function Assert-InstallerCacheProtection {param($Path)}
$script:Started=$false;$script:Waited=$false;$script:Disposed=$false
function Start-InstallationNotificationProcess {
    param($HelperPath,$LaunchDirectory)
    if($HelperPath -cne $Helper){throw 'wrong helper'}
    $script:Started=$true
    if($Outcome -ceq 'throw'){throw 'simulated notification launch failure'}
    $process=[pscustomobject]@{ExitCode=$(if($Outcome -ceq 'delivered'){0}else{75})}
    $process|Add-Member ScriptMethod WaitForExit {$script:Waited=$true}
    $process|Add-Member ScriptMethod Dispose {$script:Disposed=$true}
    return $process
}
$hash=(Get-FileHash -LiteralPath $Helper -Algorithm SHA256).Hash.ToLowerInvariant()
if($Outcome -ceq 'changed-helper'){$hash='0'*64}
$result=Invoke-InstallationNotification -HelperPath $Helper -HelperHash $hash -LaunchDirectory (Split-Path $Helper)
if($result -cne $(if($Outcome -ceq 'delivered'){'delivered'}else{'pending'})){throw 'wrong optional result'}
if($Outcome -ceq 'changed-helper' -and $script:Started){throw 'unverified helper launched'}
if($Outcome -cin @('delivered','pending') -and (!$script:Waited -or !$script:Disposed)){throw 'coordinator not observed/exited/disposed'}
Write-Output 'passed'
''',encoding='utf-8')
    result=subprocess.run([powershell,'-NoProfile','-NonInteractive','-File',str(script),str(SOURCE),str(helper),outcome],capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='passed'


@pytest.mark.parametrize('native_exit', [0,68])
@pytest.mark.parametrize('delivery', ['pending','throw'])
def test_outer_finally_releases_native_mutex_before_delivery_and_keeps_exit(tmp_path,native_exit,delivery):
    powershell=shutil.which('powershell.exe') or shutil.which('pwsh')
    if not powershell:
        pytest.skip('PowerShell wrapper')
    script=tmp_path/'notification-finally.ps1'
    script.write_text(r'''param($Source,[int]$NativeExit,$Delivery)
$ErrorActionPreference='Stop'
$env:PSModulePath=Join-Path $PSHOME 'Modules'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $null -ne $n.Finally -and $n.Finally.Extent.Text.Contains('$updateMutex.ReleaseMutex()')},$true)
if(!$node -or !$node.Finally.Extent.Text.Contains('Invoke-InstallationNotification')){throw 'post-native stage missing'}
$script:Released=$false;$script:Disposed=$false
$updateMutex=[pscustomobject]@{}
$updateMutex|Add-Member ScriptMethod ReleaseMutex {$script:Released=$true}
$updateMutex|Add-Member ScriptMethod Dispose {$script:Disposed=$true}
$transactionOwned=$true;$installationNotification=@{HelperPath='retained signed helper';HelperHash='bound hash';LaunchDirectory='private launch'}
function Invoke-InstallationNotification {
    param($HelperPath,$HelperHash,$LaunchDirectory)
    if(!$script:Released -or !$script:Disposed){throw 'native exclusion still held'}
    Write-Host 'post-native'
    if($Delivery -ceq 'throw'){throw 'notification-only failure'}
    return 'pending'
}
try {exit $NativeExit}
finally {
    $body=$node.Finally.Extent.Text
    Invoke-Expression $body.Substring(1,$body.Length-2)
}
''',encoding='utf-8')
    result=subprocess.run([powershell,'-NoProfile','-NonInteractive','-File',str(script),str(SOURCE),str(native_exit),delivery],capture_output=True,text=True,timeout=15)
    assert result.returncode==native_exit,result.stderr
    assert 'post-native' in result.stdout
    assert 'INSTALLATION_NOTIFICATION_PENDING' in result.stdout
