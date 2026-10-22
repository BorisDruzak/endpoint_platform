"""Deferred recovery keeps its task and retries with the same verified entrypoint."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.skipif(os.name != 'nt', reason='actual Windows scheduled task settings')
def test_recovery_settings_bound_failure_restarts_without_parallel_runs(tmp_path):
    source = Path(__file__).resolve().parents[2] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'retry.ps1'
    script.write_text(r'''param($Source)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'New-StagedRecoverySettings'},$true)
if($null -eq $node){throw 'bounded recovery restart settings missing'}
Invoke-Expression $node.Extent.Text
$settings=New-StagedRecoverySettings
if($settings.RestartCount -ne 3 -or $settings.RestartInterval -cne 'PT1M' -or $settings.MultipleInstances -ne 2){throw 'unbounded or overlapping retries'}
if($settings.ExecutionTimeLimit -cne 'PT4H10M' -or !$settings.StartWhenAvailable -or $settings.DisallowStartIfOnBatteries -or $settings.StopIfGoingOnBatteries){throw 'recovery availability changed'}
$register=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Register-StagedRecoveryTask'},$true)
if(!$register.Extent.Text.Contains('$settings=New-StagedRecoverySettings')){throw 'registered task does not use verified settings'}
'passed'
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'


@pytest.mark.skipif(os.name != 'nt', reason='actual PowerShell terminal cleanup decisions')
@pytest.mark.parametrize('users', ['deferred', 'launch-requested', 'session-unavailable', 'not-required', 'unknown'])
def test_deferred_companion_launch_keeps_authenticated_recovery_task(tmp_path, users):
    source = Path(__file__).resolve().parents[2] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'cleanup.ps1'
    script.write_text(r'''param($Source,$Users)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Complete-StagedTerminalCleanup'},$true)
Invoke-Expression $node.Extent.Text
$global:removed=$false
function Invoke-InstallerHelper {return [pscustomobject]@{services=[pscustomobject]@{EndpointAgent='running'};users=$Users}}
function Start-ManagedEndpointAgent {}
function Remove-StagedRecoveryTask {$global:removed=$true}
$threw=$false
try{Complete-StagedTerminalCleanup @{TransactionId='test'} @{EndpointAgent='Running'} 'model' -RequireServices}catch{if($_.Exception.Message -cne 'RECOVERY_REQUIRED'){throw};$threw=$true}
$deferred=$Users -in @('deferred','unknown')
if($global:removed -eq $deferred -or $threw -ne $deferred){throw 'deferred cleanup lost its recovery task'}
'passed'
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source), users],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == 'passed'
    assert ('STAGED_TERMINAL_CLEANUP_DEFERRED' in result.stdout) == (users in {'deferred', 'unknown'})
