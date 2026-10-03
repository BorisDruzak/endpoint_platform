"""Execute isolated wrapper functions without touching operator SCM services."""
from pathlib import Path
import subprocess
import shutil
import pytest


@pytest.fixture
def powershell():
    executable = shutil.which("powershell.exe") or shutil.which("pwsh")
    if executable is None:
        pytest.skip("PowerShell required for extracted mocked service checkpoint behavior")
    return executable


@pytest.mark.parametrize('failure,expected', [
    ('late-pending', ['stop:EndpointAgent', 'gate', 'restore:deferred']),
    ('late-settled', ['stop:EndpointAgent', 'gate', 'verify-settled', 'start:EndpointAgent']),
    ('stopped-by-worker', ['gate']),
    ('partial-agent', ['stop:EndpointAgent', 'start:EndpointAgent']),
    ('partial-updater', ['stop:EndpointAgent', 'gate', 'stop:EndpointAgentUpdater', 'start:EndpointAgent', 'start:EndpointAgentUpdater']),
])
def test_quiescence_gate_precedes_old_updater_stop_and_restores_partial_failure(tmp_path, failure, expected, powershell):
    source = Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'checkpoint.ps1'
    script.write_text(r'''param($Source,$Failure)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.ServiceProcess
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse failure'}
foreach($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) { Invoke-Expression $node.Extent.Text }
$ManagedServiceNames=@('EndpointAgent','EndpointAgentUpdater')
$ManagedServiceTimeout=[TimeSpan]::FromSeconds(1)
$script:events=[Collections.Generic.List[string]]::new()
$script:services=@{}
foreach($name in $ManagedServiceNames){
 $service=[pscustomobject]@{Name=$name;Status=[ServiceProcess.ServiceControllerStatus]::Running}
 $service | Add-Member ScriptMethod WaitForStatus {param($Status,$Timeout) if($this.Status -ne $Status){throw 'not settled'}}
 $service | Add-Member ScriptMethod Refresh {}
 $script:services[$name]=$service
}
function Get-Service {param($Name,$ErrorAction) return $script:services[$Name]}
function Stop-Service {param($Name,$ErrorAction)
 $script:events.Add('stop:'+$Name)
 $script:services[$Name].Status=[ServiceProcess.ServiceControllerStatus]::Stopped
 if(($Failure -eq 'partial-agent' -and $Name -eq 'EndpointAgent') -or ($Failure -eq 'partial-updater' -and $Name -eq 'EndpointAgentUpdater')){throw 'partial stop'}
}
function Start-Service {param($Name,$ErrorAction)
 $script:events.Add('start:'+$Name)
 $script:services[$Name].Status=[ServiceProcess.ServiceControllerStatus]::Running
}
$states=Get-ManagedAgentServiceStates
$stopped=@{}
if($Failure -eq 'stopped-by-worker'){$script:services['EndpointAgent'].Status=[ServiceProcess.ServiceControllerStatus]::Stopped}
try { Stop-ManagedAgentServices -PreviousStates $states -StoppedBySetup $stopped -AfterAgentStopped {
 $script:events.Add('gate')
 if($Failure -in @('late-pending','late-settled','stopped-by-worker')){throw 'UPDATE_IN_PROGRESS'}
} } catch {} finally {
 $result=Restore-ManagedAgentServices -PreviousStates $states -StoppedBySetup $stopped -RequireSettled:($Failure -like 'late-*') -RestorationTimeout ([TimeSpan]::Zero) -CanRestore {
  if($Failure -eq 'late-settled'){$script:events.Add('verify-settled');return $true}
  return $false
 }
 if($result -eq 'deferred'){$script:events.Add('restore:deferred')}
}
ConvertTo-Json -InputObject @($script:events) -Compress
''', encoding='utf-8')
    result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(script), str(source), failure], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    import json
    assert json.loads(result.stdout) == expected


def test_restoration_evidence_failure_cannot_mask_update_in_progress(tmp_path, powershell):
    source=Path(__file__).resolve().parents[3]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'restore-exit.ps1'
    script.write_text(r'''param($Source)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $null -ne $n.Finally -and $n.Finally.Extent.Text.Contains('Restore-ManagedAgentServices') -and -not $n.Finally.Extent.Text.Contains('ReleaseMutex')},$true)
if($null -eq $node){throw 'restoration boundary missing'}
$installationCompleted=$false;$nativeStarted=$false;$interruptedFence=$null;$installerStateRoot='model'
$bridge=$null;$helperPin=$null
$packagePin=[pscustomobject]@{};$packagePin | Add-Member ScriptMethod Dispose {}
function Read-InstallerFence {throw 'evidence became unavailable'}
Invoke-Expression ('try {exit 61} finally '+$node.Finally.Extent.Text)
''',encoding='utf-8')
    result=subprocess.run([powershell,'-NoProfile','-NonInteractive','-File',str(script),str(source)],capture_output=True,text=True,timeout=30)
    assert result.returncode==61,result.stderr
    assert 'MANAGED_SERVICE_RESTORATION_DEFERRED' in result.stdout
