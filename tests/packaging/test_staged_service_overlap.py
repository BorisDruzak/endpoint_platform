"""Dispatch both verified service starts before waiting; retain both checks."""
import json
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.skipif(os.name != 'nt', reason='native Windows PowerShell service controllers')
@pytest.mark.parametrize('case', ['stopped', 'agent-running', 'browser-missing', 'browser-start-fails', 'browser-never-running'])
def test_trial_service_start_dispatches_both_and_requires_both_running(tmp_path, case):
    source = Path(__file__).resolve().parents[2] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'overlap.ps1'
    script.write_text(r'''param($Source,$Case)
$ErrorActionPreference='Stop';Add-Type -AssemblyName System.ServiceProcess
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Start-VerifiedTrialServices'},$true)
if($null -eq $node){throw 'TRIAL_PAIR_MISSING'};Invoke-Expression $node.Extent.Text
$ManagedServiceTimeout=[TimeSpan]::FromSeconds(1);$script:events=[Collections.Generic.List[string]]::new();$script:services=@{}
foreach($name in @('EndpointAgent','EndpointBrowserPolicy')){
 if($Case -eq 'browser-missing' -and $name -eq 'EndpointBrowserPolicy'){continue}
 $s=[pscustomobject]@{Name=$name;Status=[ServiceProcess.ServiceControllerStatus]::Stopped}
 if($Case -eq 'agent-running' -and $name -eq 'EndpointAgent'){$s.Status=[ServiceProcess.ServiceControllerStatus]::Running}
 $s|Add-Member ScriptMethod Start {$script:events.Add('start:'+$this.Name);if($Case -eq 'browser-start-fails' -and $this.Name -eq 'EndpointBrowserPolicy'){throw 'start failed'};$this.Status=[ServiceProcess.ServiceControllerStatus]::StartPending}
 $s|Add-Member ScriptMethod WaitForStatus {param($Status,$Timeout)
  if(-not $script:events.Contains('start:EndpointBrowserPolicy')){throw 'WAITED_BEFORE_OTHER_START'}
  $script:events.Add('wait:'+$this.Name)
  if($Case -ne 'browser-never-running' -or $this.Name -ne 'EndpointBrowserPolicy'){$this.Status=$Status}
 }
 $s|Add-Member ScriptMethod Refresh {}
 $s|Add-Member ScriptMethod Dispose {$script:events.Add('dispose:'+$this.Name)}
 $script:services[$name]=$s
}
function Get-Service {param($Name,$ErrorAction) if(-not $script:services.ContainsKey($Name)){throw 'missing'};return $script:services[$Name]}
$failed=$false;try{Start-VerifiedTrialServices}catch{$failed=$true}
if($failed -ne ($Case -in @('browser-missing','browser-start-fails','browser-never-running'))){throw 'wrong trial pair verdict'}
if($Case -in @('stopped','agent-running')){
 if($script:services['EndpointAgent'].Status -ne 'Running' -or $script:services['EndpointBrowserPolicy'].Status -ne 'Running'){throw 'unchecked service'}
}
ConvertTo-Json -InputObject @($script:events) -Compress
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source), case],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    events = json.loads(result.stdout)
    if case in {'stopped', 'agent-running'}:
        assert events.index('start:EndpointBrowserPolicy') < events.index('wait:EndpointAgent')
        assert {'dispose:EndpointAgent', 'dispose:EndpointBrowserPolicy'} <= set(events)


@pytest.mark.skipif(os.name != 'nt', reason='native Windows PowerShell service controllers')
@pytest.mark.parametrize('failure', [False, True])
def test_browser_stop_precedes_agent_but_late_gate_still_precedes_updater(tmp_path, failure):
    source = Path(__file__).resolve().parents[2] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'stop-order.ps1'
    script.write_text(r'''param($Source,[int]$Failure)
$ErrorActionPreference='Stop';Add-Type -AssemblyName System.ServiceProcess
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Stop-ManagedAgentServices'},$true)
Invoke-Expression $node.Extent.Text
$ManagedServiceTimeout=[TimeSpan]::FromSeconds(1);$script:events=[Collections.Generic.List[string]]::new();$script:services=@{}
foreach($name in @('EndpointAgent','EndpointAgentUpdater','EndpointBrowserPolicy')){
 $s=[pscustomobject]@{Name=$name;Status=[ServiceProcess.ServiceControllerStatus]::Running}
 $s|Add-Member ScriptMethod WaitForStatus {param($Status,$Timeout)if($this.Status -ne $Status){throw 'not stopped'}}
 $s|Add-Member ScriptMethod Refresh {};$script:services[$name]=$s
}
function Get-Service {param($Name,$ErrorAction)return $script:services[$Name]}
function Stop-Service {param($Name,$ErrorAction)
 $script:events.Add('stop:'+$Name);$script:services[$Name].Status=[ServiceProcess.ServiceControllerStatus]::Stopped
 if($Failure -and $Name -eq 'EndpointBrowserPolicy'){throw 'browser partial stop'}
}
$stopped=@{};$failed=$false
try{Stop-ManagedAgentServices -PreviousStates @{} -StoppedBySetup $stopped -AfterAgentStopped {
 if($script:services['EndpointAgent'].Status -ne 'Stopped' -or $script:services['EndpointBrowserPolicy'].Status -ne 'Stopped'){throw 'late gate before prerequisite stops'}
 $script:events.Add('gate')
}}catch{$failed=$true}
if($failed -ne [bool]$Failure){throw 'wrong stop verdict'}
if($Failure -and ($script:services['EndpointAgent'].Status -ne 'Running' -or $stopped.Count -ne 1 -or -not $stopped.ContainsKey('EndpointBrowserPolicy'))){throw 'touched Agent after browser failure'}
ConvertTo-Json -InputObject @($script:events) -Compress
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source), str(int(failure))],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == (['stop:EndpointBrowserPolicy'] if failure else
        ['stop:EndpointBrowserPolicy', 'stop:EndpointAgent', 'gate', 'stop:EndpointAgentUpdater'])
