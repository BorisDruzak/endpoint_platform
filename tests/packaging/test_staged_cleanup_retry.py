"""Deferred recovery keeps its task and retries with the same verified entrypoint."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.skipif(os.name != 'nt', reason='actual PowerShell terminal cleanup decisions')
@pytest.mark.parametrize('case, steps', [
    ('accepted', 'restore,arm,retire'),
    ('interrupted', 'restore,arm,restore,arm,retire'),
    ('acknowledged', 'restore,existing-only,retire'),
    ('unknown', 'restore'),
    ('wrong-operation', 'restore'),
    ('wrong-response', 'restore'),
    ('conflict', 'restore,conflict'),
])
def test_accepted_cleanup_preserves_recovery_until_delivery_is_durable(tmp_path, case, steps):
    source = Path(__file__).resolve().parents[2] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'accepted-cleanup.ps1'
    script.write_text(r'''param($Source,$Case)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'wrapper parse failure'}
foreach($name in @('Complete-StagedTerminalCleanup','Remove-StagedRecoveryTask')){
 $node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
 Invoke-Expression $node.Extent.Text
}
$id='11111111-1111-4111-8111-111111111111'
$other='22222222-2222-4222-8222-222222222222'
$script:steps=@()
$script:interrupt=$Case -ceq 'interrupted'
$script:watchdog=$true
function Read-UpdateGateState {
 $binding=if($Case -ceq 'wrong-operation'){$other}else{$id}
 $phase=if($Case -ceq 'unknown'){'switching'}else{'accepted'}
 @{Value=@{binding=@{operation_id=$binding};phase=$phase}}
}
function Invoke-InstallerHelper {
 $script:steps+='restore'
 $operation=if($Case -ceq 'wrong-response'){$other}else{$id}
 $status=if($Case -ceq 'acknowledged'){'settled'}else{'pending'}
 @{operation_id=$operation;installation_delivery=$status;services=@{EndpointAgent='running'};users='not-required'}
}
function Start-ManagedEndpointAgent {}
function Register-InstallationEventRetry {
 param($Bridge,[switch]$ExistingOnly)
 if($Bridge.TransactionId -cne $id -or !$script:watchdog){throw 'delivery lost its original recovery owner'}
 if($Case -ceq 'conflict'){$script:steps+='conflict';throw 'INSTALLATION_RETRY_TASK_CONFLICT'}
 if($ExistingOnly){$script:steps+='existing-only';return}
 $script:steps+='arm'
}
function Get-ScheduledTask { if($script:watchdog){$true} }
function Unregister-ScheduledTask {
 if($script:interrupt){throw 'interrupted after arming and before retirement'}
 $script:steps+='retire';$script:watchdog=$false
}
$bridge=@{TransactionId=$id}
if($Case -ceq 'interrupted'){
 try{Complete-StagedTerminalCleanup $bridge @{EndpointAgent='Running'} 'state' -RequireServices}
 catch{if($_.Exception.Message -cne 'RECOVERY_REQUIRED'){throw}}
 if(!$script:watchdog){throw 'interruption lost the watchdog'}
 $script:interrupt=$false
}
$failed=$false
try{Complete-StagedTerminalCleanup $bridge @{EndpointAgent='Running'} 'state' -RequireServices}
catch{if($_.Exception.Message -cne 'RECOVERY_REQUIRED'){throw};$failed=$true}
if($failed -ne ($Case -cin @('unknown','wrong-operation','wrong-response'))){throw 'unexpected cleanup result'}
if($script:watchdog -ne ($Case -cin @('unknown','wrong-operation','wrong-response','conflict'))){throw 'unexpected watchdog state'}
$script:steps -join ','
''', encoding='utf-8')
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source), case],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == steps
    assert ('INSTALLATION_RETRY_TASK_CONFLICT' in result.stdout) == (case == 'conflict')


@pytest.mark.skipif(os.name != 'nt', reason='actual PowerShell registration and security descriptor checks')
@pytest.mark.parametrize('case', [
    'new', 'resume', 'wrong-owner', 'wrong-principal', 'wrong-action', 'foreign-write',
    'different-helper', 'previous-helper', 'foreign-publisher', 'tampered-helper', 'missing-system',
    'no-boot-trigger', 'create-race', 'normalized-dacl', 'missing-admin-rights', 'inherited-rights',
    'settled-absent', 'settled-prior-helper', 'settled-access-denied',
    'changed-before-update', 'unlocked-prior-helper',
])
def test_installation_retry_registration_preserves_other_scheduled_tasks(tmp_path, case):
    source = Path(__file__).resolve().parents[2] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'notification-registration.ps1'
    script.write_text(r'''param($Source,$Case)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$env:PSModulePath=Join-Path $PSHOME 'Modules'
Import-Module Microsoft.PowerShell.Utility
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'wrapper parse failure'}
foreach($name in @('Register-InstallationEventRetry','Assert-PriorInstallationRetryHelper','Read-OwnedInstallationRetryTask')){
 $node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
 if($node){Invoke-Expression $node.Extent.Text}
}
$cache=Join-Path $PSScriptRoot 'installer-cache'
$helper=Join-Path $cache 'msi-candidate\endpoint-installer-host.exe'
$null=New-Item -ItemType Directory (Split-Path $helper) -Force
Set-Content -LiteralPath $helper 'helper fixture'
Set-Content -LiteralPath (Join-Path (Split-Path $helper) 'EndpointAgent.msi') 'current MSI fixture'
$priorMsi=Join-Path $PSScriptRoot 'prior.msi'
Set-Content -LiteralPath $priorMsi 'previous MSI fixture'
$priorDigest=(Get-FileHash -LiteralPath $priorMsi).Hash.ToLowerInvariant()
$priorRoot=Join-Path $cache ('msi-'+$priorDigest)
$null=New-Item -ItemType Directory $priorRoot
Copy-Item -LiteralPath $priorMsi -Destination (Join-Path $priorRoot 'EndpointAgent.msi')
$priorHelper=Join-Path $priorRoot 'endpoint-installer-host.exe'
Set-Content -LiteralPath $priorHelper 'previous helper from signed binary'
$env:ENDPOINT_RETRY_TEST_EMBEDDED=(Get-FileHash -LiteralPath $priorHelper).Hash.ToLowerInvariant()
if($Case -ceq 'tampered-helper'){Set-Content -LiteralPath $priorHelper 'different bytes'}
Add-Type @'
namespace EndpointInstallerBridge {
 public static class PackageHelper {
  public static string Extract(string msi,string helper) {
   if(!System.IO.File.Exists(msi) || !System.IO.File.Exists(helper)) throw new System.InvalidOperationException();
   using(var stream=System.IO.File.OpenRead(helper))
   using(var sha=System.Security.Cryptography.SHA256.Create()) {
     var value=System.BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant();
     if(value!=System.Environment.GetEnvironmentVariable("ENDPOINT_RETRY_TEST_EMBEDDED"))
       throw new System.InvalidOperationException("unexpected embedded helper bytes");
     return value;
   }
  }
 }
}
'@
$launch=Join-Path $PSScriptRoot 'helper-11111111-1111-4111-8111-111111111111-11111111111111111111111111111111'
$prior=Join-Path $PSScriptRoot 'helper-11111111-1111-4111-8111-111111111111-22222222222222222222222222222222'
$name='EndpointInstallationEventDelivery'
$mode='--installation-events-retry'
$script:registrations=@()
function Assert-ExistingPathChain {}
function Assert-RegularNonReparseFile {}
function Assert-CacheArtifactProtection {}
function Assert-InstallerCacheProtection {}
function Get-AuthenticodeSignature {
 param($LiteralPath)
 if($LiteralPath -ceq (Join-Path $priorRoot 'EndpointAgent.msi') -and $Case -ceq 'foreign-publisher'){$publisher='foreign'}
 else{$publisher='our-publisher'}
 @{Status='Valid';SignerCertificate=@{Thumbprint=$publisher}}
}
function New-TaskCollection {
 $collection=[pscustomobject]@{Items=[Collections.Generic.List[object]]::new()}
 $collection|Add-Member ScriptProperty Count {$this.Items.Count}
 $collection|Add-Member ScriptMethod Item {$this.Items[$args[0]-1]}
 $collection|Add-Member ScriptMethod Create {
   $item=[pscustomobject]@{Type=$args[0];Path='';Arguments='';WorkingDirectory='';Enabled=$true;
     StartBoundary='';EndBoundary='';Repetition=[pscustomobject]@{Interval='';Duration=''}}
   $this.Items.Add($item)
   $item
 }
 $collection
}
function New-Definition {
 [pscustomobject]@{
  Principal=[pscustomobject]@{UserId='S-1-5-18';LogonType=5;RunLevel=1}
  Settings=[pscustomobject]@{Enabled=$true;ExecutionTimeLimit='PT1M';MultipleInstances=2;
     StartWhenAvailable=$true;DisallowStartIfOnBatteries=$false;StopIfGoingOnBatteries=$false}
  RegistrationInfo=[pscustomobject]@{Description=''}
  Actions=New-TaskCollection
  Triggers=New-TaskCollection
 }
}
$existing=New-Definition
$timed=$existing.Triggers.Create(1)
$timed.Repetition.Interval='PT1M'
$null=$existing.Triggers.Create($(if($Case -ceq 'no-boot-trigger'){9}else{8}))
$action=$existing.Actions.Create(0)
$action.Path=if($Case -ceq 'different-helper'){Join-Path $cache 'msi-other\endpoint-installer-host.exe'}
 elseif($Case -cin @('previous-helper','foreign-publisher','tampered-helper','settled-prior-helper','changed-before-update','unlocked-prior-helper')){$priorHelper}else{$helper}
$action.Arguments=if($Case -ceq 'wrong-action'){'--setup'}else{$mode}
$action.WorkingDirectory=$prior
if($Case -ceq 'wrong-principal'){$existing.Principal.UserId='S-1-5-19'}
$owner=if($Case -ceq 'wrong-owner'){'LS'}else{'BA'}
$sddl="O:${owner}G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
if($Case -ceq 'foreign-write'){$sddl+='(A;;FA;;;BU)'}
if($Case -ceq 'missing-system'){$sddl="O:${owner}G:BAD:P(A;;FA;;;BA)"}
if($Case -cin @('normalized-dacl','previous-helper','settled-prior-helper')){$sddl='O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;SY)'}
if($Case -ceq 'missing-admin-rights'){$sddl=$sddl.Replace('(A;;FA;;;BA)','(A;;FR;;;BA)')}
if($Case -ceq 'inherited-rights'){$sddl=$sddl.Replace('(A;;FA;;;BA)','(A;ID;FA;;;BA)')}
$task=[pscustomobject]@{Path=('\'+$name);Definition=$existing;Enabled=$true;Sddl=$sddl;Xml='<retry-task/>'}
$task|Add-Member ScriptProperty Actions {$this.Definition.Actions.Items}
$task|Add-Member ScriptMethod GetSecurityDescriptor {$this.Sddl}
$folder=[pscustomobject]@{Task=$task;Reads=0;Present=$Case -cnotin @('new','create-race','settled-absent')}
$folder|Add-Member ScriptMethod GetTask {
 $this.Reads++
 if($Case -ceq 'settled-access-denied'){throw [UnauthorizedAccessException]::new()}
 if(!$this.Present){throw [IO.FileNotFoundException]::new()}
 if($Case -ceq 'changed-before-update' -and $this.Reads -gt 1){$this.Task.Xml='<different-task/>'}
 $this.Task
}
$folder|Add-Member ScriptMethod RegisterTaskDefinition {
 $script:registrations+=@($args[2])
 if($Case -ceq 'create-race'){throw 'a conflicting task was registered while looking it up'}
 $this.Task.Definition=$args[1]
 $this.Task.Sddl='O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;SY)'
 $this.Present=$true
 $this.Task
}
$scheduler=[pscustomobject]@{Folder=$folder}
$scheduler|Add-Member ScriptMethod Connect {}
$scheduler|Add-Member ScriptMethod GetFolder {$this.Folder}
$scheduler|Add-Member ScriptMethod NewTask {New-Definition}
function New-Object { $scheduler }
$hash=(Get-FileHash -LiteralPath $helper).Hash.ToLowerInvariant()
$failure=$null
try {
 Register-InstallationEventRetry @{HelperPath=$helper;HelperHash=$hash;LaunchDirectory=$launch} `
   -ExistingOnly:($Case -clike 'settled-*') -AllowHandover:($Case -cne 'unlocked-prior-helper')
}
catch {$failure=$_}
$expected=if($Case -cin @('new','create-race')){'2'}elseif($Case -cin @('previous-helper','settled-prior-helper')){'4'}else{''}
if(($script:registrations -join ',') -cne $expected){throw "unexpected Scheduler creation flags: $script:registrations"}
if(($null -ne $failure) -ne ($Case -cnotin @('new','resume','previous-helper','normalized-dacl','settled-absent','settled-prior-helper','unlocked-prior-helper'))){throw "unexpected Scheduler ownership result: $Case : $failure"}
if($Case -ceq 'new' -and ($task.Definition.Actions.Item(1).Arguments -cne $mode -or $task.Definition.Triggers.Item(2).Type -ne 8)){
 throw 'registered task may not resume notification only after reboot'
}
if($Case -cin @('previous-helper','settled-prior-helper') -and $task.Definition.Actions.Item(1).Path -cne $helper){
 throw 'handed-over task still runs the previous sender'
}
'passed'
''', encoding='utf-8')
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source), case],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'


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

@pytest.mark.skipif(os.name != 'nt', reason='actual PowerShell recovery task ordering')
@pytest.mark.parametrize('failure', ['none', 'flush', 'wrong-xml', 'wrong-acl', 'wrong-group', 'wrong-owner'])
def test_recovery_registration_is_durable_before_prepared(tmp_path, failure):
    source = Path(__file__).resolve().parents[2] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'recovery-registration.ps1'
    script.write_text(r'''param($Source,$Failure)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse failure'}
foreach($name in @('Register-StagedRecoveryTask','Invoke-StagedOnlinePreparation')){
 $node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
 Invoke-Expression $node.Extent.Text
}
Add-Type -TypeDefinition @"
namespace EndpointInstallerBridge {
 public static class BootMarker {
   public static System.Collections.Generic.List<string> Steps = new System.Collections.Generic.List<string>();
   public static bool Fail;
   public static string Capture(string operation){ Steps.Add("capture"); return "boot-proof"; }
   public static void FlushRegistration(string operation){
     Steps.Add("flush:" + operation);
     if(Fail) throw new System.InvalidOperationException("RECOVERY_REQUIRED");
   }
 }
 public static class Policy {
   public static string Hex(byte[] value){ BootMarker.Steps.Add("xml"); return "xml-digest"; }
 }
 public static class PackageHelper {
   public static void WriteCapability(string path,byte[] value){
     BootMarker.Steps.Add("inputs");
     System.IO.File.WriteAllBytes(path,value);
   }
 }
}
"@
[EndpointInstallerBridge.BootMarker]::Fail=$Failure -ne 'none'
function Step($Name){[EndpointInstallerBridge.BootMarker]::Steps.Add($Name)}
function New-DisposableStub {
 $v=[pscustomobject]@{}
 $v|Add-Member ScriptMethod Dispose {}
 $v|Add-Member ScriptMethod OwnerLost {}
 $v
}
function New-InstallerBridge { $global:bridge }
function Copy-InstallerRecoveryInputs { @{directory=$PSScriptRoot;files=@{}} }
function New-InstallerPublicStateRoot($Path) { $null=New-Item -ItemType Directory -Force $Path }
function Get-ScheduledTask {}
function New-ScheduledTaskAction {}
function New-ScheduledTaskTrigger {}
function New-ScheduledTaskPrincipal {}
function New-StagedRecoverySettings {}
function Register-ScheduledTask { Step 'register' }
function Start-ScheduledTask { Step 'start' }
function New-Object {
 $task=[pscustomobject]@{Xml='<task/>';Path="\EndpointStagedRecovery-$id";Security=$null;State=3}
 $task|Add-Member ScriptMethod SetSecurityDescriptor {$this.Security=$args[0];Step 'acl'}
 $task|Add-Member ScriptMethod GetSecurityDescriptor {$this.Security}
 $folder=[pscustomobject]@{Task=$task;Reads=0}
 $folder|Add-Member ScriptMethod GetTask {
    $this.Reads++
    if ($this.Reads -gt 1) {
      if($Failure -eq 'wrong-xml'){$this.Task.Xml='<changed/>'}
      if($Failure -eq 'wrong-acl'){$this.Task.Security='O:BAG:BAD:P(A;;FA;;;SY)'}
      if($Failure -eq 'wrong-group'){$this.Task.Security='O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)'}
    }
    $this.Task
 }
 $folder|Add-Member ScriptMethod DeleteTask {
    if($args[0] -cne "EndpointStagedRecovery-$id"){throw 'Wrong task deletion'}
    Step 'delete'
    $this.Task=$null
 }
 $scheduler=[pscustomobject]@{Folder=$folder}
 $scheduler|Add-Member ScriptMethod Connect {}
 $scheduler|Add-Member ScriptMethod GetFolder {$this.Folder}
 $scheduler
}
function Invoke-InstallerHelper {
 Step 'stage'
 [pscustomobject]@{result='staged-prepared';phase='prepared';operation_id=$id;
    rollback_media=@{new=@{release=@{package_sha256='pkg'};helper_sha256='helper'};old=@{}}}
}
function Get-StagedRollbackMedia { $PSScriptRoot }
$id='11111111-1111-4111-8111-111111111111'
$stub=New-DisposableStub
$stub|Add-Member NoteProperty Alive ($Failure -ne 'wrong-owner')
$stub|Add-Member NoteProperty Identity @{Pid=$PID;Elevated=$true}
$stub|Add-Member NoteProperty TransactionId $id
$stub|Add-Member ScriptMethod CheckRecoveryRegistrationOwner {
 if(!$args[0].Alive -or $args[1] -cne $this.TransactionId){throw 'OWNER_AUTH_FAILED'}
}
$global:bridge=@{TransactionId=$id;Capability=@{transaction_id=$id;owner=@{pid=$PID};package=@{package_sha256='pkg'}};
    Policy=$stub;Channel=$stub;Owner=$stub;Peers=@()}
$observedFailure=$false
try{
 $null=Invoke-StagedOnlinePreparation -Bridge $bridge -Manifest @{package_sha256='pkg'} -HelperPath 'helper' -HelperHash 'helper' -StateRoot $PSScriptRoot -ServiceStates @{} -Selection @{} -CacheRoot $PSScriptRoot -ObserveAgent {'stable'} -PrepareRecovery {
   param($owner) Register-StagedRecoveryTask -Bridge $owner -StateRoot $PSScriptRoot
 }
}catch{
 if($_.Exception.Message -notmatch 'RECOVERY_REQUIRED'){throw}
 $observedFailure=$true
}
$steps=[EndpointInstallerBridge.BootMarker]::Steps -join ','
$expected="capture,register,acl,xml,inputs,flush:$id"
if($Failure -eq 'none'){$expected+=',start,stage'}
if($Failure -eq 'flush'){$expected+=',delete'}
if($steps -cne $expected -or $observedFailure -ne ($Failure -ne 'none')){throw "Unexpected recovery sequence: $steps"}
$inputs=Get-Content -LiteralPath (Join-Path $PSScriptRoot "staged-recovery\$id\inputs.json") -Raw|ConvertFrom-Json
if($inputs.operation_id -cne $id -or $inputs.boot -cne 'boot-proof' -or $inputs.task_sha256 -cne 'xml-digest'){
 throw 'Registration barrier lost the original recovery inputs'
}
'passed'
''', encoding='utf-8')
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source), failure],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == 'passed'
    assert ('STAGED_RECOVERY_REGISTRATION_CLEANUP_REQUIRED' in result.stdout) == failure.startswith('wrong-')
