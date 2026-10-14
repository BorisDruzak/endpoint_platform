"""Driver construction validates retained owner/media without invoking MSI.

These tests never begin a native transaction on the operator workstation.
Native transaction behavior is separately observed on the dedicated guest.
"""
import os
from pathlib import Path
import subprocess

import pytest
from pc_agent.tests.windows.test_installer_fence import native_protected_root


@pytest.mark.skipif(os.name != 'nt', reason='native Windows retained owner')
@pytest.mark.parametrize('case',['valid','owner','media','writable','product','wrong-successor','replaceable-media',
    'discard-old','discard-end','pending-discard','repair-valid','repair-owner','repair-flag-loss',
    'closed-end-event','closed-abort-event','premature-event','missing-callback-event','revoked-end-event',
    'pending-end-event','pending-failed-end-event','pending-missing-callback-event','closed-rollback-event',
    'pending-pump-success-event','pending-pump-failure-event','pending-pump-race-event'])
def test_native_driver_preconditions_without_beginning_msi(tmp_path,native_protected_root,case):
    source=Path(__file__).resolve().parents[3]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'driver.ps1'
    script.write_text(r'''param($Source,$Case,$Directory)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse failure'}
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $node.Extent.Text;Initialize-InstallerBridgeTypes
if(!('EndpointInstallerBridge.NativeTransaction' -as [type])){throw 'native driver is missing'}
$oldPath=Join-Path $Directory 'public-old.msi';$newPath=Join-Path $Directory 'public-new.msi'
$installer=New-Object -ComObject WindowsInstaller.Installer
foreach($path in @($oldPath,$newPath)){
 $db=$installer.OpenDatabase($path,3)
 $view=$db.OpenView('CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) LOCALIZABLE PRIMARY KEY `Property`)');$view.Execute();$view.Close()
 $code=$(if($path -eq $oldPath){'{11111111-1111-4111-8111-111111111111}'}else{'{22222222-2222-4222-8222-222222222222}'})
 $view=$db.OpenView("INSERT INTO ``Property`` (``Property``, ``Value``) VALUES ('ProductCode', '$code')");$view.Execute();$view.Close();$db.Commit()
 [Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)|Out-Null
 [Runtime.InteropServices.Marshal]::FinalReleaseComObject($db)|Out-Null
 [IO.File]::SetAccessControl($path,[EndpointInstallerBridge.PackageHelper]::SecretSecurity())
}
[Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)|Out-Null
$view=$null;$db=$null;$installer=$null;[GC]::Collect();[GC]::WaitForPendingFinalizers()
$hash=[Security.Cryptography.SHA256]::Create()
try{$oldHash=[EndpointInstallerBridge.Policy]::Hex($hash.ComputeHash([IO.File]::ReadAllBytes($oldPath)));$newHash=[EndpointInstallerBridge.Policy]::Hex($hash.ComputeHash([IO.File]::ReadAllBytes($newPath)))}finally{$hash.Dispose()}
$retained=[EndpointInstallerBridge.NativeProcess]::new($PID)
$owner=$retained.Identity
if($Case -in @('owner','repair-owner')){$owner=[EndpointInstallerBridge.Identity]::new(1,10,('a'*64),'S-1-5-18',$true)}
$old=[EndpointInstallerBridge.Policy]::new('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222',$oldHash,'uninstall',$owner,('b'*64),[byte[]](1..32))
$new=[EndpointInstallerBridge.Policy]::new('33333333-3333-4333-8333-333333333333','44444444-4444-4444-8444-444444444444',$newHash,'install',$owner,('f'*64),[byte[]](33..64))
if($Case.StartsWith('repair-')){$new.Recovery=$true}
foreach($policy in @($old,$new)){
 $policy.MarkQuiescent();$peer=[EndpointInstallerBridge.Identity]::new($(if($policy -eq $old){200}else{201}),2000,$policy.HelperHash,'S-1-5-18',$true)
 $policy.RegisterHelper($peer,'prepare')
 foreach($action in @('begin','complete')){
  $grant=$policy.Issue($peer,'prepare',$action,('9'*64),$policy.SessionId)
  $policy.Accept($peer,$grant,$policy.Sign('request',$grant))|Out-Null
 }
}
if($Case.StartsWith('repair-')){$compound=[EndpointInstallerBridge.SuccessorRepairPolicy]::new($new,$oldHash)}
else{$compound=[EndpointInstallerBridge.CompoundPolicy]::new($old,$new)}
if($Case -eq 'repair-flag-loss'){$new.Recovery=$false}
if($Case -eq 'media'){[IO.File]::WriteAllText($oldPath,'modified public fixture')}
$access=$(if($Case -eq 'writable'){[IO.FileAccess]::ReadWrite}else{[IO.FileAccess]::Read})
$share=$(if($Case -eq 'replaceable-media'){[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete}else{[IO.FileShare]::Read})
$oldPin=[IO.File]::Open($oldPath,[IO.FileMode]::Open,$access,$share)
$newPin=[IO.File]::Open($newPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
$product=$(if($Case -eq 'product'){'not-a-product; OTHER=1'}elseif($Case -eq 'wrong-successor'){'{33333333-3333-4333-8333-333333333333}'}else{'{22222222-2222-4222-8222-222222222222}'})
$driver=$null
try{
 $rejected=$false
 try{$driver=[EndpointInstallerBridge.NativeTransaction]::new($compound,$retained,$oldPin,$newPin,$product)}catch{$rejected=$true}
 if($Case -in @('valid','replaceable-media','discard-old','discard-end','pending-discard','repair-valid',
     'closed-end-event','closed-abort-event','premature-event','missing-callback-event','revoked-end-event',
     'pending-end-event','pending-failed-end-event','pending-missing-callback-event','closed-rollback-event',
     'pending-pump-success-event','pending-pump-failure-event','pending-pump-race-event')){
  if($rejected -or $driver.HasNativeTransaction -or $compound.State -cne 'prepared'){throw 'construction performed native transaction'}
  $denied=$false;try{$driver.PublishCompletion('55555555-5555-4555-8555-555555555555',('a'*40),('b'*64))}catch{$denied=$true}
  if(!$denied){throw 'unsettled driver published terminal authority'}
  foreach($path in @($oldPath,$newPath)){
   $blocked=$false;try{$writer=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete);$writer.Dispose()}catch{$blocked=$true}
   if(!$blocked){throw 'native pathname is replaceable'}
   $blocked=$false;try{[IO.File]::Delete($path)}catch{$blocked=$true}
   if(!$blocked){throw 'native pathname is deletable'}
  }
  if($Case.EndsWith('-event')){
   # Modeled native results, paired with a real signaled kernel event. No
   # MSI API is executed. The dedicated native comparison proves this event
   # is normally signaled by successful End, across different worker threads.
   Add-Type 'using System;using System.Runtime.InteropServices;public static class EndEventFixture{[DllImport("kernel32.dll",CharSet=CharSet.Unicode)]public static extern IntPtr CreateEventW(IntPtr a,bool manual,bool initial,string n);}'
   $flags=[Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::NonPublic
   $type=$driver.GetType();$event=[EndEventFixture]::CreateEventW([IntPtr]::Zero,$true,$true,$null)
   if($event -eq [IntPtr]::Zero){throw 'kernel event unavailable'}
   $type.GetField('ownerEvent',$flags).SetValue($driver,$event)
   $type.GetField('transactionOpen',$flags).SetValue($driver,$true)
   if($Case -eq 'premature-event'){
    $blocked=$false;try{$driver.CheckOwnership()}catch{$blocked=$true};if(!$blocked){throw 'owner transfer admitted before End'}
   }else{
    $type.GetField('taskKind',$flags).SetValue($driver,$(if($Case -eq 'closed-abort-event'){'abort'}else{'end'}))
    $type.GetField('task',$flags).SetValue($driver,[Threading.Tasks.Task]::FromResult([uint32]0))
    $compound.GetType().GetField('state',$flags).SetValue($compound,'ending-commit')
    foreach($p in @($old,$new)){$p.GetType().GetField('nativeComplete',$flags).SetValue($p,$true)}
    if($Case.StartsWith('pending-')){
     $completion=[Threading.Tasks.TaskCompletionSource[uint32]]::new()
     $type.GetField('task',$flags).SetValue($driver,$completion.Task)
     if($Case -eq 'pending-missing-callback-event'){$new.GetType().GetField('nativeComplete',$flags).SetValue($new,$false)}
     $blocked=$false;try{$driver.CheckOwnership()}catch{$blocked=$true};if(!$blocked){throw 'pending End granted authority'}
     if($Case -eq 'pending-missing-callback-event'){
      $blocked=$false;try{$null=$driver.IsNativeClosurePending()}catch{$blocked=$true};if(!$blocked){throw 'pending closure ignored missing callback'}
     }elseif($Case.StartsWith('pending-pump-')){
      $pump=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-CompoundNativePump'},$true)
      Invoke-Expression $pump.Extent.Text
      $global:steps=0;$global:waits=0
      function Invoke-InstallerConversationStep {param($State)
       if(!$completion.Task.IsCompleted -or $completion.Task.Result -ne 0){throw 'pump issued a grant before successful End'}
       $global:steps++;return $false
      }
      function Start-Sleep {param($Milliseconds)
       $global:waits++
       $completion.SetResult([uint32]$(if($Case -eq 'pending-pump-failure-event'){1603}else{0}))
      }
      $conversation=@{Bridge=@{Peers=@()};Challenge=$null;Acknowledgement=$null}
      $pumpDriver=$driver
      if($Case -eq 'pending-pump-race-event'){
       $pumpDriver=[pscustomobject]@{PendingTask=$completion.Task;Real=$driver;Completion=$completion}
       $pumpDriver|Add-Member ScriptMethod CheckOwnership {$this.Real.CheckOwnership()}
       $pumpDriver|Add-Member ScriptMethod IsNativeClosurePending {$this.Completion.SetResult([uint32]0);return $this.Real.IsNativeClosurePending()}
      }
      $failed=$false;try{Invoke-CompoundNativePump $pumpDriver @($conversation,$conversation)}catch{
       if($_.Exception.Message -notlike '*OWNER_AUTH_FAILED*'){throw};$failed=$true
      }
      if($global:waits -ne $(if($Case -eq 'pending-pump-race-event'){0}else{1})){throw 'pump did not wait for private End'}
      if($Case -eq 'pending-pump-failure-event'){
       if(!$failed -or $global:steps -ne 0 -or $compound.Committed){throw 'failed End resumed grants'}
      }else{
       if($failed -or $global:steps -ne 2 -or $driver.CompleteEnd() -ne 0 -or !$compound.Committed){throw 'successful End did not settle'}
      }
     }else{
      if(!$driver.IsNativeClosurePending()){throw 'normal pending closure was not recognized'}
      $completion.SetResult([uint32]$(if($Case -eq 'pending-failed-end-event'){1603}else{0}))
      if($driver.IsNativeClosurePending()){throw 'completed closure remained pending'}
      if($Case -eq 'pending-failed-end-event'){
       $blocked=$false;try{$driver.CheckOwnership()}catch{$blocked=$true};if(!$blocked){throw 'failed End granted authority'}
      }else{
       $driver.CheckOwnership()
       if($driver.CompleteEnd() -ne 0 -or $driver.HasNativeTransaction -or !$compound.Committed){throw 'pending successful End rejected'}
      }
     }
    }elseif($Case -eq 'closed-rollback-event'){
     $compound.GetType().GetField('state',$flags).SetValue($compound,'ending-rollback')
     $blocked=$false;try{$driver.CheckOwnership()}catch{$blocked=$true};if(!$blocked){throw 'rollback granted authority'}
     if($driver.CompleteEnd() -ne 0 -or $driver.HasNativeTransaction -or $compound.OwnerActive -or $compound.Committed){throw 'rollback closure restored authority'}
    }elseif($Case -eq 'missing-callback-event'){
     $new.GetType().GetField('nativeComplete',$flags).SetValue($new,$false)
     $blocked=$false;try{$driver.CheckOwnership()}catch{$blocked=$true};if(!$blocked){throw 'missing callback admitted after End'}
     $code=$driver.DiscardInterruptedCall()
     if($code -ne 0 -or $driver.HasNativeTransaction -or $compound.OwnerActive){throw 'discard fabricated completion'}
    }elseif($Case -eq 'revoked-end-event'){
     $compound.OwnerLost();$blocked=$false;try{$driver.CheckOwnership()}catch{$blocked=$true};if(!$blocked){throw 'revoked authority restored'}
     if($driver.DiscardInterruptedCall() -ne 0 -or $driver.HasNativeTransaction){throw 'physical closure unavailable after revocation'}
    }elseif($Case -eq 'closed-abort-event'){
     $compound.OwnerLost();if($driver.CompleteAbort() -ne 0 -or $driver.HasNativeTransaction -or $compound.OwnerActive){throw 'abort closure fabricated authority'}
    }else{
     $driver.CheckOwnership()
     if($driver.CompleteEnd() -ne 0 -or $driver.HasNativeTransaction -or !$compound.Committed){throw 'normal End event rejected'}
     $driver.CheckOwnership()
    }
   }
  }
  if($Case -in @('discard-old','discard-end','pending-discard')){
   # Unit-only modeled completion: no MSI Begin/install/End API is invoked.
   $flags=[Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::NonPublic
   $type=$driver.GetType()
   $kind=$(if($Case -eq 'discard-end'){'end'}else{'old'})
   $type.GetField('taskKind',$flags).SetValue($driver,$kind)
   if($Case -eq 'pending-discard'){$completion=[Threading.Tasks.TaskCompletionSource[uint32]]::new();$task=$completion.Task}else{$task=[Threading.Tasks.Task]::FromResult([uint32]$(if($Case -eq 'discard-end'){0}else{1603}))}
   $type.GetField('task',$flags).SetValue($driver,$task)
   if($Case -eq 'discard-end'){$type.GetField('transactionOpen',$flags).SetValue($driver,$true)}
   if($Case -eq 'pending-discard'){
    $blocked=$false;try{$driver.DiscardInterruptedCall()|Out-Null}catch{$blocked=$true}
    if(!$blocked -or $driver.PendingTask.IsCompleted){throw 'pending call was consumed'}
    $type.GetField('task',$flags).SetValue($driver,$null);$type.GetField('taskKind',$flags).SetValue($driver,$null)
   }else{
    $code=$driver.DiscardInterruptedCall()
    if($code -ne $(if($Case -eq 'discard-end'){0}else{1603}) -or $null -ne $driver.PendingTask -or $driver.HasNativeTransaction -or $compound.OwnerActive){throw 'abandoned result granted authority'}
   }
  }
 }elseif(!$rejected){throw 'untrusted precondition accepted'}
}finally{
 if($null -ne $driver){
  if($Case -in @('discard-old','discard-end','pending-discard') -or $Case.EndsWith('-event')){
   # Remove only reflected unit state so a missing/failed method stays visible.
   $flags=[Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::NonPublic
   $driver.GetType().GetField('task',$flags).SetValue($driver,$null)
   $driver.GetType().GetField('taskKind',$flags).SetValue($driver,$null)
   $driver.GetType().GetField('transactionOpen',$flags).SetValue($driver,$false)
  }
  $driver.Dispose()
 }
 $oldPin.Dispose();$newPin.Dispose();$retained.Dispose()
}
Write-Output 'passed'
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source),case,str(native_protected_root)],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='passed'
