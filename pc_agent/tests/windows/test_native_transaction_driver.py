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
    'discard-old','discard-end','pending-discard','repair-valid','repair-owner','repair-flag-loss'])
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
 if($Case -in @('valid','replaceable-media','discard-old','discard-end','pending-discard','repair-valid')){
  if($rejected -or $driver.HasNativeTransaction -or $compound.State -cne 'prepared'){throw 'construction performed native transaction'}
  $denied=$false;try{$driver.PublishCompletion('55555555-5555-4555-8555-555555555555',('a'*40),('b'*64))}catch{$denied=$true}
  if(!$denied){throw 'unsettled driver published terminal authority'}
  foreach($path in @($oldPath,$newPath)){
   $blocked=$false;try{$writer=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete);$writer.Dispose()}catch{$blocked=$true}
   if(!$blocked){throw 'native pathname is replaceable'}
   $blocked=$false;try{[IO.File]::Delete($path)}catch{$blocked=$true}
   if(!$blocked){throw 'native pathname is deletable'}
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
  if($Case -in @('discard-old','discard-end','pending-discard')){
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
