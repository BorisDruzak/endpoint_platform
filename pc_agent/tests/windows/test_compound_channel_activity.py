"""Real two-channel waits, without MSI execution or installer authority."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.skipif(os.name != 'nt', reason='actual Windows overlapped pipe events')
@pytest.mark.parametrize('mode', ['first', 'second', 'native', 'bounds', 'exchange', 'pump', 'owner-loss'])
def test_compound_wait_observes_each_channel_without_consuming_io(tmp_path, mode):
    source = Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'wait.ps1'
    script.write_text(r'''param($Source,$Mode)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $node.Extent.Text
Initialize-InstallerBridgeTypes
Add-Type @'
using System;using System.IO;using System.IO.Pipes;using System.Threading;using System.Threading.Tasks;
public static class CompoundWaitFixture {
 public static Task Run(string[] names,int count) { return Task.Run(()=>{
  var clients=new NamedPipeClientStream[names.Length];
  try {
   for(int i=0;i<names.Length;i++){clients[i]=new NamedPipeClientStream(".",names[i],PipeDirection.InOut,PipeOptions.Asynchronous);clients[i].Connect(5000);}
   for(int i=0;i<count;i++){
    var c=clients[i%clients.Length];byte[] b={1,0,0,0,42};c.Write(b,0,b.Length);c.Flush();
    byte[] reply=new byte[5];int offset=0;while(offset<reply.Length){int got=c.Read(reply,offset,reply.Length-offset);if(got==0)throw new IOException();offset+=got;}
    if(reply[0]!=1||reply[4]!=43)throw new IOException();
   }
  }finally{foreach(var c in clients)if(c!=null)c.Dispose();}
 });}
}
'@
$names=@((('EndpointInstaller-'+[Guid]::NewGuid().ToString('D')+'-'+[Guid]::NewGuid().ToString('N'))),(('EndpointInstaller-'+[Guid]::NewGuid().ToString('D')+'-'+[Guid]::NewGuid().ToString('N'))))
$channels=[EndpointInstallerBridge.Channel[]]@([EndpointInstallerBridge.Channel]::new($names[0]),[EndpointInstallerBridge.Channel]::new($names[1]))
$ownerThread=[Threading.Thread]::CurrentThread.ManagedThreadId
try {
 if($Mode -in @('pump','owner-loss')){
  $pump=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-CompoundNativePump'},$true)
  Invoke-Expression $pump.Extent.Text
  $global:steps=0
  function Invoke-InstallerConversationStep {param($State) $global:steps++;$null=$State.Bridge.Channel.Poll();return $false}
  $driver=[pscustomobject]@{PendingTask=[Threading.Tasks.Task]::Delay(100);Checks=0;Fail=($Mode -eq 'owner-loss')}
  $driver|Add-Member ScriptMethod CheckOwnership {$this.Checks++;if($this.Fail){throw 'OWNER_AUTH_FAILED'}}
  $driver|Add-Member ScriptMethod IsNativeClosurePending {return $false}
  $conversations=@(foreach($channel in $channels){@{Bridge=@{Channel=$channel;Peers=@()};Challenge=$null;Acknowledgement=$null}})
  $denied=$false;try{Invoke-CompoundNativePump $driver $conversations}catch{if($_.Exception.Message -notlike '*OWNER_AUTH_FAILED*'){throw};$denied=$true}
  if($driver.Checks -lt 1){throw 'ownership was not checked'}
  if($Mode -eq 'owner-loss'){if(!$denied -or $global:steps -ne 0){throw 'revoked owner processed conversations'}}
  elseif($denied -or !$driver.PendingTask.IsCompleted -or $global:steps -lt 2){throw 'pump returned without native settlement'}
 }elseif($Mode -eq 'bounds'){
  [EndpointInstallerBridge.Channel]::WaitForAnyActivity($channels,$null,0)
  foreach($ms in @(-1,11)){$denied=$false;try{[EndpointInstallerBridge.Channel]::WaitForAnyActivity($channels,$null,$ms)}catch{$denied=$true};if(!$denied){throw 'unbounded wait admitted'}}
  foreach($bad in @(@(),@($channels[0],$channels[0]),@($channels[0],$null))){$denied=$false;try{[EndpointInstallerBridge.Channel]::WaitForAnyActivity([EndpointInstallerBridge.Channel[]]$bad,$null,0)}catch{$denied=$true};if(!$denied){throw 'invalid channels admitted'}}
 }elseif($Mode -eq 'native'){
  $task=[Threading.Tasks.Task]::FromResult(0)
  $timer=[Diagnostics.Stopwatch]::StartNew()
  [EndpointInstallerBridge.Channel]::WaitForAnyActivity($channels,$task,10)
  if($timer.Elapsed.TotalSeconds -gt 1){throw 'completed native result ignored'}
 }else{
  $count=if($Mode -eq 'exchange'){100}else{1}
  $selected=if($Mode -eq 'first'){@($names[0])}elseif($Mode -eq 'second'){@($names[1])}else{$names}
  $task=[CompoundWaitFixture]::Run([string[]]$selected,$count)
  $received=0;$timer=[Diagnostics.Stopwatch]::StartNew()
  while($received -lt $count){
   if($timer.Elapsed.TotalSeconds -gt 10){throw 'bounded transport timeout'}
   $worked=$false
   foreach($channel in $channels){$packet=$channel.Poll();if($null -ne $packet){if($packet.Length -ne 1 -or $packet[0] -ne 42){throw 'packet altered'};$channel.Send([byte[]]@(43));$received++;$worked=$true;if($received -ge $count){break}}}
   if(!$worked){[EndpointInstallerBridge.Channel]::WaitForAnyActivity($channels,$task,10)}
  }
  if(!$task.Wait(5000)){throw 'reply not delivered'}
  if($task.IsFaulted){throw $task.Exception}
 }
 if([Threading.Thread]::CurrentThread.ManagedThreadId -ne $ownerThread){throw 'owner thread changed'}
 Write-Output 'passed'
}finally{foreach($channel in $channels){$channel.Dispose()}}
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy',
        'Bypass', '-File', str(script), str(source), mode], capture_output=True, text=True,
        timeout=25, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'
