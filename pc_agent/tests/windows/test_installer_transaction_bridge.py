"""Execute the actual owner-thread policy with modeled process evidence."""
from pathlib import Path
import os
import subprocess
import pytest
from pc_agent.tests.windows.test_installer_fence import native_protected_root


@pytest.mark.skipif(os.name != "nt", reason="compiled bridge uses Windows ACL, named-pipe and MSI native APIs")
@pytest.mark.parametrize('case', ['direct','msi-order','once','owner-loss','identity','read-only','quiescence','sessions','uninstall-finalization','reboot'])
def test_installer_owner_policy(tmp_path,case):
    source=Path(__file__).resolve().parents[3]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'bridge-policy.ps1'
    script.write_text(r'''param($Source,$Case)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse failure'}
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
if($null -eq $node){throw 'owner policy missing'}
Invoke-Expression $node.Extent.Text
Initialize-InstallerBridgeTypes
function Identity($Id,$Created,$Hash,$Elevated=$true,$Sid='S-1-5-21-1'){return [EndpointInstallerBridge.Identity]::new($Id,$Created,$Hash,$Sid,$Elevated)}
function Reject([scriptblock]$Action){$failed=$false;try{& $Action | Out-Null}catch{$failed=$true};if(-not $failed){throw 'unsafe operation accepted'}}
function Admit($Peer,$Phase,$Action='begin'){
 $challenge=$session.Issue($Peer,$Phase,$Action,('e'*64),$session.SessionId)
 $session.Accept($Peer,$challenge,$session.Sign('request',$challenge)) | Out-Null
}
$owner=Identity 100 1000 ('a'*64)
$helper=Identity 200 2000 ('b'*64)
$session=[EndpointInstallerBridge.Policy]::new('11111111-1111-4111-8111-111111111111','33333333-3333-4333-8333-333333333333',('c'*64),'install',$owner,('b'*64),[byte[]](1..32))
if($Case -ne 'quiescence'){$session.MarkQuiescent()}
switch($Case){
 'reboot'{
  $prepared=Identity 199 1999 ('b'*64);$session.RegisterHelper($prepared,'prepare');Admit $prepared 'prepare';Admit $prepared 'prepare' 'complete'
  $session.RegisterMsi((Identity 300 3000 ('d'*64)),'install')
  Admit $helper 'msi-preflight';Admit $helper 'msi-preflight' 'complete'
  $enter=Identity 201 2001 ('b'*64) $true 'S-1-5-18';Admit $enter 'msi-enter';Admit $enter 'msi-enter' 'complete'
  $config=Identity 202 2002 ('b'*64) $true 'S-1-5-18';Admit $config 'foundation-config';Admit $config 'foundation-config' 'complete'
  $commit=Identity 203 2003 ('b'*64) $true 'S-1-5-18';Admit $commit 'msi-complete';Admit $commit 'msi-complete' 'complete'
  foreach($code in @(3010,1641)){
   $session.MarkMsiExited($code)
   Reject {$session.RegisterHelper((Identity 204 2004 ('b'*64)),'reconcile')}
   Reject {$session.RegisterHelper((Identity 205 2005 ('b'*64)),'finish')}
  }
 }
 'uninstall-finalization'{
  $session=[EndpointInstallerBridge.Policy]::new('11111111-1111-4111-8111-111111111111','33333333-3333-4333-8333-333333333333',('c'*64),'uninstall',$owner,('b'*64),[byte[]](1..32))
  $session.Recovery=$true;$session.UninstallFinalization=$true;$session.MarkQuiescent()
  Reject {$session.RegisterHelper($helper,'reconcile')}
  $prepared=Identity 199 1999 ('b'*64);$session.RegisterHelper($prepared,'prepare');Admit $prepared 'prepare';Admit $prepared 'prepare' 'complete'
  $session.RegisterMsi((Identity 300 3000 ('d'*64)),'uninstall')
  Reject {Admit $helper 'uninstall-finalize-enter'}
  Admit $helper 'uninstall-finalize-preflight';Admit $helper 'uninstall-finalize-preflight' 'complete'
  $enter=Identity 201 2001 ('b'*64) $true 'S-1-5-18'
  Reject {Admit $enter 'foundation-config'}
  Admit $enter 'uninstall-finalize-enter';Admit $enter 'uninstall-finalize-enter' 'mutation';Admit $enter 'uninstall-finalize-enter' 'complete'
  Reject {$session.RegisterHelper((Identity 204 2004 ('b'*64)),'reconcile')}
  $commit=Identity 202 2002 ('b'*64) $true 'S-1-5-18'
  Admit $commit 'uninstall-finalize-complete';Admit $commit 'uninstall-finalize-complete' 'complete'
  Reject {$session.RegisterHelper((Identity 204 2004 ('b'*64)),'reconcile')}
  $session.MarkMsiExited(0)
  $session.RegisterHelper((Identity 204 2004 ('b'*64)),'reconcile')
 }
 'sessions'{
  $session.RegisterHelper($helper,'inspect')
  Reject {$session.Issue($helper,'inspect','begin',('e'*64),'22222222-2222-4222-8222-222222222222')}
  if($session.SessionId -ne '33333333-3333-4333-8333-333333333333'){throw 'session identity missing'}
  $old=[EndpointInstallerBridge.Policy]::new($session.TransactionId,'22222222-2222-4222-8222-222222222222',('c'*64),'install',$owner,('b'*64),[byte[]](1..32))
  $old.RegisterHelper($helper,'inspect')
  $oldChallenge=$old.Issue($helper,'inspect','begin',('e'*64),$old.SessionId)
  $fresh=$session.Issue($helper,'inspect','begin',('e'*64),$session.SessionId)
  Reject {$session.Accept($helper,$fresh,$old.Sign('request',$oldChallenge))}
  $directory=Split-Path -Parent $MyInvocation.MyCommand.Path
  $oldPath=Join-Path $directory ($old.SessionId+'.json')
  $freshPath=Join-Path $directory ($session.SessionId+'.json')
  [EndpointInstallerBridge.PackageHelper]::WriteCapability($oldPath,[Text.Encoding]::ASCII.GetBytes('old-session'))
  [EndpointInstallerBridge.PackageHelper]::WriteCapability($freshPath,[Text.Encoding]::ASCII.GetBytes('fresh-session'))
  Reject {[EndpointInstallerBridge.PackageHelper]::WriteCapability($oldPath,[Text.Encoding]::ASCII.GetBytes('replacement'))}
  if([IO.File]::ReadAllText($oldPath) -cne 'old-session' -or [IO.File]::ReadAllText($freshPath) -cne 'fresh-session'){throw 'capability was overwritten'}
 }
 'quiescence'{
  Reject {$session.RegisterHelper($helper,'prepare')}
  Reject {$session.RegisterMsi((Identity 300 3000 ('d'*64)),'install')}
  $session.RegisterHelper($helper,'inspect');Admit $helper 'inspect';Admit $helper 'inspect' 'complete'
  Reject {$session.RegisterHelper((Identity 201 2001 ('b'*64)),'prepare')}
  $session.MarkQuiescent()
  $next=Identity 202 2002 ('b'*64)
  $session.RegisterHelper($next,'prepare');Admit $next 'prepare'
 }
 'direct'{
  Reject {$session.Issue($helper,'prepare','begin',('e'*64),$session.SessionId)}
  $session.RegisterHelper($helper,'inspect');Admit $helper 'inspect'
  Reject {$session.Issue($helper,'prepare','begin',('e'*64),$session.SessionId)}
  Admit $helper 'inspect' 'complete'
  if(-not $session.AllHelpersComplete){throw 'completion not recorded'}
 }
 'msi-order'{
  Reject {$session.Issue($helper,'msi-enter','begin',('e'*64),$session.SessionId)}
  Reject {$session.RegisterMsi((Identity 300 3000 ('d'*64)),'install')}
  $prepared=Identity 199 1999 ('b'*64);$session.RegisterHelper($prepared,'prepare');Admit $prepared 'prepare';Admit $prepared 'prepare' 'complete'
  $session.RegisterMsi((Identity 300 3000 ('d'*64)),'install')
  Reject {$session.Issue($helper,'msi-enter','begin',('e'*64),$session.SessionId)}
  Admit $helper 'msi-preflight';Admit $helper 'msi-preflight' 'complete'
  $wrong=Identity 209 2009 ('b'*64)
  Reject {Admit $wrong 'msi-enter'}
  $next=Identity 201 2001 ('b'*64) $true 'S-1-5-18'
  Admit $next 'msi-enter'
  if(-not $session.NativeEntered){throw 'entry not recorded'}
  $session.MarkMsiExited(1618)
  Reject {$session.Issue($next,'msi-enter','mutation',('e'*64),$session.SessionId)}
 }
 'once'{
  $session.RegisterHelper($helper,'prepare')
  $challenge=$session.Issue($helper,'prepare','begin',('e'*64),$session.SessionId)
  $signature=$session.Sign('request',$challenge)
  $session.Accept($helper,$challenge,$signature) | Out-Null
  Reject {$session.Accept($helper,$challenge,$signature)}
 }
 'owner-loss'{
  $session.RegisterHelper($helper,'prepare');Admit $helper 'prepare'
  $session.OwnerLost()
  Reject {$session.Issue($helper,'prepare','mutation',('e'*64),$session.SessionId)}
  if($session.AllHelpersComplete){throw 'lost operation claimed complete'}
 }
 'identity'{
  $session.RegisterHelper($helper,'prepare')
  $challenge=$session.Issue($helper,'prepare','begin',('e'*64),$session.SessionId)
  Reject {$session.Accept((Identity 200 2001 ('b'*64)),$challenge,$session.Sign('request',$challenge))}
 }
 'read-only'{
  $session.RegisterHelper($helper,'inspect');Admit $helper 'inspect'
  Reject {$session.Issue($helper,'inspect','mutation',('e'*64),$session.SessionId)}
  Reject {$session.RegisterHelper((Identity 201 2001 ('b'*64)),'reconcile')}
 }
}
Write-Output 'passed'
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
        '-File',str(script),str(source),case],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='passed'


def test_client_binds_each_mutation_and_completion_to_fresh_owner_challenge():
    import hashlib
    import hmac
    from types import SimpleNamespace
    from pc_agent.platform.windows.installer_transaction_bridge import BridgeClient
    cap={'session_id':'33333333-3333-4333-8333-333333333333','transaction_id':'11111111-1111-4111-8111-111111111111','secret':'11'*32,
        'operation':'install','package':{'package_sha256':'c'*64}}
    identity=SimpleNamespace(value={'pid':200,'created':2000},assert_alive=lambda:None)
    class Transport:
        def __init__(self): self.sequence=0;self.actions=[];self.response=None
        def sign(self,prefix):
            return hmac.new(bytes.fromhex(cap['secret']),(prefix+'|'+self.transcript).encode(),'sha256').hexdigest()
        def send(self,value):
            if 'phase' in value:
                self.sequence+=1;self.actions.append(value['action'])
                self.transcript='|'.join(map(str,('1',cap['transaction_id'],cap['session_id'],'c'*64,'install','prepare',value['action'],
                    self.sequence,200,2000,'d'*64,hashlib.sha256(bytes.fromhex(value['payload'])).hexdigest())))
                self.response={'sequence':self.sequence,'nonce':'d'*64,'proof':self.sign('owner')}
            elif 'proof' in value:
                assert value['proof']==self.sign('request')
                self.response={'sequence':self.sequence,'proof':self.sign('grant')}
            else: assert value=={'received':self.sequence}
        def receive(self): return self.response
    transport=Transport()
    client=BridgeClient(cap,'prepare',transport,identity,identity)
    client.request('begin');client.checkpoint();client.checkpoint();client.request('complete',{'result':'handoff'})
    assert transport.actions==['begin','mutation','mutation','complete']
    with pytest.raises(ValueError): client.checkpoint()


def test_client_stops_before_sending_when_owner_has_exited():
    from types import SimpleNamespace
    from pc_agent.platform.windows.installer_transaction_bridge import BridgeClient
    def lost(): raise ValueError('OWNER_AUTH_FAILED')
    calls=[]
    client=BridgeClient({'secret':'11'*32},'prepare',SimpleNamespace(send=calls.append),None,SimpleNamespace(assert_alive=lost))
    with pytest.raises(ValueError,match='OWNER_AUTH_FAILED'): client.request('begin')
    assert calls==[]


@pytest.mark.parametrize('operation,states,valid',[
    ('install',(2,3,2,3),True),('install',(3,3,2,3),True),
    ('install',(3,3,3,2),False),('retire-initial-runtime',(3,3,3,2),True),
    ('retire-initial-runtime',(3,2,3,2),False),('retire-initial-runtime',(3,3,2,2),False),
    ('uninstall',(3,2,3,2),True),('uninstall',(3,3,3,2),False),
])
def test_native_feature_plan_matches_owner_operation(operation,states,valid):
    from pc_agent.platform.windows.installer_transaction_bridge import validate_feature_plan
    if valid: validate_feature_plan(operation,states,rollback_disabled='')
    else:
        with pytest.raises(ValueError): validate_feature_plan(operation,states,rollback_disabled='')


def test_rollback_disabled_policy_rejects_before_any_mutation():
    from pc_agent.platform.windows.installer_transaction_bridge import validate_feature_plan
    with pytest.raises(ValueError): validate_feature_plan('install',(2,3,2,3),rollback_disabled='1')


@pytest.mark.parametrize('operation,recovery,states,valid',[
    ('uninstall',True,(-1,-1,-1,-1),True),('uninstall',True,(-1,2,-1,2),True),
    ('uninstall',False,(-1,2,-1,2),False),('install',True,(-1,2,-1,2),False),
    ('uninstall',True,(-1,3,-1,2),False),('uninstall',True,(3,2,-1,2),False)])
def test_absent_uninstall_feature_plan_is_only_a_disabled_recovery_branch(operation,recovery,states,valid):
    from pc_agent.platform.windows.installer_transaction_bridge import validate_feature_plan
    if valid: validate_feature_plan(operation,states,rollback_disabled='',recovery=recovery,finalization=True)
    else:
        with pytest.raises(ValueError): validate_feature_plan(operation,states,rollback_disabled='',recovery=recovery,finalization=True)


def test_local_transport_completes_bounded_request_on_owner_thread(tmp_path):
    import os
    import time
    import uuid
    if os.name!='nt': pytest.skip('Windows local pipe transport')
    from pc_agent.platform.windows.installer_transaction_bridge import PipeTransport
    source=Path(__file__).resolve().parents[3]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'pipe-owner.ps1'
    ready=tmp_path/'ready'
    pipe='EndpointInstaller-'+str(uuid.uuid4())+'-'+uuid.uuid4().hex
    script.write_text(r'''param($Source,$Pipe,$Ready)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $node.Extent.Text
Initialize-InstallerBridgeTypes
$ownerThread=[Threading.Thread]::CurrentThread.ManagedThreadId
$channel=[EndpointInstallerBridge.Channel]::new($Pipe)
try {
 [IO.File]::WriteAllText($Ready,'ready')
 $timer=[Diagnostics.Stopwatch]::StartNew()
 do {
  if($timer.Elapsed.TotalSeconds -gt 10){throw 'bounded receive timeout'}
  $packet=$channel.Poll()
  if($null -eq $packet){Start-Sleep -Milliseconds 1}
 } while($null -eq $packet)
 if([Threading.Thread]::CurrentThread.ManagedThreadId -ne $ownerThread){throw 'owner thread changed'}
 $value=[Text.Encoding]::ASCII.GetString($packet) | ConvertFrom-Json
 if($value.phase -ne 'inspect'){throw 'unexpected request'}
 $channel.Send([Text.Encoding]::ASCII.GetBytes('{"accepted":true}'))
 do {
  if($timer.Elapsed.TotalSeconds -gt 10){throw 'bounded acknowledgement timeout'}
  $ack=$channel.Poll()
  if($null -eq $ack){Start-Sleep -Milliseconds 1}
 } while($null -eq $ack)
 if([Text.Encoding]::ASCII.GetString($ack) -ne '{"received":true}'){throw 'acknowledgement mismatch'}
 $channel.Disconnect()
} finally {$channel.Dispose()}
''',encoding='utf-8')
    log=tmp_path/'pipe-owner.log'
    with log.open('w') as output:
        process=subprocess.Popen(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script),str(source),pipe,str(ready)],stdout=output,stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            deadline=time.monotonic()+10
            while not ready.exists() and process.poll() is None and time.monotonic()<deadline: time.sleep(.02)
            assert ready.exists(),log.read_text()
            client=PipeTransport(pipe)
            try:
                client.send({'phase':'inspect'})
                assert client.receive()=={'accepted':True}
                client.send({'received':True})
            finally: client.close()
            assert process.wait(timeout=15)==0,log.read_text()
        finally:
            if process.poll() is None:
                process.terminate();process.wait(timeout=5)


@pytest.mark.skipif(os.name != "nt", reason="native ProgramFiles ACL and process creation contract")
def test_helper_launch_uses_protected_directory_and_explicit_process_configuration(tmp_path,native_protected_root):
    source=Path(__file__).resolve().parents[3]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'launch-configuration.ps1'
    directory=native_protected_root/'owned-transaction'
    script.write_text(r'''param($Source,$Directory)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $node.Extent.Text
Initialize-InstallerBridgeTypes
[EndpointInstallerBridge.LaunchDirectory]::Create($Directory)
[EndpointInstallerBridge.LaunchDirectory]::Validate($Directory)
$info=[EndpointInstallerBridge.LaunchDirectory]::StartInfo('C:\Program Files\Endpoint\helper.exe','--installer-phase inspect --installer-session 11111111-1111-4111-8111-111111111111',$Directory)
if($info.UseShellExecute -or -not $info.CreateNoWindow -or $info.WorkingDirectory -cne $Directory -or $info.EnvironmentVariables['TEMP'] -cne $Directory -or $info.EnvironmentVariables['TMP'] -cne $Directory){throw 'launch configuration mismatch'}
$acl=[IO.Directory]::GetAccessControl($Directory)
if(-not $acl.AreAccessRulesProtected){throw 'inherited DACL'}
$sids=@($acl.Access | ForEach-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value} | Sort-Object)
if([string]::Join('|',$sids) -ne 'S-1-5-18|S-1-5-32-544'){throw 'unexpected readers'}
$failed=$false;try{[EndpointInstallerBridge.LaunchDirectory]::Create($Directory)}catch{$failed=$true}
if(-not $failed){throw 'existing launch directory replaced'}
Write-Output 'passed'
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
        '-File',str(script),str(source),str(directory)],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='passed'
