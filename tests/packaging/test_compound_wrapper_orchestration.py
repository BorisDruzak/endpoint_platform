"""The real wrapper orders native calls and postconditions without invoking MSI."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.skipif(os.name!='nt',reason='actual PowerShell orchestration')
@pytest.mark.parametrize('case',['commit','old-failure','new-failure','old-reboot','new-reboot','pump-loss','end-failure','publication-loss',
    'repair-commit','repair-failure','repair-publication-loss','replacement-recovery'])
def test_compound_wrapper_never_finalizes_failed_or_unsettled_native_work(tmp_path,case):
    source=Path(__file__).resolve().parents[2]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'compound.ps1'
    script.write_text(r'''param($Source,$Case)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
foreach($name in @('Initialize-InstallerBridgeTypes','Invoke-CompoundFoundationUpgrade')){
 $node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 if($null -eq $node){throw 'compound orchestration is missing'}
 Invoke-Expression $node.Extent.Text
}
Initialize-InstallerBridgeTypes
$owner=[EndpointInstallerBridge.Identity]::new(100,1000,('a'*64),'S-1-5-18',$true)
$global:events=[Collections.Generic.List[string]]::new()
function Bridge($id,$session,$package,$hash,$op){
 $policy=[EndpointInstallerBridge.Policy]::new($id,$session,$package,$op,$owner,$hash,[byte[]](1..32));$policy.MarkQuiescent()
 if($Case -eq 'replacement-recovery' -or ($Case.StartsWith('repair-') -and $op -eq 'install')){$policy.Recovery=$true}
 $peer=[EndpointInstallerBridge.Identity]::new($(if($op -eq 'uninstall'){200}else{201}),2000,$hash,'S-1-5-18',$true)
 $policy.RegisterHelper($peer,'prepare')
 foreach($action in @('begin','complete')){$grant=$policy.Issue($peer,'prepare',$action,('9'*64),$session);$policy.Accept($peer,$grant,$policy.Sign('request',$grant))|Out-Null}
 $channel=[pscustomobject]@{};$channel|Add-Member ScriptMethod Dispose {$global:events.Add('channel-closed')}
 return @{Policy=$policy;Owner=$owner;Channel=$channel;Peers=@();SessionId=$session;TransactionId=$id;
  Capability=@{compound=@{upgrade_id='55555555-5555-4555-8555-555555555555'};package=@{source_revision=('a'*40)}}}
}
$old=Bridge '11111111-1111-4111-8111-111111111111' '22222222-2222-4222-8222-222222222222' ('b'*64) ('c'*64) 'uninstall'
$new=Bridge '33333333-3333-4333-8333-333333333333' '44444444-4444-4444-8444-444444444444' ('d'*64) ('e'*64) 'install'
$mode='fresh'
if($Case.StartsWith('repair-')){$mode='repair-successor'}elseif($Case -eq 'replacement-recovery'){$mode='replace-foundation'}
if($mode -ne 'fresh'){$new.Capability.recovery=$true;$new.Capability.compound.recovery=@{mode=$mode};$new.Capability.compound.old=@{package=@{package_sha256=('b'*64)}}}
$global:driver=[pscustomobject]@{PendingTask=$null;HasNativeTransaction=$false}
$driver|Add-Member ScriptMethod BeginNative {$global:events.Add('begin');$this.HasNativeTransaction=$true}
$driver|Add-Member ScriptMethod StartOldScript {$global:events.Add('old');$this.PendingTask=[Threading.Tasks.Task]::FromResult([uint32]0)}
$driver|Add-Member ScriptMethod CompleteOldScript {$this.PendingTask=$null;return $(if($Case -eq 'old-failure'){1603}elseif($Case -eq 'old-reboot'){3010}else{0})}
$driver|Add-Member ScriptMethod StartNewScript {$global:events.Add('new');$this.PendingTask=[Threading.Tasks.Task]::FromResult([uint32]0)}
$driver|Add-Member ScriptMethod CompleteNewScript {$this.PendingTask=$null;return $(if($Case -in @('new-failure','repair-failure')){1603}elseif($Case -eq 'new-reboot'){1641}else{0})}
$driver|Add-Member ScriptMethod StartEnd {param($commit)if(!$commit){throw 'normal path requested rollback'};$global:events.Add('end');$this.PendingTask=[Threading.Tasks.Task]::FromResult([uint32]0)}
$driver|Add-Member ScriptMethod CompleteEnd {$this.PendingTask=$null;if($Case -eq 'end-failure'){return 1603};$this.HasNativeTransaction=$false;return 0}
$driver|Add-Member ScriptMethod DiscardInterruptedCall {$global:events.Add('discard');$this.PendingTask=$null}
$driver|Add-Member ScriptMethod StartAbort {$global:events.Add('abort');$this.PendingTask=[Threading.Tasks.Task]::FromResult([uint32]0)}
$driver|Add-Member ScriptMethod CompleteAbort {$this.PendingTask=$null;$this.HasNativeTransaction=$false;return 0}
$driver|Add-Member ScriptMethod Dispose {if($this.HasNativeTransaction -or $null -ne $this.PendingTask){throw 'active native transaction disposed'};$global:events.Add('disposed')}
$driver|Add-Member ScriptMethod PublishCompletion {param($id,$source,$hash)$global:events.Add('published');if($Case -in @('publication-loss','repair-publication-loss')){throw 'RECOVERY_REQUIRED'}}
function New-CompoundNativeDriver {return $global:driver}
function New-InstallerConversation {param($Bridge,$Launched,$Phase,$Native)return @{Bridge=$Bridge}}
function Invoke-CompoundNativePump {if($Case -eq 'pump-loss'){throw 'OWNER_AUTH_FAILED'};$global:events.Add('pump')}
function Invoke-InstallerHelper {param($Bridge,$Phase)$global:events.Add($Phase);if($Phase -eq 'compound-complete'){
 return @{result='compound-ready';marker=@{upgrade_id=$Bridge.Capability.compound.upgrade_id;new_transaction_id=$Bridge.TransactionId;
 old_package_sha256=('b'*64);new_package_sha256=('d'*64);successor_product_code='{22222222-2222-4222-8222-222222222222}';source_revision=('a'*40);ready_sha256=('f'*64)}}}}
$failed=$false
try{Invoke-CompoundFoundationUpgrade -OldBridge $(if($mode -eq 'repair-successor'){$null}else{$old}) -NewBridge $new -OldMedia $null -NewMedia $null -SuccessorProduct '{22222222-2222-4222-8222-222222222222}' -Mode $mode|Out-Null}catch{$failed=$true}
if($Case -in @('commit','replacement-recovery')){
 if($failed -or [string]::Join(',',@($events)) -cne 'begin,old,pump,compound-old-returned,new,pump,compound-new-returned,end,pump,compound-commit,compound-retire,reconcile,finish,compound-complete,published,disposed'){throw 'native/finalization order differs'}
}elseif($Case -eq 'repair-commit'){
 if($failed -or [string]::Join(',',@($events)) -cne 'begin,new,pump,compound-repair-returned,end,pump,compound-repair-commit,compound-retire,reconcile,finish,compound-complete,published,disposed'){throw 'successor-only repair enlisted fictitious old work'}
}elseif($Case -in @('publication-loss','repair-publication-loss')){
 if(!$failed -or !$events.Contains('published') -or $events.Contains('abort') -or !$events.Contains('disposed')){throw 'uncertain publication was rolled back or reported successful'}
}else{
 if(!$failed -or $events.Contains('compound-retire') -or $events.Contains('reconcile') -or $events.Contains('finish') -or $events.Contains('compound-complete')){throw 'failed native work reached finalization'}
 if(!$events.Contains('abort') -or !$events.Contains('disposed')){throw 'native rollback cleanup omitted'}
 if($Case -in @('old-failure','old-reboot','pump-loss') -and $events.Contains('new')){throw 'successor ran after failed predecessor'}
}
Write-Output 'passed'
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source),case],capture_output=True,text=True,timeout=25)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='passed'
