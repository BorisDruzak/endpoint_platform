"""Real write-through move in disposable protected storage, never Agent MSI."""
import os
from pathlib import Path
import subprocess

import pytest
from pc_agent.tests.windows.test_installer_fence import native_protected_root


@pytest.mark.skipif(os.name!='nt',reason='native NTFS publication')
@pytest.mark.parametrize('case',['commit','owner-loss','ready-change','barrier-change','existing',
    'ready-link','marker-acl','source-change','visible-lost-result'])
def test_terminal_file_publication_is_last_authority(tmp_path,native_protected_root,case):
    source=Path(__file__).resolve().parents[2]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'terminal.ps1'
    script.write_text(r'''param($Source,$Root,$Case)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $node.Extent.Text;Initialize-InstallerBridgeTypes
$upgrade='55555555-5555-4555-8555-555555555555';$transaction='33333333-3333-4333-8333-333333333333'
$product='{22222222-2222-4222-8222-222222222222}';$revision='a'*40
$history=Join-Path $Root ('upgrade-history\'+$upgrade)
$readers=@('S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691','S-1-5-80-327494974-20047353-929432329-1920152597-707704661')
foreach($path in @($Root,(Join-Path $Root 'upgrade-history'),$history)){
 [IO.Directory]::CreateDirectory($path)|Out-Null
 $sddl='O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
 foreach($sid in $readers){$sddl+='(A;OICI;0x1200a9;;;'+$sid+')'}
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetSecurityDescriptorSddlForm($sddl);[IO.Directory]::SetAccessControl($path,$acl)
}
$barrier='{"schema_version":1,"upgrade_id":"'+$upgrade+'","new_transaction_id":"'+$transaction+'","old_package_sha256":"'+('b'*64)+'","new_package_sha256":"'+('d'*64)+'"}'
$prefix=$barrier.Substring(0,$barrier.Length-1)+',"successor_product_code":"'+$product+'","source_revision":"'+$revision+'"'
$ready=$prefix+',"phase":"ready"}'
function PublicFile($path,$text){
 [IO.File]::WriteAllText($path,$text,[Text.Encoding]::ASCII)
 $acl=[EndpointInstallerBridge.PackageHelper]::SecretSecurity()
 foreach($sid in $readers){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]0x1200a9,[Security.AccessControl.AccessControlType]::Allow))}
 [IO.File]::SetAccessControl($path,$acl)
}
PublicFile (Join-Path $Root 'upgrade.json') $barrier
PublicFile (Join-Path $history 'barrier.json') $barrier
PublicFile (Join-Path $history 'ready.json') $ready
$sha=[Security.Cryptography.SHA256]::Create();try{$digest=[EndpointInstallerBridge.Policy]::Hex($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($ready)))}finally{$sha.Dispose()}
$final=Join-Path $history 'complete.json'
if($Case -eq 'ready-change'){[IO.File]::AppendAllText((Join-Path $history 'ready.json'),' ')}
if($Case -eq 'barrier-change'){[IO.File]::AppendAllText((Join-Path $Root 'upgrade.json'),' ')}
if($Case -eq 'ready-link'){New-Item -ItemType HardLink -Path (Join-Path $history 'alias.json') -Target (Join-Path $history 'ready.json')|Out-Null}
if($Case -eq 'existing'){PublicFile $final 'immutable previous evidence'}
if($Case -eq 'marker-acl'){[IO.File]::SetAccessControl((Join-Path $history 'ready.json'),[EndpointInstallerBridge.PackageHelper]::SecretSecurity())}
if($Case -eq 'source-change'){$revision='e'*40}
$global:checks=0
$check=[Action]{ $global:checks++;if($Case -eq 'owner-loss' -and $global:checks -eq 3){throw 'OWNER_AUTH_FAILED'} }
$type=[EndpointInstallerBridge.Policy].Assembly.GetType('EndpointInstallerBridge.TerminalPublication')
$method=$type.GetMethod('PublishAt',[Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static)
$failed=$false
try{
 $method.Invoke($null,[object[]]@($Root,$upgrade,$transaction,('b'*64),('d'*64),$product,$revision,$digest,$check))|Out-Null
 if($Case -eq 'visible-lost-result'){throw 'controller lost terminal result'}
}catch{$failed=$true}
if($Case -in @('commit','visible-lost-result')){
 if($failed -ne ($Case -eq 'visible-lost-result') -or !(Test-Path -LiteralPath $final)){throw 'publication/result distinction lost'}
 $marker=[IO.File]::ReadAllText($final)|ConvertFrom-Json
 if($marker.ready_sha256 -cne $digest -or $marker.upgrade_id -cne $upgrade -or $checks -ne 3){throw 'terminal binding differs'}
}else{
 if(!$failed){throw 'unsafe final publication accepted'}
 if($Case -eq 'existing'){if([IO.File]::ReadAllText($final) -cne 'immutable previous evidence'){throw 'historical marker overwritten'}}
 elseif(Test-Path -LiteralPath $final){throw 'failure admitted launch'}
}
Write-Output 'passed'
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source),str(native_protected_root),case],capture_output=True,text=True,timeout=25)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='passed'
