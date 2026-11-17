"""Execute the observer's read-only preparation-cancellation verifier."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from tests.packaging.test_setup_target_recovery import SCRIPT, canonical, OPERATION
from pc_agent.tests.windows.test_installer_fence import native_protected_root


@pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell observer')
@pytest.mark.parametrize('fault', ['none', 'native_manifest_order', 'duplicate_manifest_path', 'wrong_phase', 'wrong_reason', 'old_stage', 'wrong_binding',
    'wrong_source', 'wrong_target', 'unrelated_owner', 'native_attempt', 'live_owner',
    'bad_inputs_owner', 'bad_recovery_owner', 'selector_changed', 'missing_previous',
    'bad_cache', 'wrong_setup', 'tree_changed', 'no_inputs', 'busy', 'bad_input_shape',
    'bad_services', 'bad_task_hash', 'bad_owner_shape'])
def test_source_recovery_descriptor_requires_this_attempts_completed_cancellation(tmp_path, fault):
    source = dict(version='3.2.177', source_revision='a' * 40, package_sha256='b' * 64,
        product_code='{77777777-7777-4777-8777-777777777777}')
    target = dict(version='3.2.185', source_revision='c' * 40, package_sha256='d' * 64)
    owner = dict(pid=2147483000, created=134383746580000000, sid='S-1-5-18', elevated=True, hash='9' * 64)
    selected, previous = b'{"version":"3.2.177"}', b'{"version":"3.2.176"}'
    tree = hashlib.sha256(b'pc_agent.exe\x001\x00' + b'e' * 64 + b'\n').hexdigest()
    manifest_files = [dict(path='pc_agent.exe', size=1, sha256='e' * 64)]
    if fault == 'native_manifest_order':
        manifest_files = [dict(path='z.empty', size=0, sha256='f' * 64), *manifest_files,
                          dict(path='A.dll', size=1, sha256='a' * 64)]
        tree = hashlib.sha256(b'A.dll\x001\x00' + b'a' * 64 + b'\npc_agent.exe\x001\x00' +
                             b'e' * 64 + b'\nz.empty\x000\x00' + b'f' * 64 + b'\n').hexdigest()
    elif fault == 'duplicate_manifest_path':
        manifest_files.append(dict(path='PC_AGENT.EXE', size=1, sha256='e' * 64))
    binding = dict(operation_id=OPERATION, old_release=source, new_release=target,
        candidate_version='3.2.185', candidate_source_revision='c' * 40,
        candidate_tree_sha256='f' * 64, selected_before=selected.hex(), previous_before=previous.hex(),
        selected_tree_sha256_before=tree, previous_tree_sha256_before=tree)
    stage = dict(schema_version='endpoint_windows_staged_update_v1', phase='rolled-back',
        safe_code='preparation_cancelled', binding=binding, binding_sha256=hashlib.sha256(canonical(binding)).hexdigest(),
        owner=owner, switched_at=None, attempt_id=None)
    if fault == 'wrong_phase': stage['phase'] = 'recovery-required'
    if fault == 'wrong_reason': stage['safe_code'] = 'rolled_back'
    if fault == 'wrong_binding': stage['binding_sha256'] = '0' * 64
    if fault == 'wrong_source': source['package_sha256'] = '0' * 64
    if fault == 'wrong_target': target['package_sha256'] = '0' * 64
    if fault == 'unrelated_owner': owner['created'] = 134384000000000000
    recovery = tmp_path / 'staged-recovery' / OPERATION
    recovery.mkdir(parents=True)
    cache = tmp_path / 'installer-cache' / ('msi-' + 'd' * 64)
    cache.mkdir(parents=True)
    files = {}
    for name in ['EndpointAgentSetup.exe', 'EndpointAgent.msi', 'EndpointAgent.release.json', 'Install-EndpointAgentCanary.ps1']:
        data = name.encode()
        (cache / name).write_bytes(data)
        files[name] = hashlib.sha256(data).hexdigest()
    # MSI cached bytes must match the target digest; use that digest consistently.
    target['package_sha256'] = files['EndpointAgent.msi'] if fault != 'wrong_target' else '0' * 64
    actual_digest = files['EndpointAgent.msi']
    cache.rename(cache.with_name('msi-' + actual_digest))
    cache = cache.with_name('msi-' + actual_digest)
    stage['binding_sha256'] = '0' * 64 if fault == 'wrong_binding' else hashlib.sha256(canonical(binding)).hexdigest()
    inputs = dict(schema_version=1, operation_id=OPERATION, owner=owner,
        package_sha256=actual_digest, files=files, boot='registry-boot-v1:test', task_sha256='7' * 64,
        service_states=dict(EndpointAgent='Running', EndpointAgentUpdater='Stopped', EndpointBrowserPolicy='Running'))
    receipt = dict(schema_version=1, operation_id=OPERATION, binding_sha256=stage['binding_sha256'],
        original_owner=owner, owner={**owner, 'pid': 2147483001})
    if fault == 'bad_inputs_owner': inputs['owner'] = {**owner, 'hash': '0' * 64}
    if fault == 'bad_recovery_owner': receipt['binding_sha256'] = '0' * 64
    if fault == 'bad_input_shape': inputs['foreign'] = True
    if fault == 'bad_services': inputs['service_states']['EndpointAgent'] = 'Unknown'
    if fault == 'bad_task_hash': inputs['task_sha256'] = 'invalid'
    if fault == 'bad_owner_shape': receipt['foreign'] = True
    for name, record in [('staged-update.json', stage), (f'staged-recovery/{OPERATION}/inputs.json', inputs),
                         (f'staged-recovery/{OPERATION}/owner.json', receipt)]:
        (tmp_path / name).write_bytes(canonical(record))
    if fault == 'native_attempt': (recovery / 'reboot.json').write_bytes(b'{}')
    if fault == 'no_inputs': (recovery / 'inputs.json').unlink()
    if fault == 'bad_cache': (cache / 'Install-EndpointAgentCanary.ps1').write_bytes(b'altered')
    agent = tmp_path / 'Agent'
    for version in ['3.2.177', '3.2.176']:
        root = agent / 'versions' / version
        root.mkdir(parents=True)
        (root / 'endpoint-update-manifest.json').write_text(json.dumps(dict(files=manifest_files)))
    (agent / 'current.json').write_bytes(selected if fault != 'selector_changed' else b'{"changed":true}')
    if fault != 'missing_previous': (agent / 'previous.json').write_bytes(previous)
    if fault == 'tree_changed': (agent / 'versions/3.2.176/endpoint-update-manifest.json').write_text('{"files":[]}')
    harness = tmp_path / 'source.ps1'
    harness.write_text(r'''
param($Script,$Root,$Fault,$SetupDigest,$MsiDigest)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse failed'}
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){Invoke-Expression $f.Extent.Text}
$script:InstallerState=$Root;$script:AgentRoot=Join-Path $Root 'Agent';$script:ClientVersion='1.0.8'
function Assert-AdministrativePath($p){}
function Assert-NoReparse($p){}
function Read-AdministrativeRecord($p,[switch]$PublicState){Read-BoundedJson $p 65536}
function Test-RecoveryTask($operation,$inputs,$cache){return $true}
function Test-CoreOrNativeBusy{return ($Fault -ceq 'busy')}
if($Fault -ceq 'live_owner'){function Assert-StagedOwnerDead($owner){throw 'owner_alive'}}
$before=@{foundation=@{version='3.2.177';source_revision=('a'*40);package_sha256=('b'*64);product_code='{77777777-7777-4777-8777-777777777777}'};core=@{version='3.2.177';source_revision=('a'*40);package_sha256=('b'*64);origin='msi'}}
$after=@{foundation=$before.foundation;core=(@{}+$before.core);provenance=@{verified=$true;conflict=$false};pending=@{active_or_degraded=$false}}
$after.foundation.native_verified=$true;$after.core.verified=$true
$job=@{native_exit=21;native_started=$true;native_created='2026-11-05T17:50:44Z';native_ended='2026-11-05T17:56:28Z';before=$before;previous_native_id=$null;
 release=@{version='3.2.185';source_revision=('c'*40);msi_sha256=$MsiDigest;sha256=$SetupDigest}}
if($Fault -ceq 'old_stage'){$job.previous_native_id='22222222-2222-4222-8222-222222222222'}
if($Fault -ceq 'wrong_setup'){$job.release.sha256='0'*64}
$result=Get-SourceRecoveryDescriptor $job $after
if($Fault -cin @('none','native_manifest_order')){
 if(!$result -or $result.operation_id -cne '22222222-2222-4222-8222-222222222222' -or $result.source_product_code -cne '{77777777-7777-4777-8777-777777777777}'){throw 'verified source was not admitted'}
 $result|ConvertTo-Json -Compress|Set-Content (Join-Path $Root 'descriptor.json')
}elseif($result){throw 'unverified source released native hold'}
''', encoding='utf-8')
    environment = {key: value for key, value in os.environ.items() if key.lower() != 'psmodulepath'}
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT), str(tmp_path),
        fault, files['EndpointAgentSetup.exe'], actual_digest], capture_output=True, text=True, timeout=25, env=environment)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell observer')
@pytest.mark.parametrize('fault', ['none', 'private', 'no_sensor', 'short_soak', 'changed_source',
    'changed_binding', 'hello_identity', 'busy_after_soak'])
def test_native_completion_rechecks_source_after_fresh_strict_soak(tmp_path, fault):
    harness = tmp_path / 'complete.ps1'
    harness.write_text(r'''
param($Script,$Root,$Fault)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){Invoke-Expression $f.Extent.Text}
$script:InstallerState=$Root;$script:AgentRoot=Join-Path $Root 'Agent';$script:DeviceId='55555555-5555-4555-8555-555555555555';$script:Observations=0;$script:Preflights=0;$script:Refreshes=0
$before=@{foundation=@{version='3.2.177';source_revision=('a'*40);package_sha256=('b'*64)};core=@{version='3.2.177';source_revision=('a'*40);package_sha256=('b'*64);origin='msi'}}
$private=@{'device-credential'='credential';'enrollment-identity.json'='identity';'endpoint-origin'='origin';'endpoint-ca.crt'='ca'}
$job=[pscustomobject]@{assignment_id='33333333-3333-4333-8333-333333333333';device_id=$script:DeviceId;attempt_id='44444444-4444-4444-8444-444444444444';phase='recovery_required';native_exit=21;before=$before;private_before=$private;previous_native_id=$null;soak=$null;release=@{version='3.2.185'};companions=@('preserved source scope')}
function Test-CoreOrNativeBusy{return ($Fault -ceq 'busy_after_soak' -and $script:Observations -gt 0)}
function Test-RecoveredTargetBinding{return $false}
function Get-SourceRecoveryDescriptor($j,$after){if($Fault -ceq 'changed_binding' -and $script:Observations -gt 0){return $null};return @{schema_version='windows_setup_source_recovery_v1';operation_id='22222222-2222-4222-8222-222222222222';binding_sha256=('1'*64);inputs_sha256=('2'*64);owner_sha256=('3'*64);target_version='3.2.185';target_source_revision=('c'*40);target_msi_sha256=('d'*64);target_setup_sha256=('e'*64);source_product_code='{77777777-7777-4777-8777-777777777777}'}}
function Read-SetupPreflight($s){$script:Preflights++;return @{foundation=@{version='3.2.177';source_revision=('a'*40);package_sha256=('b'*64);native_verified=$true};core=@{version='3.2.177';source_revision=('a'*40);package_sha256=('b'*64);origin='msi';verified=($Fault -cne 'changed_source' -or $script:Observations -eq 0)};provenance=@{verified=$true;conflict=$false};pending=@{active_or_degraded=$false};services=@{EndpointAgent=@{identity_valid=$true;state='running';start_mode='automatic'};EndpointAgentUpdater=@{identity_valid=$true;start_mode='manual'}}}}
function Get-PrivateSnapshot{$p=@{}+$private;if($Fault -ceq 'private'){$p['device-credential']='changed'};return $p}
function Get-CimInstance{return @{State='Running';StartName='LocalSystem'}}
function Restore-Companions{throw 'read-only recovered source must not launch or repair companions'}
function Observe-InstalledRuntime($j,$version,$context){if($version -cne '3.2.177' -or !$context -or $context.companions[0] -cne 'preserved source scope'){throw 'strict source scope missing'};$script:Observations++;return @{duration_seconds=$(if($Fault -ceq 'short_soak'){179}else{180});samples=6;sensor_count=$(if($Fault -ceq 'no_sensor'){0}else{1});sensor_cpu_percent_max=0;services_stable=$true;companions_stable=$true;connected=$true}}
function Get-ClientHello{return @{client_version='1.0.8';core_version='3.2.177';foundation_version='3.2.177';ready=$true}}
function Invoke-EndpointJson($method,$path,$body){if($path -cne '/agent/v1/setup-updates/hello' -or $script:Observations -ne 1){throw 'fresh hello missing'};$script:Refreshes++;return @{device_id=$(if($Fault -ceq 'hello_identity'){'66666666-6666-4666-8666-666666666666'}else{$script:DeviceId})}}
function Send-Progress($j,$phase,$proof,$code){$j.phase=$phase;@{attempt_id=$j.attempt_id;phase=$phase;proof=$proof;safe_code=$code}|ConvertTo-Json -Depth 25 -Compress|Set-Content (Join-Path $Root 'wire.json')}
try{Complete-NativeJob $job 'never executed'}catch{if($Fault -cne 'hello_identity' -or $_.Exception.Message -cne 'setup_hello_device_differs'){throw};Send-Progress $job 'recovery_required' $null 'native_exit_requires_recovery'}
if($Fault -ceq 'none'){if($job.phase -cne 'failed' -or $script:Preflights -lt 2 -or $script:Refreshes -ne 1){throw 'verified source not settled'}}elseif($job.phase -cne 'recovery_required'){throw 'invalid source released hold'}
if($job.companions[0] -cne 'preserved source scope' -or $job.native_exit -ne 21){throw 'source history changed'}
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT), str(tmp_path), fault],
        capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    from endpoint_contracts.setup_updates import SetupProgressV1
    report = SetupProgressV1.model_validate(json.loads((tmp_path / 'wire.json').read_text(encoding='utf-8-sig')))
    assert report.phase == ('failed' if fault == 'none' else 'recovery_required')


@pytest.mark.skipif(os.name != 'nt', reason='Windows task COM boundary')
@pytest.mark.parametrize('fault', ['removed', 'denied', 'system_sid', 'system_name', 'wrong_action',
    'wrong_xml', 'wrong_sid', 'wrong_logon', 'wrong_runlevel', 'foreign_acl'])
def test_terminal_recovery_task_accepts_exact_cleanup_or_protected_matching_task(tmp_path, fault):
    harness = tmp_path / 'task.ps1'
    harness.write_text(r'''
param($Script,$Root,$Fault)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){Invoke-Expression $f.Extent.Text}
$script:Task=[pscustomobject]@{Xml='<protected task definition>';Definition=@{Actions=@{};Principal=@{UserId=$(if($Fault -ceq 'system_name'){'SYSTEM'}elseif($Fault -ceq 'wrong_sid'){'S-1-5-19'}else{'S-1-5-18'});LogonType=$(if($Fault -ceq 'wrong_logon'){3}else{5});RunLevel=$(if($Fault -ceq 'wrong_runlevel'){0}else{1})}}}
$actions=[pscustomobject]@{Count=1};$actions|Add-Member ScriptMethod Item {param($i);return @{Path=$(if($Fault -ceq 'wrong_action'){'other.exe'}else{Join-Path $Root 'EndpointAgentSetup.exe'});Arguments='--recover-staged-update 22222222-2222-4222-8222-222222222222'}}
$script:Task.Definition.Actions=$actions
$script:Task|Add-Member ScriptMethod GetSecurityDescriptor {param($flags);if($Fault -ceq 'foreign_acl'){return 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)'};return 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'}
$folder=[pscustomobject]@{};$folder|Add-Member ScriptMethod GetTask {param($name);if($Fault -ceq 'removed'){throw [Runtime.InteropServices.COMException]::new('missing',-2147024894)};if($Fault -ceq 'denied'){throw [Runtime.InteropServices.COMException]::new('denied',-2147024891)};return $script:Task}
$scheduler=[pscustomobject]@{Folder=$folder};$scheduler|Add-Member ScriptMethod Connect {}; $scheduler|Add-Member ScriptMethod GetFolder {param($name);return $this.Folder}
function New-Object {param($ComObject);if($ComObject -cne 'Schedule.Service'){throw 'unexpected COM object'};return $scheduler}
$inputsRecord=@{task_sha256=(Get-SetupTextHash '<protected task definition>')}
if($Fault -ceq 'wrong_xml'){$inputsRecord.task_sha256='0'*64}
$result=Test-RecoveryTask '22222222-2222-4222-8222-222222222222' $inputsRecord $Root
if($result -ne ($Fault -cin @('removed','system_sid','system_name'))){throw ('task evidence classified incorrectly: '+$Fault+','+$result)}
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT), str(tmp_path), fault],
        capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != 'nt', reason='actual protected Windows state ACL')
@pytest.mark.parametrize('fault', ['canonical', 'read_subset', 'writer', 'foreign_reader', 'hardlink'])
def test_public_stage_reader_allows_only_canonical_service_read_authority(native_protected_root, fault):
    import win32security
    from pc_agent.platform.windows import installer_fence
    root = native_protected_root
    record = root / 'staged-update.json'
    record.write_text('{"terminal":true}', encoding='utf-8')
    installer_fence.protect_state(record)
    if fault in {'read_subset', 'writer', 'foreign_reader'}:
        sid = 'S-1-5-32-545' if fault == 'foreign_reader' else 'S-1-5-80-327494974-20047353-929432329-1920152597-707704661'
        rights = 0x120089 if fault == 'read_subset' else 0x1200ab if fault == 'writer' else 0x120089
        acl = win32security.ACL()
        for identity, mask in [('S-1-5-18', 0x1f01ff), ('S-1-5-32-544', 0x1f01ff), (sid, rights)]:
            acl.AddAccessAllowedAceEx(win32security.ACL_REVISION, 0, mask, win32security.ConvertStringSidToSid(identity))
        win32security.SetNamedSecurityInfo(str(record), win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, acl, None)
    if fault == 'hardlink': os.link(record, root / 'other-link')
    harness = root / 'public.ps1'
    harness.write_text(r'''
param($Script,$Root,$Fault)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){Invoke-Expression $f.Extent.Text}
$accepted=$false
try{$value=Read-AdministrativeRecord (Join-Path $Root 'staged-update.json') -PublicState;$accepted=($value.terminal -ceq $true)}catch{if($Fault -cin @('canonical','read_subset')){throw}}
if($accepted -ne ($Fault -cin @('canonical','read_subset'))){throw ('state ACL admitted incorrectly: '+$Fault+','+$accepted)}
''', encoding='utf-8')
    environment = {key: value for key, value in os.environ.items() if key.lower() != 'psmodulepath'}
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT), str(root), fault],
        capture_output=True, text=True, timeout=15, env=environment)
    assert result.returncode == 0, result.stdout + result.stderr
