"""Recovery keeps original capture authority and rejects guessed settlement."""
import json
from pathlib import Path
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pc_agent.platform.windows import durable_state, staged_update_state as state
from pc_agent.tests.windows.test_staged_update_state import staged, begin, move, native_protected_root


@pytest.fixture
def recovery(staged, monkeypatch):
    from pc_agent.platform.windows import staged_recovery as recovery
    _, paths, binding, owner = staged
    begin(staged)
    new_owner = {**owner, 'pid': owner['pid'] + 100, 'created': owner['created'] + 100}
    cap = {'owner': new_owner, 'package': binding.new_release, 'transaction_id': binding.operation_id,
           'session_id': str(uuid4()), 'operation': 'install', 'recovery': False, 'uninstall_finalization': False}
    monkeypatch.setattr(recovery, '_validate_recovery_inputs', lambda *_: {})
    monkeypatch.setattr(recovery, '_assert_owner_dead', lambda *_: None)
    monkeypatch.setattr(recovery, '_verify_original_state', lambda *_: None)
    monkeypatch.setattr(recovery, '_native_settled', lambda *_: True)
    return recovery, paths, binding, cap


def test_owner_loss_before_switch_keeps_old_agent_running(recovery):
    module, paths, binding, cap = recovery
    selected = paths.current_path.read_bytes()
    with durable_state.installer_mutation_checkpoints(lambda: None):
        assert module.recover_staged_update(paths, binding.operation_id, capability=cap) == 'preparation-cancelled'
    assert paths.current_path.read_bytes() == selected
    assert state.read_staged_update(paths).phase == 'rolled-back'
    assert not (paths.install_root / 'installer-state/native-fence.json').exists()


@pytest.mark.parametrize('defect', ['live-owner', 'forged-task', 'replaced-cache', 'native-unsettled'])
def test_recovery_rejects_live_owner_forged_task_and_replaced_cache(recovery, monkeypatch, defect):
    module, paths, binding, cap = recovery
    def reject(*_): raise ValueError('RECOVERY_REQUIRED')
    if defect == 'live-owner': monkeypatch.setattr(module, '_assert_owner_dead', reject)
    elif defect == 'native-unsettled': monkeypatch.setattr(module, '_native_settled', lambda *_: False)
    else: monkeypatch.setattr(module, '_validate_recovery_inputs', reject)
    before = state._path(paths).read_bytes()
    with durable_state.installer_mutation_checkpoints(lambda: None):
        with pytest.raises(ValueError): module.recover_staged_update(paths, binding.operation_id, capability=cap)
    assert state._path(paths).read_bytes() == before


def test_original_capture_owner_survives_fresh_recovery_handoff(recovery, staged):
    module, paths, binding, cap = recovery
    move(staged, 'preparing', 'prepared');move(staged, 'prepared', 'switching');move(staged, 'switching', 'native-settled')
    original = state.read_staged_update(paths).owner
    with durable_state.installer_mutation_checkpoints(lambda: None):
        assert module.recover_staged_update(paths, binding.operation_id, capability=cap) == 'rollback-required'
    assert state.read_staged_update(paths).owner == original
    assert module.owner_authorized(paths, state.read_staged_update(paths), cap['owner'])
    assert not module.owner_authorized(paths, state.read_staged_update(paths), {**cap['owner'], 'created': 999})


@pytest.mark.parametrize('native_exit', [3010, 1641])
def test_3010_or_1641_does_not_accept_before_reboot(recovery, staged, monkeypatch, native_exit):
    module, paths, binding, cap = recovery
    move(staged, 'preparing', 'prepared');move(staged, 'prepared', 'switching')
    monkeypatch.setattr(module, '_boot_identity', lambda: 'boot-one')
    with durable_state.installer_mutation_checkpoints(lambda: None):
        module.record_reboot_required(paths, binding.operation_id, native_exit)
        assert module.recover_staged_update(paths, binding.operation_id, capability=cap) == 'reboot-required'
    assert state.read_staged_update(paths).phase != 'accepted'


def test_companion_session_changes_during_update():
    from pc_agent.platform.windows.staged_recovery import companion_restore_decisions
    before = [{'role':'sensor','session_id':2,'sid':'S-1-5-21-100'}, {'role':'tray','session_id':2,'sid':'S-1-5-21-100'}]
    assert companion_restore_decisions(before, [{'session_id':0,'sid':'S-1-5-18'}, {'session_id':2,'sid':'S-1-5-21-200'}]) == []
    assert companion_restore_decisions(before, [{'session_id':2,'sid':'S-1-5-21-100'}]) == before


def test_setup_recovery_dispatch_does_not_enter_enrollment(monkeypatch):
    from pc_agent.platform.windows import setup_entry
    operation = str(uuid4()); calls = []
    monkeypatch.setattr(setup_entry, '_run_staged_recovery', lambda value: calls.append(value) or 67, raising=False)
    monkeypatch.setattr(setup_entry, '_record_in_progress', lambda: pytest.fail('ordinary Setup flow'))
    assert setup_entry.main(['--recover-staged-update', operation]) == 67
    assert calls == [operation]


def test_recovered_trial_discards_prior_attempt(recovery, staged, monkeypatch):
    module, paths, binding, cap = recovery
    move(staged, 'preparing','prepared'); move(staged,'prepared','switching'); move(staged,'switching','native-settled')
    move(staged,'native-settled','trial',attempt_id=str(uuid4()))
    monkeypatch.setattr(module,'_validate_recovery_inputs',lambda *_: {'boot':'previous'})
    monkeypatch.setattr(module,'_boot_identity',lambda:'current')
    with durable_state.installer_mutation_checkpoints(lambda: None):
        assert module.recover_staged_update(paths,binding.operation_id,capability=cap) == 'trial-required'
    assert state.read_staged_update(paths).phase == 'native-settled'
    assert state.read_staged_update(paths).attempt_id is None


@pytest.mark.skipif(__import__('os').name != 'nt', reason='actual PowerShell owner policy')
def test_recovery_owner_functions_and_native_probe_admission(tmp_path):
    import subprocess
    source = Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'recovery.ps1'
    script.write_text(r'''param($Source)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse failure'}
foreach($name in @('Initialize-InstallerBridgeTypes','Register-StagedRecoveryTask','Remove-StagedRecoveryTask','Invoke-StagedRecovery')){
 $node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 if(!$node){throw ('missing '+$name)}
 if($name -eq 'Initialize-InstallerBridgeTypes'){Invoke-Expression $node.Extent.Text}
}
Initialize-InstallerBridgeTypes
$owner=[EndpointInstallerBridge.Identity]::new(100,1000,('a'*64),'S-1-5-18',$true)
$p=[EndpointInstallerBridge.Policy]::new('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222',('c'*64),'install',$owner,('b'*64),[byte[]](1..32))
$peer=[EndpointInstallerBridge.Identity]::new(200,2000,('b'*64),'S-1-5-18',$true)
$denied=$false;try{$p.RegisterHelper($peer,'recover-staged-owner')}catch{$denied=$true}
if(!$denied){throw 'recovery admitted without actual native settlement'}
$p.RegisterHelper($peer,'inspect-staged-recovery')
$denied=$false;try{$p.Issue($peer,'inspect-staged-recovery','mutation',('f'*64),$p.SessionId)|Out-Null}catch{$denied=$true}
if(!$denied){throw 'read-only recovery granted mutation'}
$recovery=[EndpointInstallerBridge.Policy]::new('33333333-3333-4333-8333-333333333333','44444444-4444-4444-8444-444444444444',('c'*64),'install',$owner,('b'*64),[byte[]](1..32))
$recovery.Recovery=$true;$recovery.MarkQuiescent();$recovery.RequireNativeRecoverySettlement()
$denied=$false;try{$recovery.RegisterHelper($peer,'prepare')}catch{$denied=$true}
if(!$denied){throw 'native recovery preparation admitted before settlement'}
$denied=$false;try{$recovery.AuthorizeNativeRecoveryPreparation($null)}catch{$denied=$true}
if(!$denied){throw 'missing native settlement proof admitted'}
$denied=$false;try{$recovery.RegisterHelper($peer,'prepare')}catch{$denied=$true}
if(!$denied){throw 'failed settlement allowed ACL restoration'}
'passed'
''',encoding='utf-8')
    result = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source)],
                            capture_output=True,text=True,timeout=35)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'


def test_terminal_cleanup_failure_does_not_undo_acceptance(recovery, staged, monkeypatch):
    module, paths, binding, cap = recovery
    move(staged,'preparing','prepared');move(staged,'prepared','switching');move(staged,'switching','native-settled')
    move(staged,'native-settled','trial',attempt_id=str(uuid4()));move(staged,'trial','accepted')
    before = state._path(paths).read_bytes()
    monkeypatch.setattr(module,'_restore_companion_task',lambda *_: pytest.fail('wrong-session launch'),raising=False)
    root = module._root(paths,binding.operation_id,create=True)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        module._write(root,'companions.json',{'schema_version':1,'binding_sha256':module._binding_hash(state.read_staged_update(paths)),
                      'before':[{'role':'sensor','session_id':2,'sid':'S-1-5-21-100'}]})
    monkeypatch.setattr(module,'_active_sessions',lambda: [{'session_id':0,'sid':'S-1-5-18'}],raising=False)
    monkeypatch.setattr(module,'_service_outcomes',lambda *_: {'agent':'running'},raising=False)
    result = module.restore_staged_companions(paths,binding.operation_id)
    assert result['users'] == 'session-unavailable'
    assert state._path(paths).read_bytes() == before


@pytest.mark.parametrize('defect', ['post-use-once', 'post-use-always', 'entry', 'launch'])
def test_companion_post_use_recheck_repeats_every_guard_without_relaunch(
    recovery, staged, monkeypatch, defect,
):
    from contextlib import contextmanager
    from pc_agent.platform.windows.msi_inventory import ProvenanceConflict
    module, paths, binding, cap = recovery
    move(staged, 'preparing', 'rolled-back')
    before = state._path(paths).read_bytes()
    roles = [{'role':'sensor','session_id':2,'sid':'S-1-5-21-100'},
             {'role':'tray','session_id':2,'sid':'S-1-5-21-100'}]
    root = module._root(paths, binding.operation_id, create=True)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        module._write(root, 'companions.json', {'schema_version':1,
            'binding_sha256':module._binding_hash(state.read_staged_update(paths)), 'before':roles})
    monkeypatch.setattr(module, '_active_sessions', lambda: [{'session_id':2,'sid':'S-1-5-21-100'}])
    monkeypatch.setattr(module, '_service_outcomes', lambda *_: {'agent':'running'})
    monkeypatch.setattr(module, '_probe_companions', lambda *_: [])
    guards = []; launches = []
    @contextmanager
    def verified(*_):
        guards.append('entry')
        if defect == 'entry':
            raise ProvenanceConflict()
        yield
        guards.append('exit')
        if defect == 'post-use-always' or len(guards) == 2:
            raise ProvenanceConflict()
    def launch(_paths, _operation, role):
        launches.append(role)
        if defect == 'launch':
            raise ProvenanceConflict()
        return True
    monkeypatch.setattr(module, '_verified_companion_files', verified)
    monkeypatch.setattr(module, '_restore_companion_task', launch)
    if defect == 'post-use-once':
        assert module.restore_staged_companions(paths, binding.operation_id)['users'] == 'launch-requested'
        assert guards == ['entry','exit','entry','exit']
        assert launches == roles
    else:
        with pytest.raises(ProvenanceConflict):
            module.restore_staged_companions(paths, binding.operation_id)
        assert len(launches) <= len(roles)
        assert guards.count('entry') == (2 if defect == 'post-use-always' else 1)
    assert state._path(paths).read_bytes() == before


def test_system_task_canonical_xml_omits_logon_type():
    from pc_agent.platform.windows.staged_recovery import _validate_task_definition
    operation = str(uuid4()); executable = Path('C:/Program Files/Endpoint Platform/installer-cache/msi-'+'a'*64+'/EndpointAgentSetup.exe')
    xml = f'''<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Triggers><BootTrigger/></Triggers><Actions Context="Author"><Exec><Command>{executable}</Command><Arguments>--recover-staged-update {operation}</Arguments></Exec></Actions></Task>'''
    _validate_task_definition(xml, operation, executable, 5)
    for forged, logon in ((xml.replace('S-1-5-18','S-1-5-19'),5),(xml,3),(xml.replace('HighestAvailable','LeastPrivilege'),5),(xml.replace('BootTrigger','LogonTrigger'),5),(xml.replace('--recover-staged-update','--quiet'),5),(xml.replace('</Actions>','<ComHandler/></Actions>'),5),(xml.replace('</Triggers>','<TimeTrigger/></Triggers>'),5)):
        with pytest.raises(ValueError): _validate_task_definition(forged, operation, executable, logon)


@pytest.mark.parametrize('defect', [None, 'count', 'interval', 'duplicate'])
def test_task_restart_settings_are_bounded_and_historical_tasks_remain_valid(defect):
    from pc_agent.platform.windows.staged_recovery import _validate_task_definition
    operation = str(uuid4());executable = Path('C:/Program Files/Endpoint Platform/installer-cache/recovery/EndpointAgentSetup.exe')
    restart = '<RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>'
    if defect == 'count': restart = restart.replace('<Count>3', '<Count>4')
    if defect == 'interval': restart = restart.replace('PT1M', 'PT1S')
    if defect == 'duplicate': restart += restart
    xml = f'''<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Principals><Principal><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Triggers><BootTrigger/></Triggers><Actions><Exec><Command>{executable}</Command><Arguments>--recover-staged-update {operation}</Arguments></Exec></Actions><Settings>{restart}</Settings></Task>'''
    if defect:
        with pytest.raises(ValueError): _validate_task_definition(xml, operation, executable, 5)
    else:
        _validate_task_definition(xml, operation, executable, 5)


from pc_agent.tests.windows.test_retained_storage import retained, promote


def test_reset_between_promotion_and_receipt(retained, monkeypatch):
    storage, paths, archive, identity, binding = retained
    original = storage._write
    def reset(root, value):
        if value['phase'] == 'published': raise OSError('reset after rename')
        return original(root, value)
    monkeypatch.setattr(storage, '_write', reset)
    with pytest.raises(OSError): promote(retained)
    assert sum(path.exists() for path in (archive / 'payload', paths.versions_root / identity.version)) == 1
    monkeypatch.setattr(storage, '_write', original)
    target = promote(retained)
    assert target.is_dir() and not (archive / 'payload').exists()
    assert json.loads((archive / 'storage.json').read_bytes())['phase'] == 'published'


def test_terminal_journal_is_archived_before_next_preparation(staged):
    _, paths, binding, owner = staged
    begin(staged); move(staged,'preparing','rolled-back')
    original = state._path(paths).read_bytes()
    successor = replace(binding, operation_id=str(uuid4()))
    with durable_state.installer_mutation_checkpoints(lambda: None):
        state.begin_staged_update(paths, successor, owner)
    assert state.read_staged_update(paths).binding == successor
    archived = state.read_archived_staged_update(paths, binding.operation_id)
    assert archived.phase == 'rolled-back' and archived.binding == binding
    assert (state._path(paths).parent / 'staged-history' / (binding.operation_id + '.json')).read_bytes() == original


def test_next_operation_reuses_archive_without_rewriting_capture(retained):
    storage, paths, archive, identity, binding = retained
    promote(retained)
    capture = (archive / 'receipt.json').read_bytes()
    before = (archive / 'storage.json').read_bytes()
    old = state.read_staged_update(paths)
    successor = replace(binding, operation_id=str(uuid4()))
    with durable_state.installer_mutation_checkpoints(lambda: None):
        state.advance_staged_update(paths,binding.operation_id,'native-settled','rolling-back')
        state.advance_staged_update(paths,binding.operation_id,'rolling-back','rolled-back')
        state.begin_staged_update(paths,successor,old.owner)
        for a,b in (('preparing','prepared'),('prepared','switching')):
            state.advance_staged_update(paths,successor.operation_id,a,b)
        target = storage.promote_retained_payload(paths,archive.name,successor.operation_id)
    assert target == paths.versions_root / identity.version
    assert (archive / 'receipt.json').read_bytes() == capture
    assert (archive / 'storage-history' / (binding.operation_id + '.json')).read_bytes() == before


def test_actual_private_cache_acl_and_hash_are_verified(staged, monkeypatch):
    import hashlib
    from pc_agent.platform.windows import staged_recovery as module, installation_provenance as provenance, installer_fence
    _, paths, binding, owner = staged
    package = b'fixture MSI'; package_hash = hashlib.sha256(package).hexdigest()
    binding = replace(binding, new_release={**binding.new_release,'package_sha256':package_hash})
    with durable_state.installer_mutation_checkpoints(lambda: None):
        record = state.begin_staged_update(paths,binding,owner)
        cache = paths.install_root.parent / 'installer-cache' / ('msi-'+package_hash)
        cache.mkdir(parents=True)
        installer_fence.protect_state(cache.parent,secret=True)
        installer_fence.protect_state(cache,secret=True)
        files = {}
        for name in ('EndpointAgentSetup.exe','EndpointAgent.msi','EndpointAgent.release.json','Install-EndpointAgentCanary.ps1'):
            leaf = cache / name; leaf.write_bytes(package if name == 'EndpointAgent.msi' else name.encode())
            installer_fence.protect_state(leaf,secret=True)
            files[name] = hashlib.sha256(leaf.read_bytes()).hexdigest()
        inputs = {'schema_version':1,'operation_id':binding.operation_id,'owner':owner,
                  'package_sha256':package_hash,'files':files,'service_states':dict.fromkeys(
                  ('EndpointAgent','EndpointAgentUpdater','EndpointBrowserPolicy'),'Running'),'task_sha256':'f'*64,'boot':'fixture-boot'}
        module._write(module._root(paths,binding.operation_id,create=True),'inputs.json',inputs)
    seen = []; monkeypatch.setattr(module,'_validate_task',lambda *_:seen.append('task'))
    assert module._validate_recovery_inputs(paths,record) == inputs
    assert seen == ['task']; seen.clear()
    (cache / 'EndpointAgentSetup.exe').write_bytes(b'substituted')
    with pytest.raises(ValueError): module._validate_recovery_inputs(paths,record)
    assert seen == []


@pytest.mark.skipif(__import__('os').name != 'nt', reason='actual Windows owner cache publication')
def test_recovery_cache_copy_is_durable_and_never_overwrites(native_protected_root, tmp_path):
    import subprocess
    source = Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'copy.ps1'
    script.write_text(r'''param($Source,$Root)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $node.Extent.Text;Initialize-InstallerBridgeTypes
$from=Join-Path $Root 'source';$to=Join-Path $Root 'destination'
[IO.File]::WriteAllBytes($from,[byte[]](1,2,3,4))
[EndpointInstallerBridge.PackageHelper]::CopyCacheArtifact($from,$to)
if([Convert]::ToBase64String([IO.File]::ReadAllBytes($to)) -cne 'AQIDBA=='){throw 'copy corrupted'}
$denied=$false;try{[EndpointInstallerBridge.PackageHelper]::CopyCacheArtifact($from,$to)}catch{$denied=$true}
if(!$denied -or [Convert]::ToBase64String([IO.File]::ReadAllBytes($to)) -cne 'AQIDBA=='){throw 'existing cache replaced'}
'passed'
''',encoding='utf-8')
    result = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source),str(native_protected_root)],
                            capture_output=True,text=True,timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'


from pc_agent.tests.windows.test_staged_trial_proof import trial


def test_reboot_marker_blocks_trial_until_actual_boot_changes(trial, monkeypatch):
    from pc_agent.platform.windows import staged_recovery as recovery
    proof, paths, binding, *_ = trial
    boot = ['before']; monkeypatch.setattr(recovery,'_boot_identity',lambda:boot[0])
    with durable_state.installer_mutation_checkpoints(lambda:None):
        recovery.record_reboot_required(paths,binding.operation_id,3010)
        record = state.read_staged_update(paths)
        state._write(paths,replace(record,phase='native-settled',attempt_id=None,sequence=record.sequence+1))
        with pytest.raises(ValueError): proof.begin_staged_trial(paths,binding.operation_id)
        assert state.read_staged_update(paths).phase == 'native-settled'
        boot[0] = 'after'
        assert proof.begin_staged_trial(paths,binding.operation_id)


def test_owner_loss_during_trial_requests_compensation(recovery, staged):
    module, paths, binding, cap = recovery
    move(staged,'preparing','prepared');move(staged,'prepared','switching');move(staged,'switching','native-settled')
    attempt = str(uuid4());move(staged,'native-settled','trial',attempt_id=attempt)
    with durable_state.installer_mutation_checkpoints(lambda:None):
        assert module.recover_staged_update(paths,binding.operation_id,capability=cap) == 'rollback-required'
    assert state.read_staged_update(paths).attempt_id == attempt
    assert state.read_staged_update(paths).phase == 'trial'
