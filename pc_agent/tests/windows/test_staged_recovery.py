"""Recovery keeps original capture authority and rejects guessed settlement."""
import json
import os
from pathlib import Path
import subprocess
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pc_agent.platform.windows import durable_state, staged_update_state as state
from pc_agent.tests.windows.test_staged_update_state import staged, begin, move, native_protected_root


@pytest.fixture
def boot_markers(monkeypatch):
    from pc_agent.platform.windows import staged_boot_marker as marker
    tokens = {}
    def capture(_):
        token = 'registry-boot-v1:'+str(uuid4()); tokens[token] = True; return token
    monkeypatch.setattr(marker,'capture',capture)
    monkeypatch.setattr(marker,'present',lambda _,token:tokens[token])
    return tokens,capture


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


@pytest.mark.parametrize('case', [
    'cleaned', 'bad-acl', 'foreign-receipt', 'different-sequence',
    'foreign-stage', 'different-owner', 'pending-native', 'installer-busy',
    'accepted-without-cleanup', 'switching',
])
def test_watchdog_cleanup_proves_only_the_exact_accepted_operation(tmp_path, monkeypatch, case):
    from contextlib import contextmanager
    from pc_agent.platform.windows import native_setup_continuation, staged_recovery, update_transaction

    operation = str(uuid4())
    package = 'a' * 64
    paths = SimpleNamespace(install_root=tmp_path / 'Agent')
    before = SimpleNamespace(
        binding=SimpleNamespace(operation_id=operation, new_release={'package_sha256': package}),
        owner={'pid': 42, 'created': 1100},
    )
    current = SimpleNamespace(binding=before.binding, owner=before.owner, phase='accepted', sequence=7)
    if case == 'foreign-stage':
        current.binding = SimpleNamespace(operation_id=str(uuid4()))
    if case == 'different-owner':
        current.owner = {'pid': 42, 'created': 1101}
    if case == 'switching':
        current.phase = 'switching'

    receipt = staged_recovery._root(paths, operation) / 'watchdog-cleanup.json'
    receipt.parent.mkdir(parents=True)
    if case != 'accepted-without-cleanup':
        receipt.write_text('fixture', encoding='utf-8')
    locked = False

    @contextmanager
    def transaction(actual_paths, *, timeout_ms):
        assert actual_paths is paths and timeout_ms == 5000
        nonlocal locked
        if case == 'installer-busy':
            raise update_transaction.UpdateInProgress('INSTALLER_RECOVERY_REQUIRED')
        locked = True
        try:
            yield
        finally:
            locked = False

    def read_stage(actual_paths):
        assert actual_paths is paths and locked
        return current

    def read_receipt(actual_path):
        assert actual_path == receipt and locked
        if case == 'bad-acl':
            raise ValueError('UPDATE_STATE_INVALID')
        return {
            'schema_version': 'endpoint_windows_staged_watchdog_cleanup_v1',
            'operation_id': str(uuid4()) if case == 'foreign-receipt' else operation,
            'package_sha256': package,
            'sequence': 8 if case == 'different-sequence' else 7,
        }

    def pending_continuation(actual_paths):
        assert actual_paths is paths and locked
        return {'transaction_id': operation} if case == 'pending-native' else None

    monkeypatch.setattr(update_transaction, 'update_transaction', transaction)
    monkeypatch.setattr(native_setup_continuation, 'pending_continuation', pending_continuation)
    monkeypatch.setattr(staged_recovery.state, 'read_staged_update', read_stage)
    monkeypatch.setattr(staged_recovery, '_read', read_receipt)
    assert staged_recovery.watchdog_cleanup_complete(paths, before) is (case == 'cleaned')


@pytest.mark.skipif(os.name != 'nt', reason='real Windows mutex and PowerShell receipt ACL')
def test_powershell_watchdog_receipt_round_trips_under_the_windows_update_gate(staged, tmp_path, monkeypatch):
    from pc_agent.platform.windows import staged_recovery, update_transaction

    _, paths, binding, _ = staged
    begin(staged)
    admitted = state.read_staged_update(paths)
    move(staged, 'preparing', 'prepared')
    move(staged, 'prepared', 'switching')
    move(staged, 'switching', 'native-settled')
    move(staged, 'native-settled', 'trial', attempt_id=str(uuid4()))
    current = move(staged, 'trial', 'accepted')
    staged_recovery._root(paths, binding.operation_id, create=True)
    monkeypatch.setattr(update_transaction, '_MUTEX_NAME', 'Local\\EndpointWatchdogTest-' + uuid4().hex)
    assert not staged_recovery.watchdog_cleanup_complete(paths, admitted)

    source = Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'watchdog-receipt.ps1'
    script.write_text(r'''param($Source,$StateRoot,$OperationId,$PackageHash,[int]$Sequence)
$ErrorActionPreference='Stop'
$env:PSModulePath=Join-Path $PSHOME 'Modules'
Import-Module Microsoft.PowerShell.Security
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'wrapper parse failure'}
$CacheSids=@('S-1-5-18','S-1-5-32-544')
foreach($name in @('Initialize-InstallerBridgeTypes','Assert-InstallerPublicStateAcl','Get-InstallerReaderSids',
 'Assert-ExistingPathChain','Assert-ProtectedAcl','Assert-TrustedOwner','Get-SidValue','Write-StagedWatchdogCleanup')){
 $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true)
 Invoke-Expression $function.Extent.Text
}
Write-StagedWatchdogCleanup $StateRoot $OperationId $PackageHash $Sequence
''', encoding='utf-8')
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source),
         str(staged_recovery.fence.state_root(paths)), binding.operation_id,
         binding.new_release['package_sha256'], str(current.sequence)],
        capture_output=True, text=True, timeout=25,
    )
    assert result.returncode == 0, result.stderr
    assert staged_recovery.watchdog_cleanup_complete(paths, admitted)


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
def test_3010_or_1641_does_not_accept_before_reboot(recovery, staged, boot_markers, native_exit):
    module, paths, binding, cap = recovery
    move(staged, 'preparing', 'prepared');move(staged, 'prepared', 'switching')
    with durable_state.installer_mutation_checkpoints(lambda: None):
        module._root(paths,binding.operation_id,create=True)
        module.begin_native_attempt(paths,binding.operation_id,cap['owner'])
        module.record_reboot_required(paths, binding.operation_id, native_exit, cap['owner'])
        assert module.recover_staged_update(paths, binding.operation_id, capability=cap) == 'reboot-required'
    assert state.read_staged_update(paths).phase != 'accepted'


def test_companion_session_changes_during_update():
    from pc_agent.platform.windows.staged_recovery import companion_restore_decisions
    before = [{'role':'sensor','session_id':2,'sid':'S-1-5-21-100'}, {'role':'tray','session_id':2,'sid':'S-1-5-21-100'}]
    assert companion_restore_decisions(before, [{'session_id':0,'sid':'S-1-5-18'}, {'session_id':2,'sid':'S-1-5-21-200'}]) == []
    assert companion_restore_decisions(before, [{'session_id':2,'sid':'S-1-5-21-100'}]) == before


@pytest.mark.parametrize(('schema', 'user_id', 'resolved_sid', 'rights', 'accepted'), [
    ('1.2', r'HOST\User', 'S-1-5-21-10-20-30-1001', 'GRGX', True),
    ('1.2', r'HOST\User', 'S-1-5-21-10-20-30-1002', 'GRGX', False),
    ('1.2', r'HOST\User', None, 'GRGX', False),
    ('1.2', 'User', 'S-1-5-21-10-20-30-1001', 'GRGX', False),
    ('1.3', r'HOST\User', 'S-1-5-21-10-20-30-1001', 'GRGX', False),
    ('1.4', 'S-1-5-21-10-20-30-1001', None, 'GRGX', True),
    ('1.4', 'S-1-5-21-10-20-30-1001', None, 'GRGWGX', False),
])
def test_companion_launcher_legacy_principal_matches_original_sid(
    tmp_path, monkeypatch, schema, user_id, resolved_sid, rights, accepted,
):
    win32security = pytest.importorskip('win32security')
    from xml.sax.saxutils import escape
    from pc_agent.platform.windows.staged_recovery import _validate_companion_launcher

    expected_sid = 'S-1-5-21-10-20-30-1001'
    executable = escape(str(tmp_path / 'EndpointUserSensor.exe'))
    xml = f'''<Task version="{schema}" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Principals><Principal><UserId>{user_id}</UserId></Principal></Principals>
      <Actions><Exec><Command>{executable}</Command></Exec></Actions>
    </Task>'''
    task = SimpleNamespace(
        Xml=xml,
        Definition=SimpleNamespace(Principal=SimpleNamespace(LogonType=3, RunLevel=0),
                                   Settings=SimpleNamespace(MultipleInstances=2)),
        GetSecurityDescriptor=lambda _: f'O:BAG:BAD:P(A;;FA;;;SY)(A;;{rights};;;{expected_sid})',
    )

    def lookup(system, account):
        assert system is None and account == r'HOST\User'
        if resolved_sid is None:
            raise win32security.error(1332, 'LookupAccountName', 'No account mapping')
        return win32security.ConvertStringSidToSid(resolved_sid), 'HOST', win32security.SidTypeUser

    monkeypatch.setattr(win32security, 'LookupAccountName', lookup)
    paths = SimpleNamespace(install_root=tmp_path)
    item = {'role': 'sensor', 'session_id': 1, 'sid': expected_sid}
    if accepted:
        _validate_companion_launcher(task, paths, item)
    else:
        with pytest.raises(ValueError, match='RECOVERY_REQUIRED'):
            _validate_companion_launcher(task, paths, item)


def test_setup_recovery_dispatch_does_not_enter_enrollment(monkeypatch):
    from pc_agent.platform.windows import setup_entry
    operation = str(uuid4()); calls = []
    monkeypatch.setattr(setup_entry, '_run_staged_recovery', lambda value: calls.append(value) or 67, raising=False)
    monkeypatch.setattr(setup_entry, '_record_in_progress', lambda: pytest.fail('ordinary Setup flow'))
    assert setup_entry.main(['--recover-staged-update', operation]) == 67
    assert calls == [operation]


def test_recovered_trial_discards_prior_attempt(recovery, staged, monkeypatch, boot_markers):
    module, paths, binding, cap = recovery
    move(staged, 'preparing','prepared'); move(staged,'prepared','switching'); move(staged,'switching','native-settled')
    move(staged,'native-settled','trial',attempt_id=str(uuid4()))
    tokens,capture=boot_markers;original=capture(None);tokens[original]=False
    monkeypatch.setattr(module,'_validate_recovery_inputs',lambda *_: {'boot':original})
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


from pc_agent.tests.windows.test_staged_trial_proof import trial, fake_gates


def test_reboot_marker_blocks_trial_until_actual_boot_changes(trial, monkeypatch, boot_markers):
    from pc_agent.platform.windows import staged_recovery as recovery
    proof, paths, binding, *_ = trial
    tokens,_=boot_markers
    monkeypatch.setattr(recovery,'_validate_recovery_inputs',lambda *_:{})
    with durable_state.installer_mutation_checkpoints(lambda:None):
        recovery._root(paths,binding.operation_id,create=True)
        recovery.begin_native_attempt(paths,binding.operation_id,state.read_staged_update(paths).owner)
        recovery.record_reboot_required(paths,binding.operation_id,3010)
        record = state.read_staged_update(paths)
        state._write(paths,replace(record,phase='native-settled',attempt_id=None,sequence=record.sequence+1))
        with pytest.raises(ValueError): proof.begin_staged_trial(paths,binding.operation_id)
        assert state.read_staged_update(paths).phase == 'native-settled'
        tokens[recovery._native_attempt(paths,record)['boot']]=False
        assert proof.begin_staged_trial(paths,binding.operation_id)


def test_owner_loss_during_trial_requests_compensation(recovery, staged):
    module, paths, binding, cap = recovery
    move(staged,'preparing','prepared');move(staged,'prepared','switching');move(staged,'switching','native-settled')
    attempt = str(uuid4());move(staged,'native-settled','trial',attempt_id=attempt)
    with durable_state.installer_mutation_checkpoints(lambda:None):
        assert module.recover_staged_update(paths,binding.operation_id,capability=cap) == 'rollback-required'
    assert state.read_staged_update(paths).attempt_id == attempt
    assert state.read_staged_update(paths).phase == 'trial'


def test_legacy_task_xml_spelling_needs_real_system_service_account(tmp_path):
    from pc_agent.platform.windows.staged_recovery import _validate_task_definition
    operation = 'cf85346d-b6af-47f4-bcc3-a815e6aca448'
    executable = tmp_path / 'EndpointAgentSetup.exe'
    xml = f'''<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Principals><Principal><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel><LogonType>InteractiveToken</LogonType></Principal></Principals><Triggers><BootTrigger/></Triggers><Actions><Exec><Command>{executable}</Command><Arguments>--recover-staged-update {operation}</Arguments></Exec></Actions></Task>'''
    _validate_task_definition(xml, operation, executable, 5)
    for altered, logon_type in ((xml, 3), (xml.replace('S-1-5-18', 'S-1-5-19'), 5),
                                 (xml.replace('1.3', '1.4'), 5)):
        with pytest.raises(ValueError):
            _validate_task_definition(altered, operation, executable, logon_type)
