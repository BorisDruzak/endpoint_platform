"""FoD preparation is separate from active Support and native MSI ownership."""
import importlib
import json
from pathlib import Path

import pytest


CLIENT = 'OpenSSH.Client~~~~0.0.1.0'
SERVER = 'OpenSSH.Server~~~~0.0.1.0'


def module():
    try:
        return importlib.import_module('pc_agent.platform.windows.support_access_os')
    except ModuleNotFoundError:
        pytest.fail('in-box OpenSSH provisioning is not implemented')


def test_serviced_os_files_accept_protected_hardlinks_but_reject_reparse(tmp_path, monkeypatch):
    """Windows servicing shares a protected inode with WinSxS by design."""
    import os
    import win32security as security
    from pc_agent.platform.windows import support_access_native as native
    root=tmp_path/'System32/OpenSSH';root.mkdir(parents=True)
    payload=root/'ssh.exe';payload.write_bytes(b'Windows servicing fixture')
    os.link(payload,tmp_path/'winsxs-copy.exe')
    assert payload.stat().st_nlink==2
    monkeypatch.setattr(native,'windows_root',lambda:tmp_path)
    descriptor=security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorOwner(security.ConvertStringSidToSid('S-1-5-18'),False)
    acl=security.ACL();acl.AddAccessAllowedAce(2,0x1f01ff,security.ConvertStringSidToSid('S-1-5-18'))
    descriptor.SetSecurityDescriptorDacl(True,acl,False)
    monkeypatch.setattr(security,'GetNamedSecurityInfo',lambda *args:descriptor)
    module().assert_os_path(payload)
    # An ordinary user write ACE remains forbidden even for a serviced inode.
    acl.AddAccessAllowedAce(2,2,security.ConvertStringSidToSid('S-1-5-32-545'))
    descriptor.SetSecurityDescriptorDacl(True,acl,False)
    with pytest.raises(ValueError):module().assert_os_path(payload)
    acl.DeleteAce(1);descriptor.SetSecurityDescriptorDacl(True,acl,False)
    from types import SimpleNamespace
    original=Path.lstat
    monkeypatch.setattr(Path,'lstat',lambda p:SimpleNamespace(st_mode=0,st_file_attributes=0x400)
                        if p==payload else original(p))
    with pytest.raises(ValueError):module().assert_os_path(payload)


class Servicing:
    def __init__(self, states, *, outcome='complete', previous=None):
        self.states = dict(states)
        self.outcome = outcome
        self.receipt = previous
        self.events = []

    def capabilities(self):
        self.events.append('query')
        return dict(self.states)

    def read_receipt(self):
        return self.receipt

    def write_receipt(self, value):
        self.receipt = value
        self.events.append(('receipt', value['state']))

    def install(self, names):
        assert self.receipt['state'] == 'servicing'
        self.events.append(('install', tuple(names)))
        if self.outcome == 'timeout':
            raise TimeoutError()
        if self.outcome != 'failure':
            self.states.update({name: 'Installed' for name in names})
        return {'completed': self.outcome != 'failure',
                'restart_needed': self.outcome == 'reboot',
                'boundary_preserved': self.outcome != 'foreign-change'}

    def verify(self):
        self.events.append('verify')
        return {'profile': 'windows-openssh-fod-v1', 'hashes': {'sshd': 'a' * 64}}


def test_installed_fod_is_read_only_before_signature_selection():
    ops = Servicing({CLIENT: 'Installed', SERVER: 'Installed'})
    result = module().ensure_inbox_openssh(ops)
    assert result['profile'] == 'windows-openssh-fod-v1'
    assert ops.events == ['query', 'verify']
    assert ops.receipt is None


def test_missing_server_uses_only_exact_capability_after_durable_receipt():
    ops = Servicing({CLIENT: 'Installed', SERVER: 'NotPresent'})
    result = module().ensure_inbox_openssh(ops)
    assert ('install', (SERVER,)) in ops.events
    assert ops.events.index(('receipt', 'servicing')) < ops.events.index(('install', (SERVER,)))
    assert result['profile'] == 'windows-openssh-fod-v1'
    assert ops.receipt['state'] == 'complete'


@pytest.mark.parametrize('outcome,code,state', [
    ('failure', 'support_dependency_install_failed', 'failed'),
    ('reboot', 'support_dependency_reboot_required', 'reboot_required'),
    ('foreign-change', 'support_dependency_firewall_conflict', 'conflict'),
])
def test_unsuccessful_fod_never_reaches_new_support_or_verification(outcome, code, state):
    ops = Servicing({CLIENT: 'Installed', SERVER: 'NotPresent'}, outcome=outcome)
    with pytest.raises(ValueError, match=code):
        module().ensure_inbox_openssh(ops)
    assert 'verify' not in ops.events
    assert ops.receipt['state'] == state


def test_unknown_servicing_result_is_not_replayed():
    ops = Servicing({CLIENT: 'NotPresent', SERVER: 'NotPresent'}, outcome='timeout')
    with pytest.raises(ValueError, match='support_dependency_recovery_required'):
        module().ensure_inbox_openssh(ops)
    assert ops.receipt['state'] == 'servicing'
    ops.events.clear()
    with pytest.raises(ValueError, match='support_dependency_recovery_required'):
        module().ensure_inbox_openssh(ops)
    assert not any(isinstance(e, tuple) and e[0] == 'install' for e in ops.events)


@pytest.mark.parametrize('states', [
    {CLIENT: 'Installed'},
    {CLIENT: 'Installed', SERVER: 'InstallPending'},
    {CLIENT: 'Installed', SERVER: 'Installed', 'foreign': 'NotPresent'},
])
def test_ambiguous_capability_state_refuses_before_any_write(states):
    ops = Servicing(states)
    with pytest.raises(ValueError):
        module().ensure_inbox_openssh(ops)
    assert ops.events == ['query']


def test_pending_servicing_is_not_declared_recovered_from_file_presence():
    ops = Servicing({CLIENT: 'Installed', SERVER: 'Installed'}, previous={
        'state': 'servicing', 'capabilities': [SERVER]})
    with pytest.raises(ValueError, match='support_dependency_recovery_required'):
        module().ensure_inbox_openssh(ops)
    assert 'verify' not in ops.events


def test_os_dependency_refresh_reuses_verified_snapshot_without_signature_process():
    calls = []
    current = {'profile': 'windows-openssh-fod-v1', 'hashes': {'sshd': 'a' * 64}}
    monitor = module().OSDependencyMonitor(current, unchanged=lambda value: True,
        validate=lambda: calls.append('signature'))
    assert monitor.refresh() == current
    assert calls == []


def test_os_dependency_refresh_changes_only_after_full_validation():
    before = {'profile': 'windows-openssh-fod-v1', 'hashes': {'sshd': 'a' * 64}}
    after = {'profile': 'windows-openssh-fod-v1', 'hashes': {'sshd': 'b' * 64}}
    persisted = []
    monitor = module().OSDependencyMonitor(before, unchanged=lambda value: False,
        validate=lambda: after, persist=lambda old, new: persisted.append((old, new)))
    assert monitor.refresh() == after
    assert before['hashes']['sshd'] == 'a' * 64
    assert persisted == [(before, after)]


def test_invalid_os_replacement_never_overwrites_last_verified_snapshot():
    before = {'profile': 'windows-openssh-fod-v1', 'hashes': {'sshd': 'a' * 64}}
    def rejected():
        raise ValueError('support_dependency_signature_invalid')
    persisted = []
    monitor = module().OSDependencyMonitor(before, unchanged=lambda _: False,
        validate=rejected, persist=lambda *args: persisted.append(args))
    with pytest.raises(ValueError):
        monitor.refresh()
    assert monitor.dependencies == before and not persisted


@pytest.fixture
def os_snapshot(tmp_path, monkeypatch):
    import hashlib
    from pc_agent.platform.windows import support_access_native as native
    mod = module()
    root = tmp_path/'System32/OpenSSH';root.mkdir(parents=True)
    rows = []
    for name in ('ssh.exe', 'sshd.exe', 'ssh-keygen.exe'):
        (root/name).write_bytes(b'OS fixture')
        rows.append(dict(name=name, size=10, sha256=hashlib.sha256(b'OS fixture').hexdigest(),
                         version='9.5.6.4', publisher_thumbprint='A'*40))
    monkeypatch.setattr(native, 'windows_root', lambda: tmp_path)
    monkeypatch.setattr(mod, 'assert_os_path', lambda path: None)
    value = {'profile': mod.PROFILE, 'capability_version': '0.0.1.0', 'files': rows,
             'moduli_sha256': None, 'hashes': {}, 'versions': {}}
    for role, name in mod.ROLES.items():
        value[role] = str(root/name)
        value['hashes'][role] = rows[0]['sha256']
        value['versions'][role] = '9.5.6.4'
    return mod, root, value


def test_complete_snapshot_rejects_mixed_servicing_versions(os_snapshot):
    mod, root, value = os_snapshot
    value['files'][0]['version'] = '10.0.0.0'
    value['versions']['ssh'] = '10.0.0.0'
    with pytest.raises(ValueError):mod.verify_os_snapshot(value)


def test_snapshot_requires_recorded_microsoft_publisher_fingerprint(os_snapshot):
    mod, root, value = os_snapshot
    value['files'][0]['publisher_thumbprint'] = ''
    with pytest.raises(ValueError):mod.verify_os_snapshot(value)


def test_added_or_changed_helper_invalidates_cached_signature_closure(os_snapshot):
    mod, root, value = os_snapshot
    mod.verify_os_snapshot(value)
    (root/'ssh-shellhost.exe').write_bytes(b'new helper')
    assert not mod.snapshot_unchanged(value)


def test_service_refresh_validation_can_block_without_extending_the_existing_lease():
    from datetime import datetime, timezone
    from threading import Event, Thread
    from pc_agent.tests.windows.test_support_access import DEVICE, Children, policy
    from pc_agent.platform.windows.support_access import SupportSupervisor
    now = datetime.now(timezone.utc);children = Children();state = SupportSupervisor(DEVICE, children)
    state.accept(policy(now), now=now, monotonic_now=100)
    entered, release = Event(), Event()
    def validate():
        entered.set();release.wait(2)
        return {'profile': module().PROFILE}
    monitor = module().OSDependencyMonitor({'profile': module().PROFILE},
        unchanged=lambda _: False, validate=validate)
    worker = Thread(target=monitor.refresh);worker.start()
    assert entered.wait(1)
    try:
        state.tick(monotonic_now=161)
        assert not children.active
    finally:
        release.set();worker.join(2)
    state.tick(monotonic_now=162)
    assert not children.active


def test_unit_suite_blocks_native_operator_servicing_without_an_adapter():
    ops = object.__new__(module().WindowsFOD)
    with pytest.raises(pytest.fail.Exception, match='operator Windows servicing'):
        ops.capabilities()
    with pytest.raises(pytest.fail.Exception, match='operator Windows servicing'):
        ops.install((SERVER,))


def test_known_reboot_completion_can_revalidate_without_replaying_fod():
    ops = Servicing({CLIENT: 'Installed', SERVER: 'Installed'}, previous={
        'schema_version': 1, 'state': 'reboot_required', 'capabilities': [SERVER]})
    ops.reboot_completed = lambda old: True
    assert module().ensure_inbox_openssh(ops)['profile'] == module().PROFILE
    assert ops.receipt['state'] == 'complete'
    assert not any(isinstance(e, tuple) and e[0] == 'install' for e in ops.events)


def test_new_support_build_includes_metadata_for_cleanup_without_preview_archive(monkeypatch):
    from tools.canary.support_openssh_payload import resource_datas
    monkeypatch.delenv('ENDPOINT_SUPPORT_OPENSSH_ZIP', raising=False)
    repo = Path(__file__).resolve().parents[3]
    rows = resource_datas(repo, include_archive=False)
    assert {Path(source).name for source, target in rows} == {
        'manifest.json', 'LICENSE.txt', 'NOTICE.txt', 'QUALIFICATION.md'}
    assert all(target == 'support-openssh' for source, target in rows)


def test_completed_fod_with_transient_signature_failure_retries_only_verification():
    ops=Servicing({CLIENT:'Installed',SERVER:'NotPresent'})
    original=ops.verify
    ops.verify=lambda:(_ for _ in ()).throw(ValueError('temporary signature transport'))
    with pytest.raises(ValueError):module().ensure_inbox_openssh(ops)
    assert ops.receipt['state']=='installed_unverified'
    ops.verify=original;ops.events.clear()
    assert module().ensure_inbox_openssh(ops)['profile']==module().PROFILE
    assert ops.receipt['state']=='complete'
    assert not any(isinstance(e,tuple) and e[0]=='install' for e in ops.events)



class DurableServicing(Servicing):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.completion = None
    def completed_operation(self, previous):
        self.events.append('adopt')
        return self.completion


def test_lost_caller_adopts_only_durable_v2_completion_without_add_replay():
    ops = DurableServicing({CLIENT:'Installed', SERVER:'NotPresent'}, outcome='timeout')
    with pytest.raises(ValueError, match='support_dependency_recovery_required'):
        module().ensure_inbox_openssh(ops)
    assert ops.receipt['schema_version'] == 2
    ops.states[SERVER] = 'Installed'
    ops.completion = {'completed':True, 'restart_needed':False, 'boundary_preserved':True}
    ops.events.clear()
    assert module().ensure_inbox_openssh(ops)['profile'] == module().PROFILE
    assert ops.receipt['state'] == 'complete'
    assert 'adopt' in ops.events
    assert not any(isinstance(e,tuple) and e[0]=='install' for e in ops.events)


@pytest.mark.parametrize('outcome,state,error', [
    ({'completed':False,'restart_needed':False,'boundary_preserved':True}, 'failed','install_failed'),
    ({'completed':True,'restart_needed':True,'boundary_preserved':True}, 'reboot_required','reboot_required'),
    ({'completed':True,'restart_needed':False,'boundary_preserved':False}, 'conflict','firewall_conflict'),
])
def test_adopted_proof_keeps_original_result_classification(outcome,state,error):
    ops=DurableServicing({CLIENT:'Installed',SERVER:'Installed'}, previous={
        'schema_version':2,'state':'servicing','capabilities':[SERVER]})
    ops.completion=outcome
    with pytest.raises(ValueError,match='support_dependency_'+error):module().ensure_inbox_openssh(ops)
    assert ops.receipt['state']==state
    assert 'verify' not in ops.events


def test_legacy_v1_unknown_never_adopts_a_new_proof():
    ops=DurableServicing({CLIENT:'Installed',SERVER:'Installed'},previous={
        'schema_version':1,'state':'servicing','capabilities':[SERVER]})
    ops.completion={'completed':True,'restart_needed':False,'boundary_preserved':True}
    with pytest.raises(ValueError,match='support_dependency_recovery_required'):module().ensure_inbox_openssh(ops)
    assert 'adopt' not in ops.events


@pytest.fixture
def durable_files(tmp_path,monkeypatch):
    import hashlib
    from pc_agent.platform.windows import support_access_native as native
    monkeypatch.setattr(native,'assert_private',lambda path:None)
    ops=object.__new__(module().WindowsFOD)
    ops.root=tmp_path;ops.path=tmp_path/'os-servicing.json'
    request={'schema_version':2,'operation_id':'a'*32,'nonce':'b'*32,
             'boot_id':'boot-before','capabilities':[SERVER]}
    ops._metadata=dict(request,state='servicing')
    folder=tmp_path/('os-servicing-'+request['operation_id']);folder.mkdir()
    baseline=dict(request=request,service=None,rule=None)
    raw=json.dumps(baseline).encode();(folder/'baseline.json').write_bytes(raw)
    proof=dict(request=request,baseline_sha256=hashlib.sha256(raw).hexdigest(),
               result={'completed':True,'restart_needed':False,'boundary_preserved':True})
    (folder/'completion.json').write_text(json.dumps(proof))
    (folder/'worker.lock').touch()
    return ops,folder,proof


def test_operation_proof_requires_matching_exact_request_and_baseline(durable_files):
    ops,folder,proof=durable_files
    assert ops.completed_operation(ops._metadata)==proof['result']


@pytest.mark.parametrize('damage',['missing','partial','nonce','operation','capabilities','digest','baseline','result'])
def test_invalid_durable_completion_stays_unknown(durable_files,damage):
    ops,folder,proof=durable_files
    if damage=='missing':(folder/'completion.json').unlink()
    elif damage=='partial':(folder/'completion.json').write_text('{')
    else:
        if damage=='digest':proof['baseline_sha256']='0'*64
        elif damage=='baseline':(folder/'baseline.json').write_text('{}')
        elif damage=='result':proof['result']['completed']='true'
        else:proof['request'][{'operation':'operation_id'}.get(damage,damage)]=[] if damage=='capabilities' else 'c'*32
        (folder/'completion.json').write_text(json.dumps(proof))
    with pytest.raises(ValueError,match='support_dependency_recovery_required'):
        ops.completed_operation(ops._metadata)

@pytest.mark.parametrize('state,active',[('servicing',False),('complete',True),('complete',False)])
def test_uninstall_retains_orphan_evidence_and_refuses_active_worker(durable_files,monkeypatch,state,active):
    import win32file,win32con
    from pc_agent.platform.windows import support_access as support,support_access_native as native
    from pc_agent.tests.windows.test_support_access import _PayloadTestOps
    ops,folder,proof=durable_files
    receipt=dict(ops._metadata,state=state);ops.path.write_text(json.dumps(receipt))
    credential=ops.root/'credential';credential.write_text('fixture authority')
    calls=[]
    class Client:
        def unregister(self):calls.append('unregister')
    class Ops(_PayloadTestOps):
        def remove_service(self):calls.append('stop')
        def remove_payload(self,path):return False
    monkeypatch.setattr(native,'production_roots',lambda:(ops.root,ops.root/'program'))
    lock=win32file.CreateFile(str(folder/'worker.lock'),win32con.GENERIC_READ,0,None,win32con.OPEN_EXISTING,0,None) if active else None
    try:
        if state=='servicing' or active:
            with pytest.raises((ValueError,RuntimeError),match='support_dependency_recovery_required'):
                support.uninstall_support_access(_ops=Ops(),_client=Client())
            assert not calls and credential.exists() and ops.path.exists()
        else:
            assert support.uninstall_support_access(_ops=Ops(),_client=Client())['revoked']
            assert calls==['unregister','stop'] and not credential.exists()
        assert (folder/'baseline.json').exists() and (folder/'completion.json').exists()
    finally:
        if lock:lock.Close()


def test_payload_preflight_leaves_no_rollback_image_during_servicing_and_reentry(tmp_path):
    from pc_agent.tests.windows.test_support_access import _PayloadTestOps
    source=tmp_path/'candidate.exe';source.write_bytes(b'new')
    target=tmp_path/'active.exe';target.write_bytes(b'old')
    class Ops(_PayloadTestOps):
        def protect(self,path):pass
        def stop_for_update(self,path):pass
        def install_service(self,path):pass
    fod=DurableServicing({CLIENT:'Installed',SERVER:'NotPresent'},outcome='timeout')
    with Ops().prepare_payload(source,target):
        assert not target.with_suffix('.previous.exe').exists()
        with pytest.raises(ValueError,match='recovery_required'):module().ensure_inbox_openssh(fod)
        assert not target.with_suffix('.previous.exe').exists() and target.read_bytes()==b'old'
    fod.states[SERVER]='Installed'
    fod.completion={'completed':True,'restart_needed':False,'boundary_preserved':True}
    fod.events.clear()
    with Ops().prepare_payload(source,target) as activation:
        assert module().ensure_inbox_openssh(fod)['profile']==module().PROFILE
        activation.apply(reload=True)
    assert target.read_bytes()==b'new'
    assert not any(isinstance(e,tuple) and e[0]=='install' for e in fod.events)


def test_payload_changed_during_slow_preflight_refuses_before_backup_or_stop(tmp_path):
    from pc_agent.tests.windows.test_support_access import _PayloadTestOps
    source=tmp_path/'candidate.exe';source.write_bytes(b'new')
    target=tmp_path/'active.exe';target.write_bytes(b'old')
    class Ops(_PayloadTestOps):
        def protect(self,path):pass
        def stop_for_update(self,path):pytest.fail('changed active image was stopped')
    with pytest.raises(ValueError,match='support_payload_changed'):
        with Ops().prepare_payload(source,target) as activation:
            target.write_bytes(b'changed during servicing')
            activation.apply(reload=True)
    assert target.read_bytes()==b'changed during servicing'
    assert not target.with_suffix('.previous.exe').exists()
