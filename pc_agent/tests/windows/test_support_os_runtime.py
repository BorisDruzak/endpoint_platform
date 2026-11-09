"""OS servicing recovery must not turn stale policy or SCM RUNNING into readiness."""
import hashlib
import json
from pathlib import Path
from threading import Event, Thread

import pytest

from pc_agent.tests.windows.test_support_access import DEVICE, KEY, TOKEN, Children, policy
from datetime import datetime, timezone


def test_os_profile_boot_can_revalidate_changed_files_after_worker_starts(tmp_path, monkeypatch):
    from pc_agent.platform.windows import support_access_service as service
    config = {'device_id': DEVICE, 'origin': 'https://endpoint.sosnadmin.local',
              'dependencies': {'profile': 'windows-openssh-fod-v1', 'hashes': {}}}
    (tmp_path/'support.json').write_text(json.dumps(config))
    (tmp_path/'credential').write_text(TOKEN)
    (tmp_path/'ca.pem').write_text('fixture-ca')
    monkeypatch.setattr(service, 'assert_private', lambda _: None)
    monkeypatch.setattr(service, 'verify_dependencies', lambda _: pytest.fail(
        'Changed OS bytes must reach the independent revalidation worker, not permanent boot failure'))
    assert service.load_service(tmp_path)[0] == DEVICE


def test_dependency_validation_precedes_each_fresh_policy_fetch():
    from pc_agent.platform.windows import support_access_service as service
    calls, stop = [], Event()
    children = Children()
    disabled = dict(policy(datetime.now(timezone.utc)), enabled=False,
                    expires_at=None, operator_public_keys=[], windows_admin_username=None)
    def refresh():
        calls.append('validate')
        return {'profile': 'windows-openssh-fod-v1', 'generation': 'test'}
    class Client:
        def policy(self):
            assert calls[-1] == 'validate'
            calls.append('policy')
            return disabled
        def status(self, **kwargs):
            return disabled
    def publish(state):
        if state == 'disabled': stop.set()
    service.run_supervisor(DEVICE, Client(), children, stop,
        refresh_dependencies=refresh, publish=publish)
    assert calls[:2] == ['validate', 'policy']
    assert children.dependencies['generation'] == 'test'


def test_bad_os_replacement_reports_dependency_failure_without_fetching_authority():
    from pc_agent.platform.windows import support_access_service as service
    stop, errors = Event(), []
    children = Children()
    def refresh(): raise ValueError('support_dependency_signature_invalid')
    class Client:
        def policy(self): pytest.fail('Invalid dependencies must not fetch new authority')
        def status(self, **kwargs):
            errors.append(kwargs);stop.set()
            return {}
    service.run_supervisor(DEVICE, Client(), children, stop, refresh_dependencies=refresh)
    assert errors == [{'connected': False, 'error': 'dependency_unavailable'}]
    assert not children.active


def test_stale_lower_revision_does_not_reenable_after_newer_disable():
    from pc_agent.platform.windows.support_access import SupportSupervisor
    now = datetime.now(timezone.utc)
    children = Children();state = SupportSupervisor(DEVICE, children)
    active = policy(now)
    disabled = dict(active, revision=2, enabled=False, expires_at=None,
                    operator_public_keys=[], windows_admin_username=None)
    state.accept(disabled, now=now, monotonic_now=10)
    with pytest.raises(ValueError):
        state.accept(active, now=now, monotonic_now=11)
    assert not children.active


def test_config_waiting_service_is_not_successful_candidate_readiness():
    from pc_agent.platform.windows import support_access_readiness as readiness
    request = {'nonce': 'a'*32, 'image_sha256': 'b'*64}
    assert readiness.make_record(request, device_id=DEVICE, credential_sha256='c'*64,
        dependency_sha256='d'*64, state='configuration_unavailable', pid=42) is None


@pytest.mark.parametrize('field,value', [('nonce', '0'*32), ('image_sha256', '0'*64),
    ('device_id', 'other'), ('credential_sha256', '0'*64), ('dependency_sha256', '0'*64),
    ('state', 'connecting'), ('pid', 0)])
def test_ready_proof_is_bound_to_exact_candidate_and_current_authority(field, value):
    from pc_agent.platform.windows import support_access_readiness as readiness
    request = {'nonce': 'a'*32, 'image_sha256': 'b'*64}
    record = readiness.make_record(request, device_id=DEVICE, credential_sha256='c'*64,
        dependency_sha256='d'*64, state='tunnel_connected', pid=42)
    assert readiness.matches(record, request, device_id=DEVICE,
        credential_sha256='c'*64, dependency_sha256='d'*64, active_pids={42})
    record[field] = value
    assert not readiness.matches(record, request, device_id=DEVICE,
        credential_sha256='c'*64, dependency_sha256='d'*64, active_pids={42})


def test_disabled_policy_is_initialized_ready_without_unauthorized_tunnel():
    from pc_agent.platform.windows import support_access_readiness as readiness
    request = {'nonce': 'a'*32, 'image_sha256': 'b'*64}
    record = readiness.make_record(request, device_id=DEVICE, credential_sha256='c'*64,
        dependency_sha256='d'*64, state='disabled', pid=42)
    assert readiness.matches(record, request, device_id=DEVICE,
        credential_sha256='c'*64, dependency_sha256='d'*64, active_pids={42})


def test_failed_activation_restores_dependency_configuration_before_old_service(tmp_path):
    from pc_agent.platform.windows.support_access_native import PayloadActivation, atomic_write
    from pc_agent.tests.windows.test_support_access import _PayloadTestOps
    old = {'device_id': DEVICE, 'credential_id': 'same', 'dependencies': {'profile': 'bundled-openssh-v1'}}
    config = tmp_path/'support.json';config.write_text(json.dumps(old))
    (tmp_path/'credential').write_bytes(b'same-authority')
    source = tmp_path/'new.exe';source.write_bytes(b'candidate')
    target = tmp_path/'active.exe';target.write_bytes(b'previous')
    class Ops(_PayloadTestOps):
        def protect(self, path): pass
        def stop_for_update(self, path): pass
        def install_service(self, path): raise RuntimeError('candidate startup failure')
        def restore_service(self, path, state):
            assert json.loads(config.read_text()) == old
    with pytest.raises(RuntimeError, match='candidate startup'):
        with PayloadActivation(Ops(), source, target) as activation:
            activation.snapshot_configuration(config)
            atomic_write(config, json.dumps(dict(old, dependencies={'profile': 'windows-openssh-fod-v1'})))
            activation.apply(reload=True)
    assert target.read_bytes() == b'previous'


def test_compensation_never_restores_pre_reset_configuration(tmp_path):
    from pc_agent.platform.windows.support_access_native import PayloadActivation
    from pc_agent.tests.windows.test_support_access import _PayloadTestOps
    source = tmp_path/'new.exe';source.write_bytes(b'candidate')
    target = tmp_path/'active.exe';target.write_bytes(b'previous')
    config = tmp_path/'support.json';config.write_text(json.dumps({'credential_id': 'old'}))
    credential = tmp_path/'credential';credential.write_bytes(b'old-authority')
    class Ops(_PayloadTestOps):
        def protect(self, path): pass
    with pytest.raises(RuntimeError, match='reset interrupted'):
        with PayloadActivation(Ops(), source, target) as activation:
            activation.snapshot_configuration(config)
            activation.invalidate_configuration_compensation()
            credential.write_bytes(b'new-authority')
            config.write_text(json.dumps({'credential_id': 'new'}))
            raise RuntimeError('reset interrupted')
    assert json.loads(config.read_text())['credential_id'] == 'new'
    assert credential.read_bytes() == b'new-authority'


def test_frozen_style_entrypoint_uses_absolute_imports_for_os_inspection(monkeypatch,capsys):
    import runpy,sys
    from pc_agent.platform.windows import support_access_service, support_access_os
    monkeypatch.setattr(sys,'argv',['EndpointSupportAccess.exe','--inspect-os'])
    monkeypatch.setattr(support_access_os,'signed_os_dependencies',lambda:{'profile':support_access_os.PROFILE})
    with pytest.raises(SystemExit) as result:
        runpy.run_path(support_access_service.__file__,run_name='__main__')
    assert result.value.code==0
    assert json.loads(capsys.readouterr().out)['valid'] is True


def test_scm_running_without_initialized_record_cannot_retire_previous_payload(tmp_path,monkeypatch):
    import sys,types
    from pc_agent.platform.windows import support_access_native as native
    ops=native.WindowsSupportOps();ops._ready_root=tmp_path
    ops._ready_request={'nonce':'a'*32,'image_sha256':'b'*64}
    (tmp_path/'credential').write_text(TOKEN)
    (tmp_path/'support.json').write_text(json.dumps({'device_id':DEVICE,'dependencies':{}}))
    target=tmp_path/'EndpointSupportAccess.exe';target.write_bytes(b'fixture')
    class Processes:
        handles=[123]
        def __init__(self,path):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
    monkeypatch.setattr(ops,'assert_owned_service',lambda _:True)
    monkeypatch.setattr(native,'OwnedImageProcesses',Processes)
    monkeypatch.setattr(native,'assert_private',lambda _:None)
    monkeypatch.setattr(native,'verify_dependencies',lambda _:None)
    monkeypatch.setitem(sys.modules,'win32service',types.SimpleNamespace(SERVICE_RUNNING=4))
    monkeypatch.setitem(sys.modules,'win32serviceutil',types.SimpleNamespace(
        WaitForServiceStatus=lambda *a:None,QueryServiceStatus=lambda *a:(0,4)))
    monkeypatch.setitem(sys.modules,'win32process',types.SimpleNamespace(
        GetExitCodeProcess=lambda _:259,GetProcessId=lambda _:42))
    clock=iter([0,100,200,300]);monkeypatch.setattr(native.time,'monotonic',lambda:next(clock))
    with pytest.raises(RuntimeError,match='support_service_not_ready'):
        ops.prove_service_ready(target)


@pytest.mark.parametrize('missing_code',[2,3,5])
def test_first_start_waits_for_win32_missing_readiness_before_accepting(tmp_path,monkeypatch,missing_code):
    """GetNamedSecurityInfo raises pywintypes.error, not OSError, before publish."""
    import sys,types,hashlib,pywintypes
    from pc_agent.platform.windows import support_access_native as native
    from pc_agent.platform.windows.support_access_readiness import make_record,dependency_digest
    ops=native.WindowsSupportOps();ops._ready_root=tmp_path
    request=ops._ready_request={'nonce':'a'*32,'image_sha256':'b'*64}
    deps={'profile':'fixture'}
    (tmp_path/'credential').write_text(TOKEN)
    (tmp_path/'support.json').write_text(json.dumps({'device_id':DEVICE,'dependencies':deps}))
    target=tmp_path/'EndpointSupportAccess.exe';target.write_bytes(b'fixture')
    class Processes:
        handles=[123]
        def __init__(self,path):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
    checks=[]
    def private(path):
        if path.name!='readiness.json':return
        checks.append(path)
        if len(checks)==1:raise pywintypes.error(missing_code,'GetNamedSecurityInfo','not published yet')
        record=make_record(request,device_id=DEVICE,credential_sha256=hashlib.sha256(TOKEN.encode()).hexdigest(),dependency_sha256=dependency_digest(deps),state='tunnel_connected',pid=42)
        path.write_text(json.dumps(record))
    monkeypatch.setattr(ops,'assert_owned_service',lambda _:True)
    monkeypatch.setattr(native,'OwnedImageProcesses',Processes)
    monkeypatch.setattr(native,'assert_private',private)
    monkeypatch.setattr(native,'verify_dependencies',lambda _:None)
    monkeypatch.setitem(sys.modules,'win32service',types.SimpleNamespace(SERVICE_RUNNING=4))
    monkeypatch.setitem(sys.modules,'win32serviceutil',types.SimpleNamespace(WaitForServiceStatus=lambda *a:None,QueryServiceStatus=lambda *a:(0,4)))
    monkeypatch.setitem(sys.modules,'win32process',types.SimpleNamespace(GetExitCodeProcess=lambda _:259,GetProcessId=lambda _:42))
    monkeypatch.setattr(native.time,'sleep',lambda _:None)
    if missing_code==5:
        with pytest.raises(pywintypes.error):ops.prove_service_ready(target)
        assert len(checks)==1
    else:
        ops.prove_service_ready(target)
        assert len(checks)==2


@pytest.mark.parametrize('state',['complete','installed_unverified','servicing'])
def test_uninstall_cleans_new_owned_metadata_but_preserves_uncertain_servicing(tmp_path,monkeypatch,state):
    from pc_agent.platform.windows import support_access as support,support_access_native as native
    from pc_agent.tests.windows.test_support_access import _PayloadTestOps
    root=tmp_path/'Support';root.mkdir()
    for name in ['credential','readiness-request.json','readiness.json']:(root/name).write_text('owned fixture')
    journal=root/'os-servicing.json';journal.write_text(json.dumps({'schema_version':1,'state':state}))
    calls=[]
    class Client:
        def unregister(self):calls.append('unregister')
    class Ops(_PayloadTestOps):
        def remove_service(self):calls.append('stop')
        def remove_payload(self,program):return False
    monkeypatch.setattr(native,'production_roots',lambda:(root,tmp_path/'ProgramSupport'))
    monkeypatch.setattr(native,'assert_private',lambda _:None)
    if state=='servicing':
        with pytest.raises(RuntimeError,match='support_dependency_recovery_required'):
            support.uninstall_support_access(_ops=Ops(),_client=Client())
        assert journal.exists() and (root/'credential').exists() and not calls
    else:
        result=support.uninstall_support_access(_ops=Ops(),_client=Client())
        assert result['revoked'] and not root.exists()


def test_reset_then_failed_start_restores_only_compatible_dependencies(tmp_path):
    from pc_agent.platform.windows.support_access_native import PayloadActivation
    from pc_agent.tests.windows.test_support_access import _PayloadTestOps
    old={'device_id':DEVICE,'origin':'https://endpoint.sosnadmin.local','credential_id':'old',
         'dependencies':{'profile':'bundled-openssh-v1'}}
    new=dict(old,credential_id='new',dependencies={'profile':'windows-openssh-fod-v1'})
    config=tmp_path/'support.json';config.write_text(json.dumps(old))
    credential=tmp_path/'credential';credential.write_bytes(b'old-authority')
    source=tmp_path/'new.exe';source.write_bytes(b'new')
    target=tmp_path/'active.exe';target.write_bytes(b'old')
    class Ops(_PayloadTestOps):
        def protect(self,path):pass
        def stop_for_update(self,path):pass
        def install_service(self,path):raise RuntimeError('new startup failed')
        def restore_service(self,path,state):
            restored=json.loads(config.read_text())
            assert restored['dependencies']==old['dependencies']
            assert restored['credential_id']=='new' and credential.read_bytes()==b'new-authority'
    with pytest.raises(RuntimeError,match='new startup failed'):
        with PayloadActivation(Ops(),source,target) as activation:
            activation.snapshot_configuration(config)
            activation.invalidate_configuration_compensation()
            credential.write_bytes(b'new-authority');config.write_text(json.dumps(new))
            activation.apply(reload=True)


def test_loss_of_tunnel_invalidates_same_candidate_initialized_proof(tmp_path,monkeypatch):
    import sys
    from pc_agent.platform.windows import support_access_readiness as ready,support_access_native as native
    image=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
    request={'nonce':'a'*32,'image_sha256':image}
    (tmp_path/'readiness-request.json').write_text(json.dumps(request))
    (tmp_path/'credential').write_text(TOKEN)
    (tmp_path/'support.json').write_text(json.dumps({'device_id':DEVICE}))
    children=type('Children',(),{'dependencies':{},'dependencies_validated':True})()
    monkeypatch.setattr(native,'assert_private',lambda _:None)
    monkeypatch.setattr(native.WindowsSupportOps,'protect',lambda *a:None)
    ready.publish_initialized(tmp_path,children,'disabled')
    assert json.loads((tmp_path/'readiness.json').read_text())['state']=='disabled'
    children.dependencies_validated=False
    ready.publish_initialized(tmp_path,children,'dependency_unavailable')
    record=json.loads((tmp_path/'readiness.json').read_text())
    assert not ready.matches(record,request,device_id=DEVICE,
        credential_sha256=hashlib.sha256(TOKEN.encode()).hexdigest(),
        dependency_sha256=ready.dependency_digest({}),active_pids={record.get('pid')})
