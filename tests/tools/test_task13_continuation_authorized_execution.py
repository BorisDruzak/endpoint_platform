"""A new actual authorization never restores a consumed launch claim."""
import os,copy
from pathlib import Path
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
import pytest
from tools.canary.task13_continuation.codec import parse_json
from tools.canary.task13_continuation.storage import ProtectedStore
pytestmark=pytest.mark.no_db

@pytest.mark.skipif(not os.environ.get('TASK13_HISTORICAL_ROOT'),reason='private retained admission and operator request')
def test_actual_execution_request_has_distinct_scope():
    from tools.canary.task13_continuation.permission import capture_permission
    assert capture_permission()['scope']=='seq04-after-readonly-recovery'

@pytest.mark.skipif(not os.environ.get('TASK13_HISTORICAL_ROOT'),reason='private retained admission and operator request')
def test_actual_execution_permission_binds_independent_admission():
    from tools.canary.task13_continuation.permission import capture_execution_permission,verify_permission
    value=capture_execution_permission()
    assert value['scope']=='seq04-after-readonly-recovery' and value['gate_admission_sha256']
    verify_permission(value)

@pytest.fixture
def owned(tmp_path):
    if os.name != 'nt':pytest.skip('native Windows protected execution claims')
    from tools.canary.task13_continuation import authorized_execution as execution
    root=ProtectedStore.create_root(tmp_path/'owned-prefix').root
    prefix=SimpleNamespace(root=root,binding=dict(original_run_seal_sha256='1'*64,original_tip='2'*64))
    request=dict(scope='seq04-after-readonly-recovery',record_sha256='3'*64,gate_admission_sha256='4'*64)
    first=dict(continuation_id='11111111-1111-4111-8111-111111111111');second=dict(continuation_id='22222222-2222-4222-8222-222222222222')
    return execution,prefix,request,first,second

def test_missing_foreign_and_repeat_child_claim_refuse(owned):
    ex,p,r,a,b=owned
    with pytest.raises(ValueError):ex.check_launch(p,r,a,child=True)
    ex.claim_launch(p,r,a)
    ex.check_launch(p,r,a,child=True)
    with pytest.raises(ValueError):ex.check_launch(p,r,b,child=True)
    with pytest.raises(ValueError):ex.check_launch(p,r,a,child=False)
    with pytest.raises(OSError):ex.claim_launch(p,r,a)

def test_crash_before_spawn_cannot_restore_launch(owned):
    ex,p,r,a,b=owned;ex.claim_launch(p,r,a)
    before=ex.launch_path(p,r).read_bytes()
    for closure in (a,b):
        with pytest.raises(ValueError):ex.check_launch(p,r,closure,child=False)
    assert ex.launch_path(p,r).read_bytes()==before

def test_concurrent_different_cids_share_one_execution_claim(owned):
    ex,p,r,a,b=owned
    ProtectedStore.create_root(ex.launch_path(p,r).parent)
    def attempt(closure):
        try:ex.claim_launch(p,r,closure);return True
        except OSError:return False
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(attempt,(a,b)))
    assert sorted(results)==[False,True]
    assert parse_json(ex.launch_path(p,r).read_bytes()) in (ex.launch_owner(p,r,a),ex.launch_owner(p,r,b))

@pytest.mark.skipif(not os.environ.get('TASK13_HISTORICAL_ROOT'),reason='private retained admission')
def test_fixed_independent_admission_and_oldclaim_preserved():
    from tools.canary.task13_continuation.authorized_execution import capture_admission
    from tools.canary.task13_continuation.history import verify_historical_prefix
    from tools.canary.task13_continuation.recovery import recovery_launch_path
    prefix=verify_historical_prefix(Path(os.environ['TASK13_HISTORICAL_ROOT']))
    before=recovery_launch_path(prefix).read_bytes();admission=capture_admission(prefix)
    assert admission['status']=='PRIOR_READONLY_RECOVERY_VERIFIED'
    assert admission['historical_rca']=='UNKNOWN'
    assert recovery_launch_path(prefix).read_bytes()==before

@pytest.mark.skipif(not os.environ.get('TASK13_HISTORICAL_ROOT'),reason='private retained admission')
def test_changed_admission_audit_refuses(monkeypatch):
    from tools.canary.task13_continuation.authorized_execution import capture_admission
    read=ProtectedStore.read
    def changed(self,name):
        raw=read(self,name)
        return raw+b' ' if name=='independent-observation-audit.json' else raw
    monkeypatch.setattr(ProtectedStore,'read',changed)
    with pytest.raises(ValueError,match='prior recovery admission pin'):capture_admission()

def test_spawn_failure_consumes_once_before_popen_and_cannot_retry(owned,tmp_path,monkeypatch):
    import sys
    from contextlib import contextmanager
    from tools.canary.task13_continuation import supervisor
    ex,p,r,a,b=owned;store=ProtectedStore.create_root(tmp_path/'owned-execution')
    current={'store':store,'closure':a};calls=[]
    from tests.tools.test_task13_command_transport import short_plan
    operations,entries=short_plan()
    @contextmanager
    def reviewed(*args):
        yield current['store'],{**current['closure'],'runtime':{sys._base_executable:{}}},{},{},entries,p,r,operations,dict(root_interpreter=sys._base_executable)
    monkeypatch.setattr(supervisor,'reviewed_bundle',reviewed)
    monkeypatch.setattr(supervisor,'require_seq04_permission',lambda request:None)
    def failed_spawn(*args,**kwargs):
        assert ex.launch_path(p,r).exists()
        with pytest.raises(OSError):ex.launch_path(p,r).write_bytes(b'{}')
        calls.append('spawn');raise OSError('owned synthetic spawn failure')
    monkeypatch.setattr(supervisor.subprocess,'Popen',failed_spawn)
    monkeypatch.setattr(sys,'argv',[str(store.root/'bootstrap.py'),'--execute-reviewed-seq04'])
    with pytest.raises(OSError):supervisor.supervise(store.root)
    original=ex.launch_path(p,r).read_bytes()
    assert parse_json(store.read('supervisor-unknown.json'))['retry_allowed'] is False
    next_store=ProtectedStore.create_root(tmp_path/'different-cid');current.update(store=next_store,closure=b)
    monkeypatch.setattr(sys,'argv',[str(next_store.root/'bootstrap.py'),'--execute-reviewed-seq04'])
    with pytest.raises(OSError):supervisor.supervise(next_store.root)
    assert calls==['spawn'] and ex.launch_path(p,r).read_bytes()==original
    assert not (store.root/'receipt-04-compare-after-start.json').exists()
