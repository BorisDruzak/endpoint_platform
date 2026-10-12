"""New authorized observation scope; never an execution retry."""
import os,copy,json,subprocess,base64,sys
from pathlib import Path
import pytest
from tests.tools.test_task13_continuation_reconciliation import state_case

pytestmark=pytest.mark.no_db

def test_execution_permission_cannot_upgrade_readonly_recovery(monkeypatch):
    from tools.canary.task13_continuation import permission,gate_admission
    monkeypatch.setattr(permission,'capture_permission',lambda:dict(scope='readonly-unknown-recovery'))
    monkeypatch.setattr(gate_admission,'capture_gate',lambda *a:{'synthetic':True})
    with pytest.raises(ValueError,match='read-only recovery forbids seq04'):
        permission.capture_execution_permission()

def test_bundle_rejects_mixed_execution_recovery_before_any_read():
    from tools.canary.task13_continuation.bundle import prepare_bundle
    with pytest.raises(ValueError,match='read-only recovery forbids seq04'):
        prepare_bundle(Path('absent'),Path('absent'),readonly_recovery=True,separate_seq04=True)

@pytest.mark.skipif(os.name!='nt',reason='owned Windows error31 reproduction')
def test_exited_owned_process_retains_native_failure_diagnostics_and_blocks():
    from tools.canary.task13_continuation.process_identity import classify_identity
    source=(Path(__file__).resolve().parents[2]/'tools/canary/Observe-Task13ProcessIdentity.ps1').read_text()
    child=subprocess.Popen([sys.executable,'-B','-c','pass']);child.wait(timeout=10)
    script=("$ProgressPreference='SilentlyContinue';& {"+source+"} -RunId '11111111-1111-4111-8111-111111111111' -ExpectedVmUuid ([Guid](Get-CimInstance Win32_ComputerSystemProduct).UUID) -RegistrySha256 '"+'0'*64+"' -Ids @("+str(child.pid)+")")
    result=subprocess.run([str(Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe'),'-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16-le')).decode()],capture_output=True,timeout=30,creationflags=0x08000000)
    assert result.returncode==0 and not result.stderr
    value=json.loads(result.stdout);row=value['rows'][0]
    assert classify_identity(dict(pid=child.pid,absence_filetime=1,original_birth_filetime=None),row)=='IDENTITY_UNKNOWN'
    failure=value['diagnostics'][0]['failure']
    assert failure['stage']=='QueryFullProcessImageName' and failure['native_error']==31
    assert failure['first_wait']==0 and failure['partial']['birth_filetime']>0
    assert failure['error_record']['fully_qualified_error_id']=='native image unavailable'
    assert failure['error_record']['exceptions'][0]['type']=='System.Management.Automation.RuntimeException'
    assert failure['error_record']['exceptions'][0]['hresult']==-2146233087
    assert row['first'] is None and row['error_type']=='RuntimeException'

@pytest.fixture(scope='module')
def prefix():
    if not os.environ.get('TASK13_HISTORICAL_ROOT'):pytest.skip('private historical prefix')
    from tools.canary.task13_continuation.history import verify_historical_prefix
    return verify_historical_prefix(Path(os.environ['TASK13_HISTORICAL_ROOT']))

def test_capture_readonly_recovery_preserves_consumed_claim(prefix):
    from tools.canary.task13_continuation.readonly_recovery import capture_readonly_recovery
    from tools.canary.task13_continuation.recovery import recovery_launch_path
    before=recovery_launch_path(prefix).read_bytes()
    value=capture_readonly_recovery(prefix)
    assert value['historical_rca']=='UNKNOWN' and value['seq04_authorized'] is False
    assert value['original']==prefix.binding and len(value['files'])>50
    assert recovery_launch_path(prefix).read_bytes()==before

def test_changed_failed_identity_blocks_readonly_recovery(prefix,monkeypatch):
    from tools.canary.task13_continuation.readonly_recovery import capture_readonly_recovery
    from tools.canary.task13_continuation.storage import ProtectedStore
    read=ProtectedStore.read
    def changed(self,name):
        raw=read(self,name)
        return raw+b' ' if name=='transport-006-process_identity-result.json' else raw
    monkeypatch.setattr(ProtectedStore,'read',changed)
    with pytest.raises(ValueError,match='immutable failed recovery pin'):
        capture_readonly_recovery(prefix)

def test_changed_consumed_claim_blocks_readonly_recovery(prefix,monkeypatch):
    from tools.canary.task13_continuation.readonly_recovery import capture_readonly_recovery
    from tools.canary.task13_continuation.storage import ProtectedStore
    read=ProtectedStore.read
    def changed(self,name):
        raw=read(self,name)
        if name.startswith('recovery-launch-'):return b'{}'
        return raw
    monkeypatch.setattr(ProtectedStore,'read',changed)
    with pytest.raises(ValueError,match='consumed claim owner'):
        capture_readonly_recovery(prefix)

def diagnostic_v2(value):
    value['schema']='task13_native_process_identity_v2'
    value['diagnostics']=[dict(pid=row['pid'],failure=None,elapsed_ms=1) for row in value['rows']]
    value['caller_context']=dict(pid=900,user_sid='S-1-5-18',authentication_type='synthetic',
        impersonation_level='None',is_admin=True,ps_version='5.1',clr_version='4',is_64bit=True,
        requested_process_access=0x101000,privileges=[])
    return value

def test_v2_diagnostics_preserve_full_canonical_synthetic_gate(state_case):
    from tools.canary.task13_continuation.reconciliation import validate_state
    from tests.tools.test_task13_continuation_reconciliation import rebind
    p,c,s,at=state_case
    value=diagnostic_v2(s['constituents']['process_identity']['observation'])
    rebind(s,'process_identity',value)
    validate_state(p,c,s,at)

@pytest.mark.parametrize('mutation',['denied','pid','size','extra','missing','context','failure'])
def test_v2_diagnostics_never_admit_denied_or_malformed_identity(state_case,mutation):
    from tools.canary.task13_continuation.reconciliation import validate_state
    from tests.tools.test_task13_continuation_reconciliation import rebind
    p,c,s,at=state_case;value=diagnostic_v2(s['constituents']['process_identity']['observation'])
    if mutation=='denied':value['rows'][0]['first']['native_error']=5
    elif mutation=='pid':value['diagnostics'][0]['pid']+=1
    elif mutation=='size':value['caller_context']['privileges']=['x'*513]
    elif mutation=='extra':value['diagnostics'][0]['state']='PID_REUSED'
    elif mutation=='missing':value.pop('diagnostics')
    elif mutation=='context':value['caller_context']['requested_process_access']=0x1FFFFF
    else:value['diagnostics'][0]['failure']={'state':'PID_REUSED'}
    rebind(s,'process_identity',value)
    with pytest.raises((ValueError,KeyError)):validate_state(p,c,s,at)

def test_changed_readonly_record_refuses_under_retained_handles(prefix):
    from contextlib import ExitStack
    from tools.canary.task13_continuation.readonly_recovery import capture_readonly_recovery,hold_readonly_recovery
    record=capture_readonly_recovery(prefix);record['historical_rca']='PASS'
    with ExitStack() as held,pytest.raises(ValueError,match='cannot authorize'):
        hold_readonly_recovery(held,record,prefix)

@pytest.mark.skipif(os.name!='nt',reason='owned protected observation')
@pytest.mark.parametrize('success',[True,False])
def test_new_readonly_orchestration_never_grants_execution(tmp_path,monkeypatch,success):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from tools.canary.task13_continuation import loader,readonly_gate,readonly_recovery
    from tools.canary.task13_continuation.storage import ProtectedStore
    from tools.canary.task13_continuation.codec import canonical
    store=ProtectedStore.create_root(tmp_path/'guard');identity=dict(pid=100,birth=200)
    record=dict(schema='synthetic-only',historical_rca='UNKNOWN',seq04_authorized=False)
    @contextmanager
    def bundle(*args):
        yield store,{}, {}, {'reviewer_controller':dict(pid=300,birth=400)}, {'recovery.json':canonical(record)},SimpleNamespace(binding={}),dict(scope='readonly-unknown-recovery'),{},{}
    monkeypatch.setattr(loader,'reviewed_bundle',bundle)
    monkeypatch.setattr(readonly_gate.windows,'observe_controller',lambda:identity)
    monkeypatch.setattr(readonly_gate,'verify_permission',lambda *a:None)
    monkeypatch.setattr(readonly_recovery,'capture_readonly_recovery',lambda *a:record)
    def reconcile(*args):
        if not success:raise ValueError('synthetic UNKNOWN')
        return {'synthetic':'complete'}
    monkeypatch.setattr(loader,'_reconcile',reconcile)
    monkeypatch.setattr(sys,'argv',[str(store.root/'bootstrap.py'),'--observe-reviewed-guard'])
    value=readonly_gate.observe_reviewed_guard(store.root)
    assert value['status']==('READ_ONLY_CANONICAL_PREFLIGHT_PASS' if success else 'BLOCKED')
    assert value['historical_rca']=='UNKNOWN' and value['seq04_authorized'] is False
    assert value['seq04_dispatched'] is False and value['claims_consumed'] is False
    assert value['consumed_claim_unchanged'] is True
    assert {p.name for p in store.root.iterdir()}=={'read-only-guard'}

@pytest.mark.parametrize('entry',['--execute-reviewed-seq04','--execute-reviewed-seq04-child'])
@pytest.mark.skipif(not os.environ.get('TASK13_HISTORICAL_ROOT'),reason='private retained operator request')
def test_actual_new_request_scope_denies_execution(entry):
    from tools.canary.task13_continuation.permission import capture_permission,require_seq04_permission,verify_permission
    permission=capture_permission();assert permission['scope'] in ('readonly-unknown-recovery','seq04-after-readonly-recovery')
    # Raw authorization alone is not the admitted execution permission; the
    # actual new request still needs a verified immutable prior gate binding.
    with pytest.raises(ValueError,match='separate (seq04|execution)'):require_seq04_permission(permission)
