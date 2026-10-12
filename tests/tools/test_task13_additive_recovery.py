"""Owned synthetic recovery slots; never issue a real Task13 execution claim."""
import importlib.util
import copy
import os
import subprocess
import sys
from datetime import datetime,timedelta,timezone
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from uuid import uuid4
from pathlib import Path

import pytest

pytestmark=pytest.mark.no_db
from tools.canary.task13_continuation.codec import canonical,digest,parse_json,sha256
from tools.canary.task13_continuation.history import ORIGINAL_FILES,BASELINE_SHA,SNAPSHOT_SHA
from tools.canary.task13_continuation.storage import ProtectedStore

def protocol():
    assert importlib.util.find_spec('tools.canary.task13_continuation.recovery_admission') is not None
    from tools.canary.task13_continuation import recovery_admission
    return recovery_admission

@pytest.fixture
def owned(tmp_path,monkeypatch):
    if os.name != 'nt':pytest.skip('native Windows protected recovery slots')
    root=ProtectedStore.create_root(tmp_path/'synthetic-history').root
    ProtectedStore.create_root(root/'continuation-v1-claims')
    retained=Path.home()/'.codex/task-evidence/task13-command-transport-review-20261011-c/control.json'
    if not retained.exists():pytest.skip('private immutable prefix metadata; slots use owned synthetic directories')
    original=parse_json(retained.read_bytes())['original_binding']
    p=SimpleNamespace(root=root,binding=original)
    # Replace the trusted root resolver only in owned native-storage fixtures.
    # Production has no alternate-root selector or synthetic execution flag.
    from tools.canary.task13_continuation import recovery_admission
    monkeypatch.setattr(recovery_admission,'_canonical_original_root',lambda:root)
    from tools.canary.task13_continuation.recovery_admission import OLD_CLAIMS,GLOBAL_NAME,FAILED_TREE_SHA,READONLY_TREE_SHA
    historical=dict(schema='task13_consumed_history_v1',original=original,global_claim_sha256=OLD_CLAIMS[GLOBAL_NAME],
        claims=dict(OLD_CLAIMS),failed_bundle_sha256=FAILED_TREE_SHA,prior_readonly_sha256=READONLY_TREE_SHA,
        prior_root={'pid':123,'birth':456},failure_phase='PREPARE_BUILDER_REFUSED_BEFORE_TRANSPORT',historical_rca='UNKNOWN')
    record=dict(schema='task13_recovery_launch_slot_v1',original=original,history_sha256=digest(historical),
        consumed_global_claim_sha256=historical['global_claim_sha256'],protocol_version=1,protocol_source_sha256='d'*64,implementation_sha='e'*40,
        continuation_id=str(uuid4()),gate_sha256='f'*64,request_sha256='1'*64,source_closure_sha256='2'*64,
        capsule_sha256='3'*64,preflight_sha256='4'*64,expires_utc='2099-01-01T00:00:00+00:00',
        controller={'pid':123,'birth':456,'host_id':'a'*64,'boot_id':str(uuid4()),'token_sid':'S-1-5-18','elevated':True})
    return p,historical,record

def test_separate_protocol_can_be_selected_without_restoring_ordinary_claim(owned):
    m=protocol();p,h,r=owned
    old=p.root/'continuation-v1-claims/old.json';ProtectedStore(old.parent).create(old.name,b'{"consumed":true}')
    before=old.read_bytes()
    assert m.slot_state(p,h)=='ABSENT'
    m._commit_native(m.slot_path(p,h,'launch'),canonical(r))
    assert m.slot_state(p,h)=='LAUNCH_COMMITTED' and old.read_bytes()==before

def test_cid_request_revision_and_deadline_cannot_issue_another_slot(owned):
    m=protocol();p,h,r=owned
    path=m.slot_path(p,h,'launch');m._commit_native(path,canonical(r))
    for change in [dict(continuation_id=str(uuid4())),dict(protocol_version=2),dict(request_sha256='9'*64),dict(expires_utc='2100-01-01T00:00:00Z')]:
        with pytest.raises(OSError):m._commit_native(m.slot_path(p,h,'launch'),canonical(dict(r,**change)))
    assert parse_json(path.read_bytes())==r

def test_parallel_native_consumers_have_exactly_one_winner(owned):
    m=protocol();p,h,r=owned;path=m.slot_path(p,h,'launch')
    def attempt(index):
        try:m._commit_native(path,canonical(dict(r,continuation_id=str(uuid4()))));return True
        except OSError:return False
    with ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(attempt,range(8)))
    assert results.count(True)==1

def test_v1_and_v2_share_one_irreversible_slot(owned):
    m=protocol();p,h,r=owned;path=m.slot_path(p,h,'launch')
    def attempt(version):
        record=dict(r,protocol_version=version)
        m.validate_launch_record(p,h,record)
        try:m._commit_native(path,canonical(record));return True
        except OSError:return False
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(attempt,(1,2)))
    assert results.count(True)==1 and m.slot_state(p,h)=='LAUNCH_COMMITTED'
    with pytest.raises(ValueError):m.require_unused_slot(p,h)

@pytest.mark.parametrize('raw',[b'',b'{',b'{}',b'{"schema":"wrong"}'])
def test_restart_after_partial_slot_is_permanently_fail_closed(owned,raw):
    m=protocol();p,h,r=owned;path=m.slot_path(p,h,'launch')
    ProtectedStore(path.parent).create(path.name,raw)
    assert m.slot_state(p,h)=='OCCUPIED_UNKNOWN'
    with pytest.raises(OSError):m._commit_native(path,canonical(r))
    assert path.read_bytes()==raw

def test_consumed_launch_slot_restarts_as_blocked_without_reissue(owned):
    m=protocol();p,h,r=owned;path=m.slot_path(p,h,'launch');m._commit_native(path,canonical(r))
    assert m.slot_state(p,h)=='LAUNCH_COMMITTED'
    with pytest.raises(ValueError,match='already occupied'):m.require_unused_slot(p,h)
    with pytest.raises(OSError):m._commit_native(path,canonical(r))

def test_dispatch_transition_requires_exact_launch_and_is_single_use(owned):
    m=protocol();p,h,r=owned
    launch=m.slot_path(p,h,'launch');dispatch=m.slot_path(p,h,'dispatch')
    m._commit_native(launch,canonical(r))
    d=dict(schema='task13_recovery_dispatch_slot_v1',launch_slot_sha256=digest(r),continuation_id=r['continuation_id'],
        original=p.binding,protocol_version=1,protocol_source_sha256=r['protocol_source_sha256'],
        consumed_global_claim_sha256=h['global_claim_sha256'],capsule_sha256='5'*64,preflight_sha256='6'*64)
    m.validate_dispatch_record(p,h,r,d)
    with pytest.raises(ValueError):m.validate_dispatch_record(p,h,r,dict(d,continuation_id=str(uuid4())))
    m._commit_native(dispatch,canonical(d))
    assert m.slot_state(p,h)=='DISPATCH_COMMITTED'
    with pytest.raises(OSError):m._commit_native(dispatch,canonical(d))

@pytest.mark.parametrize('field',['original_plan_sha256','original_run_seal_sha256','original_tip','baseline_sha256','snapshot_identity_sha256','verified_receipt_count'])
def test_wrong_historical_prefix_cannot_select_recovery_slot(owned,field):
    m=protocol();p,h,r=owned;bad=copy.deepcopy(h);bad['original'][field]='wrong'
    with pytest.raises(ValueError):m.slot_path(p,bad,'launch')
    assert list((p.root/'continuation-v1-claims').iterdir())==[]

def test_forged_consumed_global_hash_cannot_select_an_alternate_slot(owned):
    m=protocol();p,h,r=owned
    with pytest.raises(ValueError):m.slot_path(p,dict(h,global_claim_sha256='9'*64),'launch')

def test_copied_prefix_cannot_select_second_physical_recovery_slot(owned,tmp_path):
    m=protocol();p,h,r=owned
    copied=SimpleNamespace(root=tmp_path/'copied-history',binding=p.binding)
    with pytest.raises(ValueError,match='canonical historical root'):m.slot_path(copied,h,'launch')

def permission_module():
    assert importlib.util.find_spec('tools.canary.task13_continuation.recovery_permission') is not None
    from tools.canary.task13_continuation import recovery_permission
    return recovery_permission

@pytest.fixture
def session_case(tmp_path,monkeypatch):
    home=tmp_path/'app';folder=home/'.codex/sessions/2026/10/12';folder.mkdir(parents=True)
    thread=str(uuid4());path=folder/('rollout-test-'+thread+'.jsonl')
    monkeypatch.setenv('CODEX_THREAD_ID',thread)
    from pathlib import Path
    monkeypatch.setattr(Path,'home',classmethod(lambda cls:home))
    gate=dict(schema='task13_additive_recovery_gate_v1',status='READY_REQUIRES_SEPARATE_AUTHORIZATION',
        continuation_id=str(uuid4()),implementation_sha='a'*40,protocol_source_sha256='b'*64,
        checked_utc=datetime.now(timezone.utc).isoformat(),allowed_seq=4,seq04_authorized=False)
    fields=dict(gate_sha256=digest(gate),implementation_sha=gate['implementation_sha'],protocol_source_sha256='b'*64,
        continuation_id=gate['continuation_id'],allowed_seq=4,
        expires_utc=(datetime.now(timezone.utc)+timedelta(seconds=1100)).isoformat())
    def write(text,extra=None):
        frames=[dict(type='session_meta',payload=dict(id=thread)),dict(type='response_item',payload=dict(type='message',role='user',content=[dict(type='input_text',text=text)]))]
        if extra is not None:frames.append(dict(type='response_item',payload=dict(type='message',role='user',content=[dict(type='input_text',text=extra)])))
        path.write_bytes(b'\n'.join(canonical(f) for f in frames)+b'\n')
    return gate,fields,write,path

def test_actual_fresh_human_record_can_bind_recovery_but_implementation_scope_cannot(session_case):
    m=permission_module();gate,f,write,path=session_case
    write('TASK13_RECOVERY_EXECUTE_V1 '+canonical(f).decode())
    grant=m.capture_recovery_permission(gate)
    assert grant['scope']=='seq04-additive-recovery-v1' and grant['gate_sha256']==digest(gate)
    m.verify_recovery_permission(grant,gate)
    write('Implement recovery protocol; do not execute seq04')
    with pytest.raises(ValueError):m.verify_recovery_permission(grant,gate)

@pytest.mark.parametrize('fault',['quote','latest_changed','wrong_gate','wrong_source','wrong_revision','wrong_cid','seq05','expired','too_long','noncanonical','boolean_seq'])
def test_permission_replay_mismatch_or_expiry_has_no_execution_authority(session_case,fault):
    m=permission_module();gate,f,write,path=session_case
    if fault=='wrong_gate':f['gate_sha256']='c'*64
    elif fault=='wrong_source':f['protocol_source_sha256']='c'*64
    elif fault=='wrong_revision':f['implementation_sha']='c'*40
    elif fault=='wrong_cid':f['continuation_id']=str(uuid4())
    elif fault=='seq05':f['allowed_seq']=5
    elif fault=='boolean_seq':f['allowed_seq']=True
    elif fault=='expired':f['expires_utc']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
    elif fault=='too_long':f['expires_utc']=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
    text='TASK13_RECOVERY_EXECUTE_V1 '+canonical(f).decode()
    if fault=='quote':text='Here is a quote: '+text
    if fault=='noncanonical':text+=' '
    write(text,'Please stop execution' if fault=='latest_changed' else None)
    with pytest.raises(ValueError):m.capture_recovery_permission(gate)

def bundle_module():
    assert importlib.util.find_spec('tools.canary.task13_continuation.recovery_bundle') is not None
    from tools.canary.task13_continuation import recovery_bundle
    return recovery_bundle

@pytest.fixture(scope='module')
def historical():
    if not os.environ.get('TASK13_HISTORICAL_ROOT'):pytest.skip('private retained prefix input')
    from tools.canary.task13_continuation.history import verify_historical_prefix
    return verify_historical_prefix(os.environ['TASK13_HISTORICAL_ROOT'])

def packet_entries(prefix):
    from tools.canary.task13_continuation.sources import build_stdin_delivery
    from tools.canary.task13_continuation.operations import thin_script
    # harmless decoded code is never invoked by these offline feasibility tests.
    entries={'wire.bin':b'QUJDRA=='}
    for name in ('guest','inventory','current','process_identity','clock_guest','prepare','workload','collect'):
        script=thin_script("@{status='SYNTHETIC_NOT_EXECUTED'}|ConvertTo-Json -Compress")
        b,p,pin=build_stdin_delivery(prefix,script,entries['wire.bin'] if name=='workload' else b'')
        entries['entry-'+name+'.ps1']=script.encode();entries['delivery-'+name+'.ps1']=b
        entries['packet-'+name+'.bin']=p;entries['packet-'+name+'-binding.json']=canonical(pin)
    return entries

def test_offline_sealed_packet_verification_passes_without_dispatch(historical):
    m=bundle_module();entries=packet_entries(historical)
    result=m.verify_packets(historical,entries)
    assert result['verified_packets']==8

@pytest.mark.parametrize('fault',['length','sha','body_length','source','param','truncated','trailing','bootstrap'])
def test_bad_packet_or_source_pin_fails_before_any_claim(historical,fault):
    m=bundle_module();entries=packet_entries(historical);name='guest';key='packet-'+name+'-binding.json'
    pin=parse_json(entries[key])
    if fault=='length':pin['wire_bytes']+=1
    elif fault=='sha':pin['wire_sha256']='0'*64
    elif fault=='body_length':pin['body_utf8_bytes']+=1
    elif fault=='source':pin['helper_sha256']='0'*64
    elif fault=='param':pin['parameter_hashes']['PlanSha256']='0'*64
    elif fault=='truncated':entries['packet-guest.bin']=entries['packet-guest.bin'][:-1]
    elif fault=='trailing':entries['packet-guest.bin']+=b'X'
    else:entries['delivery-guest.ps1']+=b' '
    entries[key]=canonical(pin)
    with pytest.raises(ValueError):m.verify_packets(historical,entries)

def test_historical_consumed_claims_are_expected_but_ordinary_recovery_stays_closed(historical):
    m=protocol();record=m.capture_history(historical)
    assert record['failure_phase']=='PREPARE_BUILDER_REFUSED_BEFORE_TRANSPORT'
    assert len(record['claims'])==3 and m.slot_state(historical,record)=='ABSENT'
    from tools.canary.task13_continuation.readonly_recovery import capture_readonly_recovery
    with pytest.raises(ValueError,match='before original seq04 dispatch'):capture_readonly_recovery(historical)

def loader_module():
    assert importlib.util.find_spec('tools.canary.task13_continuation.recovery_loader') is not None
    from tools.canary.task13_continuation import recovery_loader
    return recovery_loader

def test_execution_entry_rejects_implementation_request_without_creating_claims(session_case,tmp_path,monkeypatch):
    m=loader_module();gate,f,write,path=session_case;write('Implement only; no seq04')
    called=[]
    # Actual permission parser is real; expensive external dispatch must not occur.
    monkeypatch.setattr(m,'_execute_reviewed',lambda root:called.append(root))
    monkeypatch.setattr(sys,'argv',[str(tmp_path/'bootstrap.py'),'--execute-recovery-v1'])
    with pytest.raises(ValueError):m.bootstrap_entry(tmp_path)
    assert called==[]

def test_remaining_budget_is_checked_before_claim(owned):
    m=loader_module();p,h,r=owned
    import time
    from tools.canary.task13_continuation.readonly_gate import ReadOnlyWindow
    from tools.canary.task13_continuation.windows import observe_controller
    auth=ReadOnlyWindow(observe_controller())
    m.require_budget(auth,420)
    class NearDeadline:
        capsule=dict(auth.capsule,deadline_mono_ns=time.monotonic_ns()+10*10**9)
        def check(self):pass
    with pytest.raises(ValueError,match='budget'):m.require_budget(NearDeadline(),420)
    assert list((p.root/'continuation-v1-claims').iterdir())==[]

def test_changed_human_deadline_revokes_live_recovery_even_with_live_capsule():
    m=loader_module()
    class Base:
        capsule={}
        def check(self):pass
    auth=m.RecoveryAuthorization(Base(),dict(expires_utc=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()))
    with pytest.raises(ValueError,match='authorization expired'):auth.check()

def receipt_module():
    assert importlib.util.find_spec('tools.canary.task13_continuation.recovery_receipt') is not None
    from tools.canary.task13_continuation import recovery_receipt
    return recovery_receipt

def test_recovery_receipt_refuses_fabricated_legacy_dispatch_authority():
    m=receipt_module()
    with pytest.raises(ValueError,match='recovery evidence'):
        m.validate_recovery_evidence(SimpleNamespace(binding={}),{},dict(schema='task13_execution_evidence_v1',dispatch_claim={}))

@pytest.mark.skipif(os.name != 'nt',reason='native Windows controller identity')
def test_live_same_pid_birth_cannot_be_admitted_as_gone():
    m=loader_module()
    from tools.canary.task13_continuation.windows import observe_controller
    current=observe_controller()
    h=dict(prior_controller=current,prior_root={k:current[k] for k in ('pid','birth')},prior_supervisor={k:current[k] for k in ('pid','birth')})
    with pytest.raises(ValueError):m.fresh_previous(h)

@pytest.mark.skipif(os.name != 'nt',reason='native Windows parent identity')
def test_native_parent_liveness_checks_creation_time():
    m=loader_module()
    from tools.canary.task13_continuation.windows import observe_controller
    current=observe_controller();m._parent_live(current)
    with pytest.raises(ValueError):m._parent_live(dict(current,birth=current['birth']+1))

def test_self_declared_ready_gate_is_not_complete_native_admission(session_case):
    assert importlib.util.find_spec('tools.canary.task13_continuation.recovery_gate') is not None
    from tools.canary.task13_continuation import recovery_gate
    gate,_,_,_=session_case
    with pytest.raises((ValueError,KeyError)):recovery_gate.capture_verified_gate(gate)

@pytest.fixture
def feasible(historical,tmp_path):
    from tools.canary.task13_continuation.recovery_admission import MODULES,protocol_sources
    from tools.canary.task13_continuation.sources import seal_sources
    from tools.canary.task13_continuation.windows import system_core_paths
    entries=packet_entries(historical)
    base=Path(__file__).resolve().parents[2]/'tools/canary/task13_continuation'
    for n in MODULES:entries['tools/canary/task13_continuation/'+n]=(base/n).read_bytes()
    cid=str(uuid4());ssh=next(p for p in system_core_paths() if p.name=='ssh.exe')
    ops=dict(schema='task13_fixed_operations_v1',allowed_seq=4,allowed_step='compare-after-start',continuation_id=cid,
        guest_root='C:\\Task13Continuation-'+cid.replace('-',''),guest_ssh=[str(ssh),'StrictHostKeyChecking=yes','BatchMode=yes','fixture'],
        provider_argv=[str(ssh),'StrictHostKeyChecking=yes','BatchMode=yes','fixture'],management_argv=[sys._base_executable,'-c','pass'])
    entries['operations.json']=canonical(ops)
    c=dict(execution=seal_sources(entries),protocol_source_sha256=protocol_sources(entries),continuation_id=cid,
        runtime={sys._base_executable:{},str(ssh):{}})
    argv=[sys._base_executable,'-I','-S','-B','-X','pycache_prefix='+str(tmp_path/'no-pyc'),str(tmp_path/'bootstrap.py'),'--execute-recovery-v1-child']
    return entries,ops,c,argv

def test_complete_feasibility_accepts_short_bootstrap(historical,feasible):
    m=bundle_module();e,o,c,a=feasible
    plan=m.verify_feasibility(historical,c,e,o,a)
    assert all(v['utf16_units_with_nul']<8192 for v in plan.values())

@pytest.mark.parametrize('fault',['long_command','source_drift','open_dependency','changed_operation'])
def test_preclaim_feasibility_refuses_command_source_or_dependency_drift(historical,feasible,fault):
    m=bundle_module();e,o,c,a=feasible
    from tools.canary.task13_continuation.sources import seal_sources
    if fault=='long_command':
        o['management_argv'].append('x'*8192);e['operations.json']=canonical(o);c['execution']=seal_sources(e)
    elif fault=='source_drift':e['entry-guest.ps1']+=b'changed'
    elif fault=='open_dependency':del c['runtime'][o['management_argv'][0]]
    else:o['guest_ssh'][-1]='other-short-target'
    with pytest.raises(ValueError):m.verify_feasibility(historical,c,e,o,a)

def test_parallel_independent_native_processes_have_one_slot_winner(owned,tmp_path):
    m=protocol();p,h,r=owned;path=m.slot_path(p,h,'launch')
    worker=tmp_path/'native-contender.py'
    repository=str(Path(__file__).resolve().parents[2])
    worker.write_text("import sys\nfrom pathlib import Path\nsys.path.insert(0,"+repr(repository)+")\n"
        "from tools.canary.task13_continuation.recovery_admission import _commit_native\n"
        "try:_commit_native(Path(sys.argv[1]),Path(sys.argv[2]).read_bytes())\n"
        "except OSError:raise SystemExit(2)\n",encoding='utf-8')
    payload=tmp_path/'slot-payload.json';payload.write_bytes(canonical(r))
    procs=[subprocess.Popen([sys._base_executable,'-I','-S','-B',str(worker),str(path),str(payload)],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=0x08000000) for _ in range(4)]
    codes=[]
    for proc in procs:
        stdout,stderr=proc.communicate(timeout=15);assert not stdout and not stderr;codes.append(proc.returncode)
    assert codes.count(0)==1 and codes.count(2)==3
    assert parse_json(path.read_bytes())==r

@pytest.mark.parametrize('partial',[False,True])
def test_killed_native_writer_leaves_permanently_burned_slot(owned,tmp_path,partial):
    m=protocol();p,h,r=owned;path=m.slot_path(p,h,'launch');worker=tmp_path/'crash-writer.py'
    repository=str(Path(__file__).resolve().parents[2])
    worker.write_text("import sys,os\nfrom pathlib import Path\nsys.path.insert(0,"+repr(repository)+")\n"
        "from tools.canary.task13_continuation import windows\nfrom tools.canary.task13_continuation.storage import ProtectedStore\n"
        "path=Path(sys.argv[1])\nwith ProtectedStore(path.parent)._ancestry(),windows.retained(path,writable=True,create=True,protected=True) as h:\n"
        " windows.write_handle(h,b'');windows.flush_volume(path)\n"
        +( " windows.write_handle(h,b'{');windows.flush_volume(path)\n" if partial else '')+
        " os._exit(77)\n",encoding='utf-8')
    proc=subprocess.run([sys._base_executable,'-I','-S','-B',str(worker),str(path)],capture_output=True,timeout=15,creationflags=0x08000000)
    assert proc.returncode==77 and not proc.stdout and not proc.stderr
    assert m.slot_state(p,h)=='OCCUPIED_UNKNOWN'
    with pytest.raises(OSError):m._commit_native(path,canonical(r))
    assert path.read_bytes()==(b'{' if partial else b'')

@pytest.fixture
def supervisor_case(owned,tmp_path,monkeypatch):
    from contextlib import contextmanager
    from tools.canary.task13_continuation import recovery_supervisor as m
    from tools.canary.task13_continuation.readonly_gate import ReadOnlyWindow
    from tools.canary.task13_continuation.windows import observe_controller
    p,h,r=owned;s=ProtectedStore.create_root(tmp_path/'owned-execution');b=dict(root=s.root,store=s,prefix=p,history=h,
        closure=dict(continuation_id=r['continuation_id'],protocol_source_sha256=r['protocol_source_sha256'],implementation_sha=r['implementation_sha']),
        request=dict(expires_utc=r['expires_utc']),gate={},control=dict(root_interpreter=sys._base_executable,protocol_version=1),operations={},entries={},held=None)
    @contextmanager
    def reviewed(*args,**kwargs):
        from contextlib import ExitStack
        with ExitStack() as stack:b['held']=stack;yield b
    monkeypatch.setattr(m,'reviewed_recovery',reviewed)
    monkeypatch.setattr(m,'create_live',lambda *args:ReadOnlyWindow(observe_controller()))
    monkeypatch.setattr(m,'reconcile_recovery',lambda *args:{})
    monkeypatch.setattr(m,'prepared_observation',lambda *args:(object(),object(),{}))
    monkeypatch.setattr(m,'ready_guard',lambda *args,**kwargs:(lambda at:None))
    return m,b

def test_too_long_final_root_command_never_spawns_or_consumes_slot(supervisor_case,monkeypatch):
    m,b=supervisor_case;b['control']['root_interpreter']='x'*8192;spawned=[]
    monkeypatch.setattr(m.subprocess,'Popen',lambda *args,**kwargs:spawned.append(True))
    with pytest.raises(ValueError,match='COMMAND_LINE_TOO_LONG'):m.supervise(b['root'])
    assert not spawned and protocol().slot_state(b['prefix'],b['history'])=='ABSENT'


def test_v2_parent_reserves_child_startup_before_any_slot(supervisor_case,monkeypatch):
    m,b=supervisor_case
    import time
    b['control']['protocol_version']=2
    class StartupBudget:
        capsule=dict(deadline_mono_ns=time.monotonic_ns()+800*10**9,
            expires_utc=(datetime.now(timezone.utc)+timedelta(seconds=800)).isoformat())
        def check(self):pass
    monkeypatch.setattr(m,'create_live',lambda *args:StartupBudget())
    monkeypatch.setattr(m,'reconcile_recovery',lambda *args:pytest.fail('must refuse before preflight'))
    with pytest.raises(ValueError,match='budget'):m.supervise(b['root'])
    from tools.canary.task13_continuation.recovery_admission import slot_state
    assert slot_state(b['prefix'],b['history'])=='ABSENT'


@pytest.mark.parametrize('clock',['utc','monotonic'])
def test_v2_late_preflight_budget_refuses_before_launch_slot(supervisor_case,monkeypatch,clock):
    m,b=supervisor_case
    import time
    from tools.canary.task13_continuation.recovery_loader import require_budget
    b['control']['protocol_version']=2
    class StartupBudget:
        capsule=dict(deadline_mono_ns=time.monotonic_ns()+1200*10**9,
            expires_utc=(datetime.now(timezone.utc)+timedelta(seconds=1200)).isoformat())
        def check(self):pass
    auth=StartupBudget();spawned=[]
    monkeypatch.setattr(m,'create_live',lambda *args:auth)
    def preflight(*args):
        if clock=='utc':auth.capsule['expires_utc']=(datetime.now(timezone.utc)+timedelta(seconds=779)).isoformat()
        else:auth.capsule['deadline_mono_ns']=time.monotonic_ns()+779*10**9
        return {}
    monkeypatch.setattr(m,'prepared_observation',lambda *args:(object(),object(),preflight()))
    monkeypatch.setattr(m,'ready_guard',lambda context,a,state,seconds,**kwargs:require_budget(a,seconds))
    monkeypatch.setattr(m.subprocess,'Popen',lambda *args,**kwargs:spawned.append(True))
    with pytest.raises(ValueError,match='budget'):m.supervise(b['root'])
    assert not spawned and protocol().slot_state(b['prefix'],b['history'])=='ABSENT'

def test_preclaim_refusal_preserves_unused_slot(supervisor_case,monkeypatch):
    m,b=supervisor_case
    def refuse(*args):raise ValueError('owned synthetic stale state refusal')
    monkeypatch.setattr(m,'ready_guard',refuse)
    with pytest.raises(ValueError,match='stale state'):m.supervise(b['root'])
    assert protocol().slot_state(b['prefix'],b['history'])=='ABSENT'


@pytest.mark.parametrize('clock',['utc','monotonic'])
@pytest.mark.parametrize('phase',['before-slot','after-slot'])
def test_v2_budget_is_checked_after_expensive_guard_before_commit_and_spawn(supervisor_case,monkeypatch,clock,phase):
    m,b=supervisor_case
    import time
    b['control']['protocol_version']=2
    class StartupBudget:
        capsule=dict(deadline_mono_ns=time.monotonic_ns()+1200*10**9,
            expires_utc=(datetime.now(timezone.utc)+timedelta(seconds=1200)).isoformat())
        def check(self):pass
    auth=StartupBudget();calls=[];spawned=[]
    monkeypatch.setattr(m,'create_live',lambda *args:auth)
    def expensive_guard(*args,**kwargs):
        calls.append(True)
        if len(calls)==(1 if phase=='before-slot' else 2):
            if clock=='utc':auth.capsule['expires_utc']=(datetime.now(timezone.utc)+timedelta(seconds=779)).isoformat()
            else:auth.capsule['deadline_mono_ns']=time.monotonic_ns()+779*10**9
        return lambda at:None
    monkeypatch.setattr(m,'ready_guard',expensive_guard)
    monkeypatch.setattr(m.subprocess,'Popen',lambda *args,**kwargs:spawned.append(True))
    with pytest.raises(ValueError,match='budget'):m.supervise(b['root'])
    assert not spawned
    assert protocol().slot_state(b['prefix'],b['history'])==('ABSENT' if phase=='before-slot' else 'LAUNCH_COMMITTED')

def test_spawn_failure_permanently_consumes_launch_without_retry(supervisor_case,monkeypatch):
    m,b=supervisor_case;calls=[]
    def failed(*args,**kwargs):
        assert protocol().slot_state(b['prefix'],b['history'])=='LAUNCH_COMMITTED'
        calls.append(True);raise OSError('owned synthetic process creation failure')
    monkeypatch.setattr(m.subprocess,'Popen',failed)
    with pytest.raises(OSError):m.supervise(b['root'])
    assert parse_json(b['store'].read('recovery-supervisor-unknown.json'))['retry_allowed'] is False
    with pytest.raises(ValueError,match='already occupied'):m.supervise(b['root'])
    assert calls==[True]


@pytest.mark.parametrize('phase',['before-slot','after-slot'])
def test_v2_stale_final_clock_refuses_without_spawn_and_preserves_slot_transition(supervisor_case,monkeypatch,phase):
    m,b=supervisor_case;b['control']['protocol_version']=2;calls=[]
    def guarded(*args,**kwargs):
        calls.append(True)
        if len(calls)==(1 if phase=='before-slot' else 2):raise ValueError('owned stale dispatch clock')
        return lambda at:None
    monkeypatch.setattr(m,'ready_guard',guarded)
    monkeypatch.setattr(m.subprocess,'Popen',lambda *a,**k:pytest.fail('stale clocks cannot spawn'))
    with pytest.raises(ValueError,match='stale dispatch clock'):m.supervise(b['root'])
    assert protocol().slot_state(b['prefix'],b['history'])==('ABSENT' if phase=='before-slot' else 'LAUNCH_COMMITTED')
    assert (b['root']/'supervisor-transports').is_dir()

@pytest.mark.parametrize('fault',['registration','communicate'])
def test_postspawn_failure_kills_reaps_and_records_native_child_exit(supervisor_case,monkeypatch,fault):
    m,b=supervisor_case;calls=[]
    class Child:
        pid=456;_handle=789;returncode=None
        def kill(self):calls.append('kill');self.returncode=9
        def communicate(self,timeout):
            calls.append('communicate')
            if self.returncode is None:raise OSError('owned communication failure')
            return b'',b''
    monkeypatch.setattr(m.subprocess,'Popen',lambda *a,**k:Child())
    monkeypatch.setattr(m.windows,'process_birth',lambda h:123456)
    monkeypatch.setattr(m.windows,'retained_process_exit',lambda h:dict(birth=123456,exit_code=9,wait_result=0))
    original=b['store'].create
    def write(name,raw):
        result=original(name,raw)
        if fault=='registration' and name=='recovery-child.json':raise OSError('flush failed after visible registration')
        return result
    monkeypatch.setattr(b['store'],'create',write)
    with pytest.raises(OSError):m.supervise(b['root'])
    assert calls[-2:]==['kill','communicate']
    settlement=parse_json(b['store'].read('recovery-child-failure-settlement.json'))
    assert settlement['wait_result']==0 and settlement['birth']==123456 and settlement['pid']==456
    assert protocol().slot_state(b['prefix'],b['history'])=='LAUNCH_COMMITTED'


def test_readonly_communication_failure_always_kills_and_reaps(supervisor_case,monkeypatch):
    from tools.canary.task13_continuation import recovery_gate as g,recovery_loader as loader
    m,b=supervisor_case;calls=[]
    monkeypatch.setattr(loader,'reviewed_recovery',m.reviewed_recovery)
    class Child:
        pid=456;_handle=789;returncode=None
        def kill(self):calls.append('kill');self.returncode=9
        def communicate(self,timeout):
            calls.append('communicate')
            if self.returncode is None:raise OSError('owned read-only communication failure')
            return b'',b''
    monkeypatch.setattr(g.subprocess,'Popen',lambda *a,**k:Child())
    monkeypatch.setattr(g.windows,'process_birth',lambda h:123456)
    monkeypatch.setattr(g.windows,'retained_process_exit',lambda h:dict(birth=123456,exit_code=9,wait_result=0))
    with pytest.raises(OSError):g.run_observation(b['root'])
    assert calls[-2:]==['kill','communicate']
    assert parse_json(b['store'].read('read-only-child-failure-settlement.json'))['wait_result']==0
    assert protocol().slot_state(b['prefix'],b['history'])=='ABSENT'


def test_historical_executable_spelling_binds_exact_closed_runtime_key(historical):
    m=bundle_module();accepted=Path.home()/'.codex/task-evidence/task13-command-transport-review-20261011-c'
    ops=parse_json((accepted/'operations.json').read_bytes());runtime=parse_json((accepted/'closure.json').read_bytes())['runtime']
    assert ops['management_argv'][0] not in runtime and str(Path(ops['management_argv'][0])) in runtime
    original=copy.deepcopy(ops);m.bind_closed_executables(ops,runtime)
    for name in ('guest_ssh','provider_argv','management_argv'):
        assert ops[name][0] in runtime and Path(ops[name][0])==Path(original[name][0])
        assert ops[name][1:]==original[name][1:]
    with pytest.raises(ValueError):m.bind_closed_executables(original,{})

@pytest.mark.parametrize('ending',['\n','\r\n'])
def test_one_ui_line_ending_keeps_actual_operator_record_unchanged(session_case,ending):
    m=permission_module();gate,f,write,path=session_case
    text=m.PREFIX+canonical(f).decode()+ending;write(text);before=path.read_bytes()
    grant=m.capture_recovery_permission(gate)
    assert grant['record']['payload']['content'][0]['text']==text
    assert path.read_bytes()==before
    m.verify_recovery_permission(grant,gate)
    write(text[:-len(ending)])
    with pytest.raises(ValueError,match='changed or replayed'):m.verify_recovery_permission(grant,gate)

@pytest.mark.parametrize('ending',['\n\n','\r',' \n','\t\n','\r\n\r\n'])
def test_noncanonical_suffix_is_not_a_ui_line_ending(session_case,ending):
    m=permission_module();gate,f,write,path=session_case;write(m.PREFIX+canonical(f).decode()+ending)
    with pytest.raises(ValueError):m.capture_recovery_permission(gate)

@pytest.mark.parametrize('ending',['\n','\r\n'])
def test_ui_line_ending_cannot_revive_expired_authorization(session_case,ending):
    m=permission_module();gate,f,write,path=session_case
    f['expires_utc']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
    write(m.PREFIX+canonical(f).decode()+ending)
    with pytest.raises(ValueError):m.capture_recovery_permission(gate)
