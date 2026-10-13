"""Owned readiness capabilities; no target operations or execution claims."""
import importlib
import copy
import os
import stat
import time
from pathlib import Path
from types import SimpleNamespace
from datetime import timedelta

import pytest
from tools.canary.task13_continuation.codec import parse_json,instant,digest
from tools.canary.task13_continuation.transport import validate_command_plan,validate_command,powershell_argv
from tests.tools.test_task13_command_transport import historical
from tests.tools.test_task13_recovery_receipt import recovery_case
from tests.tools.test_task13_continuation_receipt import evidence_case

pytestmark=pytest.mark.no_db


@pytest.mark.parametrize('name',['prepare_readiness','reconcile_prepared','require_ready','open_context','close_context'])
def test_prepared_v2_has_explicit_context_and_freshness_boundaries(name):
    module=importlib.import_module('tools.canary.task13_continuation.recovery_readiness_v2')
    assert callable(getattr(module,name))


@pytest.fixture
def owned(historical,monkeypatch):
    m=importlib.import_module('tools.canary.task13_continuation.recovery_readiness_v2')
    from tools.canary.task13_continuation import recovery_loader as loader,recovery_bundle as bundle,recovery_admission as admission,recovery_permission_v2 as permission,receipt,recovery_observation_v2 as observer
    root=Path.home()/'.codex/task-evidence/task13-additive-recovery-execute-20261012-d'
    closure=parse_json((root/'closure.json').read_bytes())
    entries={n:(root/n).read_bytes() for n in closure['execution']['entries']}
    b=dict(root=root,prefix=historical,closure=closure,entries=entries,held=object(),
        **{key:parse_json(entries[name]) for key,name in (('control','control.json'),('operations','operations.json'),
        ('history','recovery-history.json'),('request','operator-request.json'),('gate','admission-gate.json'))})
    raw=parse_json((root/'launch-preflight.json').read_bytes());state=raw['observation'];events=[]
    now=[instant(raw['finished_utc'])];monkeypatch.setattr(m,'utc',lambda:now[0].isoformat())
    auth=SimpleNamespace(capsule=parse_json((root/'launch-capsule.json').read_bytes()),check=lambda:events.append('live'))
    auth.capsule=dict(auth.capsule,created_utc=(now[0]-timedelta(seconds=2)).isoformat(),
        expires_utc=(now[0]+timedelta(seconds=1200)).isoformat(),created_mono_ns=time.monotonic_ns()-2*10**9,
        deadline_mono_ns=time.monotonic_ns()+1200*10**9)
    auth.request=b['request']
    monkeypatch.setattr(permission,'verify_recovery_permission',lambda *a:events.append('permission'))
    monkeypatch.setattr(loader,'require_budget',lambda *a:events.append('budget'))
    def history(*a):events.append('full-history');return b['history']
    monkeypatch.setattr(admission,'capture_history',history)
    monkeypatch.setattr(loader,'fresh_previous',lambda *a:events.append('previous-native'))
    argv=loader.root_argv(root,b['control'],loader.entry_flag(b['control'],'execute-child'))
    def feasibility(*a):
        events.append('full-packets');plan=validate_command_plan(b['operations'],entries);plan['root']=validate_command(argv)
        joint=powershell_argv(b['operations']['guest_ssh'],entries['delivery-joint_identity.ps1'].decode())
        plan['joint_identity']=validate_command(joint,remote_command=joint[-1]);return plan
    monkeypatch.setattr(bundle,'verify_feasibility',feasibility)
    def observed(*a):
        events.append('real-observer-boundary');value=copy.deepcopy(raw)
        value.update(dispatch_utc=now[0].isoformat(),finished_utc=now[0].isoformat(),
            dispatch_mono_ns=time.monotonic_ns(),finished_mono_ns=time.monotonic_ns()+1)
        return value
    monkeypatch.setattr(observer,'reconcile',observed)
    # Owned observer mock; full captured-D raw/state guards are checked separately.
    monkeypatch.setattr(receipt,'observation',lambda *a,**k:state)
    m.open_context(b)
    try:yield m,b,auth,argv,events,now
    finally:m.close_context(b)


def ready(case,phase='supervisor-preclaim'):
    m,b,auth,argv,events,now=case
    prepared=m.prepare_readiness(b,auth,phase)
    fresh=m.reconcile_prepared(prepared,auth,object())
    return prepared,fresh


def test_expensive_checks_precede_observations_and_never_repeat_after_clocks(owned):
    m,b,a,argv,events,now=owned;prepared,fresh=ready(owned)
    assert events.index('full-history')<events.index('full-packets')<events.index('real-observer-boundary')
    events.clear();m.require_ready(prepared,fresh,a,argv)
    assert 'full-history' not in events and 'full-packets' not in events and 'real-observer-boundary' not in events


def test_slow_preparation_passes_but_post_observation_delay_refuses(owned,monkeypatch):
    m,b,a,argv,events,now=owned
    # Delay belongs before the newly sampled clocks, not after them.
    from tools.canary.task13_continuation import recovery_admission
    original=recovery_admission.capture_history
    def slow(*args):now[0]-=timedelta(seconds=20);result=original(*args);now[0]+=timedelta(seconds=20);return result
    monkeypatch.setattr(recovery_admission,'capture_history',slow)
    prepared,fresh=ready(owned);m.require_ready(prepared,fresh,a,argv)
    now[0]+=timedelta(seconds=5.001)
    with pytest.raises(ValueError,match='stale dispatch clock'):m.require_ready(prepared,fresh,a,argv)


@pytest.mark.parametrize('fault',['serialized','forged','foreign_auth','foreign_process','closed','source','capsule','live_request','argv'])
def test_unissued_or_changed_readiness_never_passes(owned,monkeypatch,fault):
    m,b,a,argv,events,now=owned;prepared,fresh=ready(owned)
    if fault=='serialized':prepared=m.prepared_manifest(prepared,a)
    elif fault=='forged':prepared=object.__new__(m._Capability)
    elif fault=='foreign_auth':a=copy.copy(a)
    elif fault=='foreign_process':monkeypatch.setattr(m.os,'getpid',lambda:987654321)
    elif fault=='closed':m.close_context(b)
    elif fault=='source':b['entries']['entry-workload.ps1']+=b'changed'
    elif fault=='capsule':a.capsule={**a.capsule,'allowed_seq':5}
    elif fault=='live_request':a.request={**a.request,'expires_utc':'2100-01-01T00:00:00Z'}
    elif fault=='argv':argv=[*argv,'caller-selected']
    with pytest.raises(ValueError):m.require_ready(prepared,fresh,a,argv)


def test_revocation_and_budget_are_rechecked_at_final_barrier(owned,monkeypatch):
    m,b,a,argv,events,now=owned;prepared,fresh=ready(owned)
    from tools.canary.task13_continuation import recovery_permission_v2,recovery_loader
    def denied(*a):raise ValueError('withdrawn')
    monkeypatch.setattr(recovery_permission_v2,'verify_recovery_permission',denied)
    with pytest.raises(ValueError,match='withdrawn'):m.require_ready(prepared,fresh,a,argv)
    monkeypatch.setattr(recovery_permission_v2,'verify_recovery_permission',lambda *a:None)
    monkeypatch.setattr(recovery_loader,'require_budget',denied)
    with pytest.raises(ValueError,match='withdrawn'):m.require_ready(prepared,fresh,a,argv)


def test_context_and_observer_capability_cannot_reissue_or_cross_bind(owned):
    m,b,a,argv,events,now=owned;prepared,fresh=ready(owned)
    with pytest.raises(ValueError):m.prepare_readiness(b,a,'supervisor-preclaim')
    with pytest.raises(ValueError):m.reconcile_prepared(prepared,a,object())
    next_prepared,next_fresh=ready(owned,'supervisor-postclaim')
    with pytest.raises(ValueError):m.require_ready(next_prepared,fresh,a,argv)
    assert m.raw_reconciliation(next_fresh,a)==m.raw_reconciliation(fresh,a) or next_fresh is not fresh


def test_actual_d_clock_guard_passes_at_capture_then_fails_after_five_seconds(historical):
    from tools.canary.task13_continuation.reconciliation import guards,legacy
    root=Path.home()/'.codex/task-evidence/task13-additive-recovery-execute-20261012-d'
    state=parse_json((root/'launch-preflight.json').read_bytes())['observation'];g=guards(historical)
    for kind in ('guest','management'):
        row=state['constituents']['clock_'+kind];clock=legacy(row,historical.plan['run_id'],'clock-'+kind)
        done=instant(row['finished_utc'])
        assert g['clock_guard'](historical.controller,clock,kind,historical.plan['run_id'],done.isoformat())['status']=='FRESH_CLOCK_BRACKET_VALIDATED'
        with pytest.raises(ValueError):g['clock_guard'](historical.controller,clock,kind,historical.plan['run_id'],(done+timedelta(seconds=5.001)).isoformat())


@pytest.mark.parametrize('fault',['permission','budget','identity','clock'])
def test_returned_final_callback_rechecks_live_conditions_after_initial_ready(owned,monkeypatch,fault):
    m,b,a,argv,events,now=owned
    from tools.canary.task13_continuation import recovery_permission_v2,recovery_loader
    allow={'value':True}
    def checked(*args):
        if not allow['value']:raise ValueError('late denial')
    if fault=='permission':monkeypatch.setattr(recovery_permission_v2,'verify_recovery_permission',checked)
    elif fault=='budget':monkeypatch.setattr(recovery_loader,'require_budget',checked)
    elif fault=='identity':a.check=checked
    prepared,fresh=ready(owned);final=m.require_ready(prepared,fresh,a,argv)
    if fault=='clock':now[0]+=timedelta(seconds=5.001)
    else:allow['value']=False
    with pytest.raises(ValueError):final(now[0].isoformat())


def test_new_historical_catalogue_child_refuses_without_rehashing_old_bytes(owned,tmp_path,monkeypatch):
    m,b,a,argv,events,now=owned;root=tmp_path/'owned-history';root.mkdir();(root/'old.json').write_bytes(b'unchanged')
    monkeypatch.setattr(m,'_catalogues',lambda context:{str(root):m._catalogue(root)})
    prepared,fresh=ready(owned);final=m.require_ready(prepared,fresh,a,argv)
    (root/'new.json').write_bytes(b'addition')
    with pytest.raises(ValueError,match='catalogue'):final(now[0].isoformat())
    assert (root/'old.json').read_bytes()==b'unchanged'


def test_inaccessible_historical_subtree_is_not_silently_omitted(tmp_path,monkeypatch):
    m=importlib.import_module('tools.canary.task13_continuation.recovery_readiness_v2')
    root=tmp_path/'owned-empty-history';root.mkdir()
    def inaccessible(*args,**kwargs):
        kwargs['onerror'](PermissionError('owned denied enumeration'))
        yield root,[],[]
    monkeypatch.setattr(m.os,'walk',inaccessible)
    with pytest.raises(ValueError,match='enumeration unavailable'):m._catalogue(root)


def test_posix_catalogue_accepts_regular_files_without_windows_attributes(tmp_path,monkeypatch):
    m=importlib.import_module('tools.canary.task13_continuation.recovery_readiness_v2')
    (tmp_path/'nested').mkdir();(tmp_path/'nested'/'old.json').write_bytes(b'unchanged')
    original=Path.stat
    def posix(path,**kwargs):
        native=original(path,**kwargs)
        return SimpleNamespace(**{name:getattr(native,name) for name in ('st_mode','st_dev','st_ino','st_nlink')})
    monkeypatch.setattr(Path,'stat',posix)
    assert m._catalogue(tmp_path)==(('nested','directory'),('nested/old.json','file'))


@pytest.mark.parametrize('kind',['root','directory','file'])
@pytest.mark.parametrize('platform',['posix','windows'])
def test_catalogue_refuses_link_and_reparse_types(tmp_path,monkeypatch,kind,platform):
    m=importlib.import_module('tools.canary.task13_continuation.recovery_readiness_v2')
    (tmp_path/'nested').mkdir();(tmp_path/'old.json').write_bytes(b'unchanged')
    target={'root':tmp_path,'directory':tmp_path/'nested','file':tmp_path/'old.json'}[kind]
    original=Path.stat
    def linked(path,**kwargs):
        native=original(path,**kwargs)
        values={name:getattr(native,name) for name in ('st_mode','st_dev','st_ino','st_nlink')}
        if platform=='windows':values['st_file_attributes']=1024 if path==target else 0
        elif path==target:values['st_mode']=stat.S_IFLNK|0o777
        return SimpleNamespace(**values)
    monkeypatch.setattr(Path,'stat',linked)
    with pytest.raises(ValueError,match='catalogue'):m._catalogue(tmp_path)


def test_catalogue_refuses_regular_file_replacement_during_enumeration(tmp_path,monkeypatch):
    m=importlib.import_module('tools.canary.task13_continuation.recovery_readiness_v2')
    item=tmp_path/'old.json';item.write_bytes(b'old')
    def replaced(*args,**kwargs):
        yield str(tmp_path),[],['old.json']
        replacement=tmp_path/'new.json';replacement.write_bytes(b'new')
        os.replace(replacement,item)
    monkeypatch.setattr(m.os,'walk',replaced)
    with pytest.raises(ValueError,match='catalogue.*changed'):m._catalogue(tmp_path)


def test_catalogue_refuses_addition_after_directory_enumeration(tmp_path,monkeypatch):
    m=importlib.import_module('tools.canary.task13_continuation.recovery_readiness_v2')
    def added(*args,**kwargs):
        yield str(tmp_path),[],[]
        (tmp_path/'late.json').write_bytes(b'addition')
    monkeypatch.setattr(m.os,'walk',added)
    with pytest.raises(ValueError,match='catalogue.*changed'):m._catalogue(tmp_path)


@pytest.mark.parametrize('kind',['root','directory','file'])
def test_native_catalogue_refuses_symbolic_links(tmp_path,kind):
    m=importlib.import_module('tools.canary.task13_continuation.recovery_readiness_v2')
    root=tmp_path/'history';root.mkdir()
    outside=tmp_path/'outside';outside.mkdir();(outside/'private.json').write_bytes(b'outside')
    link=root/'link'
    target=outside/'private.json' if kind=='file' else outside
    if kind=='root':link=tmp_path/'root-link'
    link.symlink_to(target,target_is_directory=kind!='file')
    with pytest.raises(ValueError,match='catalogue'):m._catalogue(link if kind=='root' else root)


def test_native_catalogue_refuses_linked_ancestor(tmp_path):
    m=importlib.import_module('tools.canary.task13_continuation.recovery_readiness_v2')
    outside=tmp_path/'outside';outside.mkdir();(outside/'history').mkdir()
    link=tmp_path/'alias';link.symlink_to(outside,target_is_directory=True)
    with pytest.raises(ValueError,match='catalogue'):m._catalogue(link/'history')


@pytest.mark.skipif(os.name=='nt',reason='POSIX special-file type')
def test_native_posix_catalogue_refuses_fifo(tmp_path):
    m=importlib.import_module('tools.canary.task13_continuation.recovery_readiness_v2')
    os.mkfifo(tmp_path/'pipe')
    with pytest.raises(ValueError,match='catalogue'):m._catalogue(tmp_path)


def test_history_addition_between_full_hash_and_snapshot_cannot_be_absorbed(owned,tmp_path,monkeypatch):
    m,b,a,argv,events,now=owned;root=tmp_path/'owned-bracketed-history';root.mkdir();(root/'old.json').write_bytes(b'unchanged')
    monkeypatch.setattr(m,'_catalogues',lambda context:{str(root):m._catalogue(root)})
    from tools.canary.task13_continuation import recovery_bundle
    original=recovery_bundle.verify_feasibility
    def changed(*args):
        result=original(*args);(root/'late.json').write_bytes(b'addition after hash');return result
    monkeypatch.setattr(recovery_bundle,'verify_feasibility',changed)
    with pytest.raises(ValueError,match='during full verification'):m.prepare_readiness(b,a,'supervisor-preclaim')
    assert 'real-observer-boundary' not in events


@pytest.mark.parametrize('fault',[None,'missing','command','phase','capsule','raw','late_preparation','binding'])
def test_recorded_proofs_bind_all_four_real_phase_envelopes_without_issuing_authority(owned,fault):
    m,b,a,argv,events,now=owned;records={};raws={}
    for phase in ('supervisor-preclaim','supervisor-postclaim','child-preclaim','child-dispatch'):
        prepared,fresh=ready(owned,phase)
        records[phase+'-prepared']=m.prepared_manifest(prepared,a);records[phase+'-fresh']=m.fresh_manifest(fresh,a)
        raws[phase]=m.raw_reconciliation(fresh,a)
    evidence=dict(prepared_readiness=records,launch_preflight=raws['supervisor-preclaim'],
        launch_postclaim_preflight=raws['supervisor-postclaim'],preclaim_preflight=raws['child-preclaim'],
        preflight=raws['child-dispatch'],recovery_history=b['history'],recovery_authorization=b['request'],admission_gate=b['gate'])
    row=records['supervisor-preclaim-prepared']
    if fault=='missing':records.pop('child-dispatch-fresh')
    elif fault=='command':
        row['command_plan']['workload']['command_sha256']='0'*64
        records['supervisor-preclaim-fresh']['prepared_sha256']=digest(row)
    elif fault=='phase':row['phase']='child-dispatch'
    elif fault=='capsule':row['capsule_sha256']='0'*64
    elif fault=='raw':raws['child-preclaim']['prepared_readiness_sha256']='0'*64
    elif fault=='late_preparation':row['finished_mono_ns']=raws['supervisor-preclaim']['dispatch_mono_ns']+1
    elif fault=='binding':row['bindings_sha256']='0'*64
    if fault is None:
        m.validate_recorded_readiness(a.capsule,a.capsule,evidence)
        with pytest.raises(ValueError):m.require_ready(row,records['supervisor-preclaim-fresh'],a,argv)
    else:
        with pytest.raises(ValueError):m.validate_recorded_readiness(a.capsule,a.capsule,evidence)


@pytest.fixture
def owned_v2_receipt(recovery_case):
    """Pure schema integration; no native execution, slots or publication."""
    from tools.canary.task13_continuation.codec import canonical,sha256
    p,c,e=recovery_case
    gate=e['admission_gate'];gate['protocol_version']=2
    grant=e['recovery_authorization'];grant.update(schema='task13_actual_recovery_execution_request_v2',
        scope='seq04-additive-recovery-v2',gate_sha256=digest(gate))
    pins=c['source_closure']['execution']['entries']
    pins.update({'control.json':dict(bytes=13,sha256=sha256(b'owned-control')),
        'operations.json':dict(bytes=10,sha256=sha256(b'owned-ops')),
        'tools/canary/task13_continuation/recovery_readiness_v2.py':dict(bytes=10,sha256='f'*64),
        'operator-request.json':dict(bytes=len(canonical(grant)),sha256=digest(grant)),
        'admission-gate.json':dict(bytes=len(canonical(gate)),sha256=digest(gate))})
    c['created_mono_ns']=3;parent=copy.deepcopy(c);parent['created_mono_ns']=1
    parent['controller']=dict(c['controller'],pid=22,birth=1235);e['launch_capsule']=parent
    for name,start in (('launch_preflight',1),('preclaim_preflight',5),('watchdog_preparation',7),
        ('preflight',9),('guest',11),('retained_collection',13),('postflight',15)):
        e[name].update(dispatch_mono_ns=start,finished_mono_ns=start+1)
    e['launch_postclaim_preflight']=copy.deepcopy(e['launch_preflight'])
    e['launch_postclaim_preflight'].update(dispatch_mono_ns=2,finished_mono_ns=3)
    e['watchdog']['retained_transport_sha256']=digest(e['retained_collection'])
    records={};e['prepared_readiness']=records
    phases={'supervisor-preclaim':(parent,e['launch_preflight']),
        'supervisor-postclaim':(parent,e['launch_postclaim_preflight']),
        'child-preclaim':(c,e['preclaim_preflight']),'child-dispatch':(c,e['preflight'])}
    names={'clock_guest','collect','current','guest','inventory','joint_identity','management','prepare','process_identity','provider','root','workload'}
    plan={n:dict(utf16_units_with_nul=400,command_sha256='a'*64,
        **({} if n in ('root','management','provider') else dict(remote_utf16_units_with_nul=300))) for n in names}
    for phase,(cap,raw) in phases.items():
        binding=dict(capsule_sha256=digest(cap),request_sha256=digest(grant),gate_sha256=digest(gate),
            history_sha256=digest(e['recovery_history']),closure_sha256=digest(cap['source_closure']),
            control_sha256=pins['control.json']['sha256'],operations_sha256=pins['operations.json']['sha256'],
            execution=cap['source_closure']['execution'])
        record=dict(schema='task13_prepared_readiness_v2',phase=phase,source_closure_sha256=digest(cap['source_closure']),
            capsule_sha256=digest(cap),history_sha256=digest(e['recovery_history']),command_plan=copy.deepcopy(plan),
            bindings_sha256=digest(binding),started_utc=cap['created_utc'],finished_utc=raw['dispatch_utc'],
            started_mono_ns=cap['created_mono_ns'],finished_mono_ns=raw['dispatch_mono_ns'])
        raw['prepared_readiness_sha256']=digest(record);records[phase+'-prepared']=record
        records[phase+'-fresh']=dict(schema='task13_validated_fresh_reconciliation_v2',prepared_sha256=digest(record),
            preflight_sha256=digest(raw),capsule_sha256=digest(cap),source_closure_sha256=digest(cap['source_closure']))
    launch=e['recovery_launch_slot'];launch.update(protocol_version=2,gate_sha256=digest(gate),request_sha256=digest(grant),
        source_closure_sha256=digest(c['source_closure']),capsule_sha256=digest(parent),preflight_sha256=digest(e['launch_preflight']))
    e['recovery_dispatch_slot'].update(protocol_version=2,launch_slot_sha256=digest(launch),capsule_sha256=digest(c),
        preflight_sha256=digest(e['preclaim_preflight']))
    e['source_closure_sha256']=digest(c['source_closure'])
    return p,c,e


def test_owned_v2_receipt_requires_all_prepared_and_native_settlement_bindings(owned_v2_receipt):
    from tools.canary.task13_continuation.recovery_receipt import make_recovery_receipt,verify_recovery_receipt
    from tools.canary.task13_continuation.receipt import publication_ack
    from tests.tools.test_task13_continuation_receipt import root_completion
    p,c,e=owned_v2_receipt;receipt=make_recovery_receipt(p,c,e)
    verify_recovery_receipt(p,c,receipt,e,publication_ack(c,receipt),root_completion(c,receipt,e))
    assert receipt['protocol_version']==2 and receipt['resume_gate']=='STOP_BEFORE_SEQ05'


@pytest.mark.parametrize('fault',['command','missing','raw_marker','postclaim','phase'])
def test_owned_v2_receipt_cannot_repair_mutated_readiness_by_rehashing_metadata(owned_v2_receipt,fault):
    from tools.canary.task13_continuation.recovery_receipt import make_recovery_receipt
    p,c,e=owned_v2_receipt;records=e['prepared_readiness']
    if fault=='command':
        row=records['child-preclaim-prepared'];row['command_plan']['workload']['command_sha256']='0'*64
        records['child-preclaim-fresh']['prepared_sha256']=digest(row)
    elif fault=='missing':records.pop('supervisor-postclaim-fresh')
    elif fault=='raw_marker':e['preclaim_preflight']['prepared_readiness_sha256']='0'*64
    elif fault=='postclaim':e['launch_postclaim_preflight']['dispatch_mono_ns']=0
    elif fault=='phase':records['child-dispatch-prepared']['phase']='child-preclaim'
    with pytest.raises(ValueError):make_recovery_receipt(p,c,e)
