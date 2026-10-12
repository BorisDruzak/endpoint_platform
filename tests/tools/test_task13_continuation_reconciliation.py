"""Synthetic current-time projections of retained fixtures; never VM evidence."""
import copy
import os
import time
from datetime import datetime,timedelta,timezone

import pytest
from tools.canary.task13_continuation.codec import canonical,digest,parse_json
from tools.canary.task13_continuation.history import verify_historical_prefix
from tools.canary.task13_continuation.reconciliation import validate_state
from tools.canary.task13_continuation.transport import envelope
from tools.canary.task13_continuation.process_identity import reference_registry,SAMPLE_KEYS

pytestmark = [pytest.mark.no_db,pytest.mark.skipif(not os.environ.get("TASK13_HISTORICAL_ROOT"),reason="private retained fixture")]


@pytest.fixture(scope="module")
def prefix():
    return verify_historical_prefix(os.environ["TASK13_HISTORICAL_ROOT"])


@pytest.fixture
def state_case(prefix):
    now = datetime.now(timezone.utc)
    utc = now.isoformat()
    mono = time.monotonic_ns()
    objects = [parse_json(path.read_bytes()) for path in (prefix.root/"zero-owner-recovery-records").glob("*-accepted-observation.json")]
    provider = copy.deepcopy(next(v["observation"] for v in objects if v["tag"].startswith("provider-zero-owners")))
    provider["provider_utc"] = utc
    provider["latest_instance"]["last_seen_at"] = utc
    for row in provider["sessions"]:
        row["last_seen_at"],row["expires_at"] = utc,(now+timedelta(seconds=1200)).isoformat()
    current = copy.deepcopy(next(v["observation"] for v in objects if v["tag"].startswith("fresh-current-quiescence")))
    current["utc"] = now.strftime("%Y-%m-%dT%H:%M:%S.")+f"{now.microsecond:06d}0Z"
    inventory = copy.deepcopy(next(v["observation"] for v in objects if v["tag"].startswith("recovery-leaves")))
    generation = prefix.receipts[0]["initial_vm_generation"]
    management = {"status":"CONTINUATION_MANAGEMENT_OBSERVED","run_id":prefix.plan["run_id"],"active_tasks":[],
                  "state":{"status":"status: running","config":{"vmgenid":generation},
                           "lvs":prefix.receipts[3]["postcondition"]["lvm_after"]},
                  "metadata":prefix.snapshot["metadata"],"saved_config_normalized":prefix.receipts[2]["saved_config"],
                  "volumes":prefix.snapshot["volumes"]}
    guest = {"status":"QUIESCENT_NATIVE81_OBSERVED","run_id":prefix.plan["run_id"],
             "vm_uuid":prefix.plan["vm_uuid"],"device_id":prefix.plan["device_id"],"network_matches":1,
             "plan_sha256":prefix.binding["original_plan_sha256"],"service_state":"Running","current":"versions/3.2.81",
             "update_owners":[],"msi_in_progress":False,"msiexec":[],"baseline_sha256":prefix.binding["baseline_sha256"],"marker_absent":True}
    values = {"management":management,"provider":provider,"current":current,"inventory":inventory,"guest":guest}
    registry=reference_registry(prefix)
    identity_rows=[]
    for ref in registry['refs']:
        sample={k:None for k in SAMPLE_KEYS}
        sample.update(status='ABSENT',pid=ref['pid'],native_error=87,cim_count=0)
        identity_rows.append(dict(pid=ref['pid'],first=sample,second=dict(sample),retained_first_not_exited=None,error_type=None))
    values['process_identity']=dict(schema='task13_native_process_identity_v1',status='READ_ONLY_PROCESS_IDENTITY_OBSERVATION',
        run_id=registry['run_id'],vm_uuid=registry['vm_uuid'],registry_sha256=digest(registry),utc=current['utc'],rows=identity_rows,parent_observations=[])
    for kind in ("guest","management"):
        values["clock_"+kind] = {"status":"CLOCK_OBSERVED","kind":kind,"run_id":prefix.plan["run_id"],"utc":utc}
    constituents = {name:envelope(canonical(value),b"",0,(now-timedelta(milliseconds=100)).isoformat(),mono-100000000,
                                 utc,mono,True) for name,value in values.items()}
    capsule = {"created_utc":(now-timedelta(seconds=1)).isoformat(),"expires_utc":(now+timedelta(seconds=1200)).isoformat(),
               "created_mono_ns":mono-10**9,"deadline_mono_ns":mono+1200*10**9}
    state = {"schema":"task13_reconciled_state_v1","original":prefix.binding,"status":"PASS",
             "predicate_version":"task13_readonly_reconciliation_v1","constituents":constituents,"constituent_sha256":digest(constituents)}
    return prefix,capsule,state,utc


def test_retained_state_predicates_accept_complete_synthetic_projection(state_case):
    validate_state(*state_case)

def rebind(state,target,value):
    row=state['constituents'][target]
    state['constituents'][target]=envelope(canonical(value),b'',0,row['dispatch_utc'],row['dispatch_mono_ns'],row['finished_utc'],row['finished_mono_ns'],True)
    state['constituent_sha256']=digest(state['constituents'])

@pytest.mark.parametrize('slot',[0,14,15])
@pytest.mark.parametrize('mode',['reused','unknown','original','race'])
def test_live_ssh_reuse_admits_only_proven_other_instance(state_case,slot,mode):
    from tests.tools.test_task13_process_identity import sample
    p,c,s,at=state_case
    registry=reference_registry(p);ref=registry['refs'][slot]
    identity=s['constituents']['process_identity']['observation']
    birth=ref['absence_filetime']+100
    if mode=='original':birth=ref['original_birth_filetime'] or ref['absence_filetime']-100
    x=sample(birth);x.update(pid=ref['pid'],cim_birth_filetime=birth//10*10)
    row=dict(pid=ref['pid'],first=x,second=dict(x),retained_first_not_exited=True,error_type=None)
    if mode=='unknown':row['first']['native_error']=5
    if mode=='race':row['second']['birth_filetime']+=1
    identity['rows'][slot]=row
    current=s['constituents']['current']['observation']
    (current['known']+current['pair'])[slot]['present']=True
    rebind(s,'current',current);rebind(s,'process_identity',identity)
    if mode=='reused':validate_state(p,c,s,at)
    else:
        with pytest.raises(ValueError):validate_state(p,c,s,at)

def test_original_leaf_absence_predicate_is_not_substituted(state_case):
    p,c,s,at=state_case
    current=s['constituents']['current']['observation']
    # The first sealed leaf must remain absent irrespective of process identity.
    for row in current['leaves']:
        if row['present'] is False:
            row['present']=True
            break
    else:raise AssertionError('fixture absent leaf required')
    rebind(s,'current',current)
    with pytest.raises(ValueError):validate_state(p,c,s,at)

def test_missing_identity_constituent_cannot_use_legacy_numeric_fallback(state_case):
    p,c,s,at=state_case
    del s['constituents']['process_identity'];s['constituent_sha256']=digest(s['constituents'])
    with pytest.raises(ValueError):validate_state(p,c,s,at)

def test_raw_identity_tamper_cannot_be_replaced_by_computed_state_label(state_case):
    p,c,s,at=state_case
    s['constituents']['process_identity']['observation']['rows'][0]['state']='PID_REUSED'
    s['constituent_sha256']=digest(s['constituents'])
    with pytest.raises(ValueError):validate_state(p,c,s,at)

@pytest.mark.parametrize('mutation',['marker','observer','pid_type','pair_error','presence_disagreement','registry','vm','missing_row','generation','snapshot'])
def test_pid_correction_preserves_other_boundaries(state_case,mutation):
    p,c,s,at=state_case
    current=s['constituents']['current']['observation']
    identity=s['constituents']['process_identity']['observation']
    if mutation=='marker':current['preserved_capsule']['marker']['present']=True
    elif mutation=='observer':current['observer_pid']=current['known'][0]['pid']
    elif mutation=='pid_type':current['known'][0]['pid']=str(current['known'][0]['pid'])
    elif mutation=='pair_error':current['pair'][0]['error_type']='AccessDenied'
    elif mutation=='presence_disagreement':current['pair'][0]['present']=True
    elif mutation=='registry':identity['registry_sha256']='0'*64
    elif mutation=='vm':identity['vm_uuid']='wrong'
    elif mutation=='missing_row':identity['rows'].pop()
    else:
        management=s['constituents']['management']['observation']
        if mutation=='generation':management['state']['config']['vmgenid']='wrong'
        else:management['metadata']={}
        rebind(s,'management',management)
    rebind(s,'current',current);rebind(s,'process_identity',identity)
    with pytest.raises((ValueError,KeyError)):validate_state(p,c,s,at)


@pytest.mark.parametrize("target,field,value", [
    ("guest","plan_sha256","0"*64),("guest","baseline_sha256","0"*64),("guest","marker_absent",False),
    ("guest","msi_in_progress",True),("guest","update_owners",["pending"]),
    ("guest","vm_uuid","wrong"),("guest","device_id","wrong"),("guest","network_matches",2),
    ("provider","device_owners",["owner"]),("provider","visible_recommendations",1),
    ("management","active_tasks",["task"]),("current","scan_complete",False),
    ("clock_guest","utc","2000-01-01T00:00:00Z"),
])
def test_live_state_tamper_refuses(state_case,target,field,value):
    p,c,s,at = state_case
    row = s["constituents"][target]
    row["observation"][field] = value
    s["constituents"][target] = envelope(canonical(row["observation"]),b"",0,row["dispatch_utc"],row["dispatch_mono_ns"],
                                        row["finished_utc"],row["finished_mono_ns"],True)
    s["constituent_sha256"] = digest(s["constituents"])
    with pytest.raises(ValueError):
        validate_state(p,c,s,at)


def test_dispatch_refuses_clock_that_was_fresh_before_preparation(state_case):
    from types import SimpleNamespace
    from tools.canary.task13_continuation.loader import guard_dispatch
    p,c,s,at=state_case
    c['created_utc']=(datetime.now(timezone.utc)-timedelta(seconds=20)).isoformat()
    c['created_mono_ns']-=20*10**9
    row=s['constituents']['clock_guest']
    old=(datetime.fromisoformat(at)-timedelta(seconds=6)).isoformat()
    value=dict(row['observation'],utc=old)
    s['constituents']['clock_guest']=envelope(canonical(value),b'',0,old,row['dispatch_mono_ns']-6*10**9,
                                             old,row['finished_mono_ns']-6*10**9,True)
    s['constituent_sha256']=digest(s['constituents'])
    preflight=envelope(canonical(s),b'',0,at,row['dispatch_mono_ns'],at,row['finished_mono_ns'],True)
    with pytest.raises(ValueError): guard_dispatch(p,SimpleNamespace(check=lambda:None,capsule=c),preflight)


def test_dispatch_accepts_complete_fresh_synthetic_state(state_case):
    from types import SimpleNamespace
    from tools.canary.task13_continuation.loader import guard_dispatch
    p,c,s,at=state_case
    row=s['constituents']['clock_guest']
    preflight=envelope(canonical(s),b'',0,at,row['dispatch_mono_ns'],at,row['finished_mono_ns'],True)
    final=guard_dispatch(p,SimpleNamespace(check=lambda:None,capsule=c),preflight)
    final(at)
    with pytest.raises(ValueError,match='stale dispatch clock'):
        final((datetime.fromisoformat(at)+timedelta(seconds=6)).isoformat())


def test_current_vm_parent_is_checkpoint_snapshot_not_saved_snapshot_parent(prefix):
    from tools.canary.task13_continuation.management import sealed_module,validate_checkpoint_config
    manifest=parse_json((prefix.root/'source-closure-manifest.json').read_bytes())
    policy=sealed_module(prefix.root,'task13_vm100_recovery.draft.py',manifest)
    request={'snapshot':prefix.plan['snapshot'],'generation':prefix.receipts[0]['initial_vm_generation']}
    config=dict(policy.EXPECTED,parent=request['snapshot'],vmgenid=request['generation'])
    # Synthetic exact post-checkpoint configuration through the actual sealed
    # original policy; no VM observation or execution authority is supplied.
    assert validate_checkpoint_config(policy,config,request)==policy.EXPECTED
    with pytest.raises(ValueError):
        validate_checkpoint_config(policy,dict(config,parent='pre82-real81-clock'),request)
    with pytest.raises(ValueError):
        validate_checkpoint_config(policy,dict(config,boot='changed'),request)
