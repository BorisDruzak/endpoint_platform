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
