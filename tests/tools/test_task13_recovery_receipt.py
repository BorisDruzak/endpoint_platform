"""Pure recovery receipt mutations; no native execution or receipt publication."""
import base64
import copy
from pathlib import Path
from datetime import datetime,timezone,timedelta
from uuid import uuid4
import pytest

from tests.tools.test_task13_continuation_receipt import evidence_case,envelope,root_completion
from tools.canary.task13_continuation.codec import canonical,digest,parse_json,sha256
from tools.canary.task13_continuation.recovery_admission import OLD_CLAIMS,GLOBAL_NAME,FAILED_TREE_SHA,READONLY_TREE_SHA
from tools.canary.task13_continuation.recovery_receipt import make_recovery_receipt,verify_recovery_receipt,validate_recovery_evidence
from tools.canary.task13_continuation.receipt import publication_ack

pytestmark=pytest.mark.no_db

@pytest.fixture
def recovery_case(evidence_case,monkeypatch):
    p,c,e=evidence_case
    control=Path.home()/'.codex/task-evidence/task13-command-transport-review-20261011-c/control.json'
    if not control.exists():pytest.skip('private original immutable binding input')
    original=parse_json(control.read_bytes())['original_binding'];original_root=Path(parse_json(control.read_bytes())['original_root'])
    p.root=original_root
    p.binding=original;p.plan['run_id']=original['original_run_id'];c['original']=original
    for n in ('preflight','postflight'):
        v=dict(e[n]['observation'],original=original);e[n]=envelope(v,e[n]['dispatch_mono_ns'],e[n]['dispatch_utc'])
    g=dict(e['guest']['observation'],run_id=original['original_run_id'],plan_sha256=original['original_plan_sha256'])
    e['guest']=envelope(g,e['guest']['dispatch_mono_ns'],e['guest']['dispatch_utc'])
    h=dict(schema='task13_consumed_history_v1',original=original,global_claim_sha256=OLD_CLAIMS[GLOBAL_NAME],claims=dict(OLD_CLAIMS),
        failed_bundle_sha256=FAILED_TREE_SHA,prior_readonly_sha256=READONLY_TREE_SHA,prior_root=dict(pid=123,birth=456),
        failure_phase='PREPARE_BUILDER_REFUSED_BEFORE_TRANSPORT',historical_rca='UNKNOWN')
    gate=dict(schema='task13_additive_recovery_gate_v1',continuation_id=c['continuation_id'],protocol_source_sha256='d'*64,
        implementation_sha='e'*40,status='READY_REQUIRES_SEPARATE_AUTHORIZATION')
    request=dict(schema='task13_actual_recovery_execution_request_v1',scope='seq04-additive-recovery-v1',gate_sha256=digest(gate),
        continuation_id=c['continuation_id'],protocol_source_sha256='d'*64,implementation_sha='e'*40,allowed_seq=4,
        expires_utc=(datetime.now(timezone.utc)+timedelta(seconds=1100)).isoformat())
    c['source_closure']['protocol_source_sha256']='d'*64
    c['source_closure']['execution']['entries']['operator-request.json']=dict(bytes=len(canonical(request)),sha256=digest(request))
    c['source_closure']['execution']['entries']['admission-gate.json']=dict(bytes=len(canonical(gate)),sha256=digest(gate))
    parent=copy.deepcopy(c);parent['controller']=dict(c['controller'],pid=22,birth=1235)
    launch_preflight=copy.deepcopy(e['preflight']);launch_preflight['dispatch_mono_ns']=1;launch_preflight['finished_mono_ns']=2
    launch=dict(schema='task13_recovery_launch_slot_v1',original=original,history_sha256=digest(h),consumed_global_claim_sha256=h['global_claim_sha256'],
        protocol_version=1,protocol_source_sha256='d'*64,implementation_sha='e'*40,continuation_id=c['continuation_id'],gate_sha256=digest(gate),
        request_sha256=digest(request),source_closure_sha256=digest(c['source_closure']),capsule_sha256=digest(parent),
        preflight_sha256=digest(launch_preflight),expires_utc=request['expires_utc'],controller=parent['controller'])
    dispatch=dict(schema='task13_recovery_dispatch_slot_v1',launch_slot_sha256=digest(launch),continuation_id=c['continuation_id'],
        original=original,protocol_version=1,protocol_source_sha256='d'*64,consumed_global_claim_sha256=h['global_claim_sha256'],
        capsule_sha256=digest(c),preflight_sha256=digest(e['preflight']))
    e.pop('dispatch_claim');e.update(schema='task13_recovery_execution_evidence_v1',source_closure_sha256=digest(c['source_closure']),
        recovery_history=h,recovery_launch_slot=launch,recovery_dispatch_slot=dispatch,recovery_authorization=request,admission_gate=gate,
        historical_consumed_claims={n:base64.b64encode((original_root/'continuation-v1-claims'/n).read_bytes()).decode() for n in OLD_CLAIMS},
        launch_capsule=parent,launch_preflight=launch_preflight,preclaim_preflight=copy.deepcopy(e['preflight']))
    monkeypatch.setattr('tools.canary.task13_continuation.recovery_receipt.validate_state',lambda *args:None)
    return p,c,e

def test_explicit_recovery_receipt_requires_native_root_completion(recovery_case):
    p,c,e=recovery_case;r=make_recovery_receipt(p,c,e)
    assert r['schema']=='task13_additive_recovery_receipt_v1' and r['previous_sha256']==p.binding['original_tip']
    verify_recovery_receipt(p,c,r,e,publication_ack(c,r),root_completion(c,r,e))
    with pytest.raises(ValueError):verify_recovery_receipt(p,c,r,e,publication_ack(c,r),None)

@pytest.mark.parametrize('fault',['old_claim','launch','dispatch','capsule','source','deadline','stdin','watchdog','journal','native_exit','marker','grant_pin'])
def test_recovery_receipt_cannot_promote_bad_authority_or_settlement(recovery_case,fault):
    p,c,e=recovery_case
    if fault=='old_claim':e['historical_consumed_claims'][GLOBAL_NAME]=base64.b64encode(b'{}').decode()
    elif fault=='launch':e['recovery_launch_slot']['request_sha256']='0'*64
    elif fault=='dispatch':e['recovery_dispatch_slot']['launch_slot_sha256']='0'*64
    elif fault=='capsule':e['recovery_dispatch_slot']['capsule_sha256']='0'*64
    elif fault=='source':e['source_closure_sha256']='0'*64
    elif fault=='deadline':
        e['recovery_authorization']['expires_utc']='2000-01-01T00:00:00Z'
        e['recovery_launch_slot']['expires_utc']=e['recovery_authorization']['expires_utc']
        e['recovery_launch_slot']['request_sha256']=digest(e['recovery_authorization']);e['recovery_dispatch_slot']['launch_slot_sha256']=digest(e['recovery_launch_slot'])
    elif fault=='stdin':e['guest']['stdin_confirmed']=False
    elif fault=='watchdog':e['watchdog']['observation']['terminated']=True
    elif fault=='journal':e['journal_sha256']='0'*64
    elif fault=='marker':e['guest']['observation']['markerAbsent']=False
    elif fault=='grant_pin':
        c['source_closure']['execution']['entries']['operator-request.json']['sha256']='0'*64
        e['launch_capsule']['source_closure']=copy.deepcopy(c['source_closure'])
        e['source_closure_sha256']=digest(c['source_closure']);e['recovery_launch_slot']['source_closure_sha256']=digest(c['source_closure'])
        e['recovery_launch_slot']['capsule_sha256']=digest(e['launch_capsule']);e['recovery_dispatch_slot']['capsule_sha256']=digest(c)
        e['recovery_dispatch_slot']['launch_slot_sha256']=digest(e['recovery_launch_slot'])
    else:
        r=make_recovery_receipt(p,c,e);completion=root_completion(c,r,e);completion['exit_code']=1
        with pytest.raises(ValueError):verify_recovery_receipt(p,c,r,e,publication_ack(c,r),completion)
        return
    with pytest.raises(ValueError):validate_recovery_evidence(p,c,e)
