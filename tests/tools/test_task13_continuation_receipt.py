import base64
import copy
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from tools.canary.task13_continuation.codec import canonical, digest, sha256
from tools.canary.task13_continuation.history import ORIGINAL_FILES, BASELINE_SHA, SNAPSHOT_SHA
from tools.canary.task13_continuation.receipt import validate_execution_evidence, make_receipt, verify_continuation_receipt, publication_ack

pytestmark = pytest.mark.no_db


def envelope(value, mono, now):
    raw = canonical(value)
    return {"status": "TRANSPORT_COMPLETE", "exit_code": 0, "stdin_confirmed": True,
            "stdout_b64": base64.b64encode(raw).decode(), "stderr_b64": "", "stdout_sha256": sha256(raw),
            "stderr_sha256": sha256(b""), "dispatch_mono_ns": mono, "finished_mono_ns": mono+1,
            "dispatch_utc": now, "finished_utc": now, "observation": value}


@pytest.fixture
def evidence_case(monkeypatch):
    monkeypatch.setattr("tools.canary.task13_continuation.receipt.validate_state", lambda *args: None)
    now = datetime.now(timezone.utc).isoformat()
    binding = {"original_tip": ORIGINAL_FILES["receipt-03-start-after-snapshot.json"],
               'original_run_seal_sha256':ORIGINAL_FILES['run-seal.json'],
               "baseline_sha256": BASELINE_SHA, "snapshot_identity_sha256": SNAPSHOT_SHA,
               "original_run_id": str(uuid4()), "original_plan_sha256": "a"*64}
    cid = str(uuid4())
    capsule = {"continuation_id": cid, "original": binding, "created_utc": now,
               'controller':dict(host_id='a'*64,boot_id=str(uuid4()),pid=21,birth=1234,token_sid='S-1-5-18',elevated=True),
               "expires_utc": (datetime.now(timezone.utc)+timedelta(seconds=1200)).isoformat(),
               "created_mono_ns": 1, "deadline_mono_ns": 1000000000000,
               "source_closure": {'execution':{'entries':{'wire.bin':{'bytes':3},'Watch-Task13DiagnosticProcess.ps1':{'sha256':'c'*64}}}}}
    prefix = SimpleNamespace(binding=binding, plan={"run_id": binding["original_run_id"]},
                             controller=SimpleNamespace(genuine81=lambda proof, plan: None))
    identity = {"run": cid, "pid": 12, "birth": 123}
    from tests.tools.task13_journal_fixture import journal_bytes
    journal = journal_bytes(identity,now)
    value = {"status":"GUEST_COMPARATOR_PASS", "run_id":binding["original_run_id"], "utc":now,
             "plan_sha256":binding["original_plan_sha256"],
             "baselineSha256":BASELINE_SHA, "snapshot_identity_sha256":SNAPSHOT_SHA,
             "markerAbsent":True, "native_proof":{}}
    evidence = {"schema":"task13_execution_evidence_v1", "continuation_id":cid,
                "source_closure_sha256":digest(capsule['source_closure']), "guest":envelope(value,10,now), "identity":identity,
                "journal_b64":base64.b64encode(journal).decode(), "journal_sha256":sha256(journal),
                "watchdog":envelope({**identity,"terminated":False,"confirmed":True,"wait_result":0,
                                       "exit_code":0,'termination_utc':None,'capture_error':None,'elapsed_ms':1},12,now),
                "preflight":envelope({"schema":"task13_reconciled_state_v1","original":binding,
                    "status":"PASS","predicate_version":"task13_readonly_reconciliation_v1",
                    "constituents":{},"constituent_sha256":digest({})},2,now),
                "postflight":envelope({"schema":"task13_reconciled_state_v1","original":binding,
                    "status":"PASS","predicate_version":"task13_readonly_reconciliation_v1",
                    "constituents":{},"constituent_sha256":digest({})},14,now)}
    root='C:\\Task13Continuation-'+cid.replace('-','')
    ready={'run':cid,'pid':13,'limit':120,'utc':now}
    exit_row={k:v for k,v in evidence['watchdog']['observation'].items() if k!='run'}
    raw_files={'identity.json':canonical(dict(identity,root=root)),'watchdog-ready.json':canonical(ready),
               'watchdog-armed.json':canonical(dict(pid=12,birth=123,retained_handle=True,safety_margin_ms=500,remaining_ms=119000)),
               'exit-confirmed.json':canonical(exit_row),'stages.jsonl':journal}
    evidence['retained_collection']=envelope(dict(status='RETAINED_CONTINUATION_EVIDENCE',run=cid,root=root,
        files={k:base64.b64encode(v).decode() for k,v in raw_files.items()}),12,now)
    evidence['watchdog']['retained_transport_sha256']=digest(evidence['retained_collection'])
    evidence['watchdog_preparation']=envelope(dict(status='INDEPENDENT_WATCHDOG_READY',run=cid,root=root,watchdog_sha256='c'*64,ready=ready),1,now)
    evidence['dispatch_claim']=dict(schema='task13_dispatch_claim_v1',original_run_seal_sha256=binding['original_run_seal_sha256'],
                                    original_tip=binding['original_tip'],seq=4,continuation_id=cid)
    # Pure evidence tests do not confer operational acceptance; loader supplies actual reconciler.
    return prefix, capsule, evidence


def test_only_validated_seq04_receipt_can_link_to_original_tip(evidence_case):
    p,c,e = evidence_case
    receipt = make_receipt(p,c,e)
    verify_continuation_receipt(p,c,receipt,e,publication_ack(c,receipt),root_completion(c,receipt,e))
    assert receipt["seq"] == 4 and receipt["previous_sha256"] == p.binding["original_tip"]
    for field,value in [("seq",5),("step","marker"),("previous_sha256","0"*64)]:
        with pytest.raises(ValueError):
            verify_continuation_receipt(p,c,{**receipt,field:value},e)
    with pytest.raises(ValueError,match="publication acknowledgement"):
        verify_continuation_receipt(p,c,receipt,e)


@pytest.mark.parametrize('field',['retained_collection','watchdog_preparation','dispatch_claim'])
def test_missing_or_unknown_retained_evidence_never_supports_receipt(evidence_case,field):
    p,c,e=evidence_case
    for bad in (None,{'status':'UNKNOWN'}):
        candidate=copy.deepcopy(e)
        if bad is None: candidate.pop(field,None)
        else: candidate[field]=bad
        with pytest.raises(ValueError): make_receipt(p,c,candidate)

def test_durable_ack_without_actual_root_exit_never_opens_resume_gate(evidence_case):
    p,c,e=evidence_case
    receipt=make_receipt(p,c,e)
    with pytest.raises(ValueError,match='root completion'):
        verify_continuation_receipt(p,c,receipt,e,publication_ack(c,receipt))


def root_completion(c,receipt,e):
    publication=publication_ack(c,receipt)
    stdout=canonical(dict(status='ROOT_PUBLICATION_READY',continuation_id=c['continuation_id'],continuation_sha256=digest(c),
                         receipt_sha256=digest(receipt),source_closure_sha256=digest(c['source_closure']),resume_gate='STOP_BEFORE_SEQ05'))
    return dict(schema='task13_root_completion_v1',status='ROOT_NORMAL_EXIT_OBSERVED',controller=c['controller'],
        supervisor_controller=dict(c['controller'],pid=22,birth=1235),root_pid=21,root_birth=1234,exit_code=0,wait_result=0,
        observed_exit_utc=c['created_utc'],observed_exit_mono_ns=20,stdout_b64=base64.b64encode(stdout).decode(),stderr_b64='',
        stdout_sha256=sha256(stdout),stderr_sha256=sha256(b''),receipt_sha256=digest(receipt),continuation_sha256=digest(c),
        evidence_sha256=digest(e),publication_sha256=digest(publication))


@pytest.mark.parametrize('fault',['nonzero','expiry_after_ack','wrong_birth','unknown_result','publication_hash'])
def test_failed_or_expired_root_finalization_refuses(evidence_case,fault):
    p,c,e=evidence_case;receipt=make_receipt(p,c,e);completion=root_completion(c,receipt,e)
    if fault=='nonzero': completion['exit_code']=2
    elif fault=='expiry_after_ack': completion['observed_exit_mono_ns']=c['deadline_mono_ns']
    elif fault=='wrong_birth': completion['root_birth']=1236
    elif fault=='publication_hash': completion['publication_sha256']='0'*64
    else:
        raw=canonical({'status':'UNKNOWN'})
        completion['stdout_b64']=base64.b64encode(raw).decode();completion['stdout_sha256']=sha256(raw)
    with pytest.raises(ValueError): verify_continuation_receipt(p,c,receipt,e,publication_ack(c,receipt),completion)


@pytest.mark.parametrize("fault", ["pass","run","plan","baseline","snapshot","ssh","timeout","stdin",
                                   "journal","journal_identity","terminated","exit","unconfirmed","source"])
def test_no_false_pass(evidence_case, fault):
    p,c,e = evidence_case
    e = copy.deepcopy(e)
    if fault in ("pass","run","plan","baseline","snapshot"):
        field = {"pass":"status","run":"run_id","plan":"plan_sha256","baseline":"baselineSha256","snapshot":"snapshot_identity_sha256"}[fault]
        e["guest"]["observation"][field] = "wrong"
        e["guest"] = envelope(e["guest"]["observation"],10,e["guest"]["dispatch_utc"])
    elif fault in ("ssh","timeout","stdin"):
        e["guest"][{"ssh":"exit_code","timeout":"status","stdin":"stdin_confirmed"}[fault]] = 2
    elif fault.startswith("journal"):
        raw = base64.b64decode(e["journal_b64"])
        raw = raw[:-1] if fault == "journal" else raw.replace(b'"pid":12',b'"pid":13')
        e["journal_b64"],e["journal_sha256"] = base64.b64encode(raw).decode(),sha256(raw)
    elif fault == "source":
        e["source_closure_sha256"] = "0"*64
    else:
        w = e["watchdog"]["observation"]
        w[{"terminated":"terminated","exit":"exit_code","unconfirmed":"confirmed"}[fault]] = True if fault=="terminated" else (2 if fault=="exit" else False)
        e["watchdog"] = envelope(w,12,e["watchdog"]["dispatch_utc"])
    with pytest.raises(ValueError):
        validate_execution_evidence(p,c,e)


def test_self_declared_reconciliation_pass_is_not_evidence(evidence_case):
    from tools.canary.task13_continuation.reconciliation import validate_state
    p,c,e = evidence_case
    with pytest.raises(ValueError, match="complete live reconciliation"):
        validate_state(p,c,e["preflight"]["observation"],e["preflight"]["finished_utc"])
