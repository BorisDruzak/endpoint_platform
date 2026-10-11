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
               "baseline_sha256": BASELINE_SHA, "snapshot_identity_sha256": SNAPSHOT_SHA,
               "original_run_id": str(uuid4()), "original_plan_sha256": "a"*64}
    cid = str(uuid4())
    capsule = {"continuation_id": cid, "original": binding, "created_utc": now,
               "expires_utc": (datetime.now(timezone.utc)+timedelta(seconds=1200)).isoformat(),
               "created_mono_ns": 1, "deadline_mono_ns": 1000000000000, "source_closure": {}}
    prefix = SimpleNamespace(binding=binding, plan={"run_id": binding["original_run_id"]},
                             controller=SimpleNamespace(genuine81=lambda proof, plan: None))
    identity = {"run": cid, "pid": 12, "birth": 123}
    rows = [("ENTER", "WRAPPER"), ("RETURN", "WATCHDOG_ARMED"), ("ENTER", "SCRIPTBLOCK.INVOKE"),
            ("RETURN", "SCRIPTBLOCK.INVOKE"), ("RETURN", "WRAPPER")]
    journal = b"".join(canonical(dict(identity, utc=now, ms=n, seq=n, phase=p, stage=s, counts=None))+b"\n"
                       for n,(p,s) in enumerate(rows,1))
    value = {"status":"GUEST_COMPARATOR_PASS", "run_id":binding["original_run_id"], "utc":now,
             "plan_sha256":binding["original_plan_sha256"],
             "baselineSha256":BASELINE_SHA, "snapshot_identity_sha256":SNAPSHOT_SHA,
             "markerAbsent":True, "native_proof":{}}
    evidence = {"schema":"task13_execution_evidence_v1", "continuation_id":cid,
                "source_closure_sha256":digest({}), "guest":envelope(value,10,now), "identity":identity,
                "journal_b64":base64.b64encode(journal).decode(), "journal_sha256":sha256(journal),
                "watchdog":envelope({**identity,"terminated":False,"confirmed":True,"wait_result":0,
                                       "exit_code":0},12,now),
                "preflight":envelope({"schema":"task13_reconciled_state_v1","original":binding,
                    "status":"PASS","predicate_version":"task13_readonly_reconciliation_v1",
                    "constituents":{},"constituent_sha256":digest({})},2,now),
                "postflight":envelope({"schema":"task13_reconciled_state_v1","original":binding,
                    "status":"PASS","predicate_version":"task13_readonly_reconciliation_v1",
                    "constituents":{},"constituent_sha256":digest({})},14,now)}
    # Pure evidence tests do not confer operational acceptance; loader supplies actual reconciler.
    return prefix, capsule, evidence


def test_only_validated_seq04_receipt_can_link_to_original_tip(evidence_case):
    p,c,e = evidence_case
    receipt = make_receipt(p,c,e)
    verify_continuation_receipt(p,c,receipt,e,publication_ack(c,receipt))
    assert receipt["seq"] == 4 and receipt["previous_sha256"] == p.binding["original_tip"]
    for field,value in [("seq",5),("step","marker"),("previous_sha256","0"*64)]:
        with pytest.raises(ValueError):
            verify_continuation_receipt(p,c,{**receipt,field:value},e)
    with pytest.raises(ValueError,match="publication acknowledgement"):
        verify_continuation_receipt(p,c,receipt,e)


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
