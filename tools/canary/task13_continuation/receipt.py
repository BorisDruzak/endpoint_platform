"""Raw-bound observations and additive seq04 receipts; no status promotion."""
import base64
from datetime import timedelta

from .codec import canonical, digest, integer, instant, parse_json, require, sha256
from .journal import validate_journal
from .reconciliation import validate_state


def raw_bytes(encoded):
    require(type(encoded) is str and len(encoded) <= 48 * 1024 * 1024, "bounded base64 record")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, __import__("binascii").Error) as error:
        raise ValueError("invalid raw evidence encoding") from error
    require(base64.b64encode(raw).decode("ascii") == encoded, "canonical base64 required")
    return raw


def observation(envelope, capsule, *, maximum=145):
    require(type(envelope) is dict and envelope["status"] == "TRANSPORT_COMPLETE"
            and type(envelope["exit_code"]) is int and envelope["exit_code"] == 0
            and envelope["stdin_confirmed"] is True, "complete actual transport required")
    stdout, stderr = raw_bytes(envelope["stdout_b64"]), raw_bytes(envelope["stderr_b64"])
    require(len(stdout) <= 8*1024*1024 and stderr == b"" and sha256(stdout) == envelope["stdout_sha256"]
            and sha256(stderr) == envelope["stderr_sha256"], "raw transport binding")
    value = parse_json(stdout.strip())
    require(value == envelope["observation"] and not value.get("synthetic"), "actual raw observation required")
    sent, done = instant(envelope["dispatch_utc"]), instant(envelope["finished_utc"])
    start, end = integer(envelope["dispatch_mono_ns"]), integer(envelope["finished_mono_ns"])
    require(instant(capsule["created_utc"]) <= sent <= done <= instant(capsule["expires_utc"])
            and 0 <= (done-sent).total_seconds() <= maximum
            and capsule["created_mono_ns"] <= start <= end < capsule["deadline_mono_ns"] - 2*10**9
            and end-start <= maximum*10**9, "fresh continuation transport clocks")
    return value


def validate_execution_evidence(prefix, capsule, evidence):
    require(evidence["schema"] == "task13_execution_evidence_v1"
            and evidence["continuation_id"] == capsule["continuation_id"]
            and capsule["original"] == prefix.binding
            and evidence["source_closure_sha256"] == digest(capsule["source_closure"]), "execution identity/source binding")
    pre = observation(evidence["preflight"], capsule, maximum=60)
    post = observation(evidence["postflight"], capsule, maximum=60)
    for state, envelope in ((pre,evidence["preflight"]),(post,evidence["postflight"])):
        validate_state(prefix,capsule,state,envelope["finished_utc"])
    guest = observation(evidence["guest"], capsule)
    require(guest["status"] == "GUEST_COMPARATOR_PASS" and guest["run_id"] == prefix.plan["run_id"]
            and guest["plan_sha256"] == prefix.binding["original_plan_sha256"]
            and guest["baselineSha256"] == prefix.binding["baseline_sha256"]
            and guest["snapshot_identity_sha256"] == prefix.binding["snapshot_identity_sha256"]
            and guest["markerAbsent"] is True, "real compare-after-start result required")
    observed = instant(guest["utc"])
    require(instant(evidence["guest"]["dispatch_utc"])-timedelta(seconds=5) <= observed
            <= instant(evidence["guest"]["finished_utc"])+timedelta(seconds=5), "guest result clock bracket")
    prefix.controller.genuine81(guest["native_proof"], prefix.plan)
    require(evidence["preflight"]["finished_mono_ns"] <= evidence["guest"]["dispatch_mono_ns"]
            <= evidence["guest"]["finished_mono_ns"] <= evidence["postflight"]["dispatch_mono_ns"], "pre/workload/post chronology")
    identity = evidence["identity"]
    require(set(identity) == {"run","pid","birth"} and identity["run"] == capsule["continuation_id"], "guest process identity")
    integer(identity["pid"],1,2**32-1)
    integer(identity["birth"],1)
    watchdog = observation(evidence["watchdog"], capsule, maximum=15)
    require(all(type(watchdog[k]) is type(v) and watchdog[k] == v for k,v in identity.items())
            and watchdog["terminated"] is False and watchdog["confirmed"] is True
            and type(watchdog["wait_result"]) is int and watchdog["wait_result"] == 0
            and type(watchdog["exit_code"]) is int and watchdog["exit_code"] == 0,
            "watchdog retained normal exit required")
    journal = raw_bytes(evidence["journal_b64"])
    require(sha256(journal) == evidence["journal_sha256"], "retained journal hash")
    validate_journal(journal,identity)


def make_receipt(prefix, capsule, evidence):
    validate_execution_evidence(prefix,capsule,evidence)
    return {"schema":"task13_continuation_receipt_v1", "seq":4, "step":"compare-after-start",
            "status":"PASS", "continuation_id":capsule["continuation_id"],
            "continuation_sha256":digest(capsule), "previous_sha256":prefix.binding["original_tip"],
            "original":prefix.binding, "source_closure_sha256":digest(capsule["source_closure"]),
            "evidence_sha256":digest(evidence), "resume_gate":"STOP_BEFORE_SEQ05"}


def verify_continuation_receipt(prefix,capsule,receipt,evidence):
    require(receipt == make_receipt(prefix,capsule,evidence), "canonical seq04 receipt mismatch")
