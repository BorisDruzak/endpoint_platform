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
    require({'retained_collection','watchdog_preparation','dispatch_claim'}<=evidence.keys(),'actual retained collection/preparation/claim required')
    claim={'schema':'task13_dispatch_claim_v1','original_run_seal_sha256':prefix.binding['original_run_seal_sha256'],
           'original_tip':prefix.binding['original_tip'],'seq':4,'continuation_id':capsule['continuation_id']}
    require(evidence['dispatch_claim']==claim,'original-step permanent dispatch claim binding')
    root='C:\\Task13Continuation-'+capsule['continuation_id'].replace('-','')
    preparation=observation(evidence['watchdog_preparation'],capsule,maximum=25)
    collection=observation(evidence['retained_collection'],capsule,maximum=15)
    require(preparation['status']=='INDEPENDENT_WATCHDOG_READY' and preparation['run']==capsule['continuation_id']
            and preparation['root']==root and preparation['watchdog_sha256']==capsule['source_closure']['execution']['entries']['Watch-Task13DiagnosticProcess.ps1']['sha256'],
            'exact watchdog preparation/source')
    require(collection['status']=='RETAINED_CONTINUATION_EVIDENCE' and collection['run']==capsule['continuation_id']
            and collection['root']==root and set(collection['files'])=={'identity.json','watchdog-ready.json','watchdog-armed.json','exit-confirmed.json','stages.jsonl'},
            'actual complete retained evidence collection')
    files={name:raw_bytes(value) for name,value in collection['files'].items()}
    identity_row=parse_json(files['identity.json']);ready_row=parse_json(files['watchdog-ready.json'])
    armed_row=parse_json(files['watchdog-armed.json']);exit_row=parse_json(files['exit-confirmed.json'])
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
    require(identity_row==dict(identity,root=root),'retained process identity projection')
    require(ready_row==preparation['ready'] and ready_row['run']==capsule['continuation_id']
            and integer(ready_row['limit'])==120 and integer(ready_row['pid'],1)!=identity['pid'],'retained readiness binding')
    require(instant(evidence['watchdog_preparation']['dispatch_utc'])-timedelta(seconds=5)<=instant(ready_row['utc'])
            <=instant(evidence['watchdog_preparation']['finished_utc'])+timedelta(seconds=5),'watchdog readiness clock bracket')
    require(integer(armed_row['pid'])==identity['pid'] and integer(armed_row['birth'])==identity['birth']
            and armed_row['retained_handle'] is True and integer(armed_row['safety_margin_ms'])==500
            and 0<integer(armed_row['remaining_ms'])<=119500,'retained watchdog arm binding')
    watchdog = observation(evidence["watchdog"], capsule, maximum=15)
    require(watchdog==dict(exit_row,run=identity['run'])
            and evidence['watchdog'].get('retained_transport_sha256')==digest(evidence['retained_collection']),'actual retained exit projection')
    require(all(type(watchdog[k]) is type(v) and watchdog[k] == v for k,v in identity.items())
            and watchdog["terminated"] is False and watchdog["confirmed"] is True
            and type(watchdog["wait_result"]) is int and watchdog["wait_result"] == 0
            and type(watchdog["exit_code"]) is int and watchdog["exit_code"] == 0,
            "watchdog retained normal exit required")
    require(exit_row['termination_utc'] is None and exit_row['capture_error'] is None
            and integer(exit_row['elapsed_ms'],0,120000)<=120000,'watchdog normal bounded completion')
    journal = raw_bytes(evidence["journal_b64"])
    require(journal==files['stages.jsonl'] and sha256(journal) == evidence["journal_sha256"], "retained journal hash")
    validate_journal(journal,identity,capsule['source_closure']['execution']['entries']['wire.bin']['bytes'])
    journal_rows=[parse_json(line) for line in journal.splitlines()]
    require(instant(evidence['guest']['dispatch_utc'])-timedelta(seconds=5)<=instant(journal_rows[0]['utc'])
            <=instant(journal_rows[-1]['utc'])<=instant(evidence['guest']['finished_utc'])+timedelta(seconds=5),'journal/workload clocks')
    require(evidence['watchdog_preparation']['finished_mono_ns']<=evidence['preflight']['dispatch_mono_ns']
            and evidence['guest']['finished_mono_ns']<=evidence['retained_collection']['dispatch_mono_ns']
            <=evidence['retained_collection']['finished_mono_ns']<=evidence['postflight']['dispatch_mono_ns'],
            'preparation/reconciliation/retained chronology')


def make_receipt(prefix, capsule, evidence):
    validate_execution_evidence(prefix,capsule,evidence)
    return {"schema":"task13_continuation_receipt_v1", "seq":4, "step":"compare-after-start",
            "status":"PASS", "continuation_id":capsule["continuation_id"],
            "continuation_sha256":digest(capsule), "previous_sha256":prefix.binding["original_tip"],
            "original":prefix.binding, "source_closure_sha256":digest(capsule["source_closure"]),
            "evidence_sha256":digest(evidence), "resume_gate":"STOP_BEFORE_SEQ05"}


def publication_ack(capsule,receipt):
    return {"schema":"task13_receipt_publication_v1","status":"AWAITING_ROOT_EXIT",
            "receipt_sha256":digest(receipt),"continuation_sha256":digest(capsule),"resume_gate":"STOP_BEFORE_SEQ05"}


def verify_receipt_candidate(prefix,capsule,receipt,evidence,publication=None):
    require(receipt == make_receipt(prefix,capsule,evidence), "canonical seq04 receipt mismatch")
    require(publication == publication_ack(capsule,receipt), "durable publication acknowledgement required")


def verify_continuation_receipt(prefix,capsule,receipt,evidence,publication=None,completion=None):
    verify_receipt_candidate(prefix,capsule,receipt,evidence,publication)
    require(type(completion) is dict and completion.get('schema')=='task13_root_completion_v1'
            and completion.get('status')=='ROOT_NORMAL_EXIT_OBSERVED','actual root completion required')
    require(set(completion)=={'schema','status','controller','supervisor_controller','root_pid','root_birth','exit_code','wait_result',
            'observed_exit_utc','observed_exit_mono_ns','stdout_b64','stderr_b64','stdout_sha256','stderr_sha256',
            'receipt_sha256','continuation_sha256','evidence_sha256','publication_sha256'},'exact root completion schema')
    integer(completion['root_pid'],1,2**32-1);integer(completion['root_birth'],1)
    require(completion['controller']==capsule['controller'] and completion['root_pid']==capsule['controller']['pid']
            and completion['root_birth']==capsule['controller']['birth'] and type(completion['exit_code']) is int
            and completion['exit_code']==0 and type(completion['wait_result']) is int and completion['wait_result']==0,
            'retained normal root exit required')
    from .authority import _identity
    supervisor=completion['supervisor_controller'];_identity(supervisor)
    require(supervisor['host_id']==capsule['controller']['host_id'] and supervisor['boot_id']==capsule['controller']['boot_id']
            and (supervisor['pid'],supervisor['birth'])!=(completion['root_pid'],completion['root_birth']),'independent local exit observer')
    require(instant(capsule['created_utc'])<=instant(completion['observed_exit_utc'])<instant(capsule['expires_utc'])
            and capsule['created_mono_ns']<=integer(completion['observed_exit_mono_ns'])<capsule['deadline_mono_ns']-2*10**9,
            'root publication completion outside authority')
    require(abs((instant(completion['observed_exit_utc'])-instant(capsule['created_utc'])).total_seconds()
                -(completion['observed_exit_mono_ns']-capsule['created_mono_ns'])/10**9)<=5,'root exit clocks diverged')
    stdout,stderr=raw_bytes(completion['stdout_b64']),raw_bytes(completion['stderr_b64'])
    require(stderr==b'' and sha256(stdout)==completion['stdout_sha256'] and sha256(stderr)==completion['stderr_sha256'],
            'actual retained root streams')
    expected={'status':'ROOT_PUBLICATION_READY','continuation_id':capsule['continuation_id'],'continuation_sha256':digest(capsule),
              'receipt_sha256':digest(receipt),'source_closure_sha256':digest(capsule['source_closure']),'resume_gate':'STOP_BEFORE_SEQ05'}
    require(parse_json(stdout.strip())==expected and completion['receipt_sha256']==digest(receipt)
            and completion['continuation_sha256']==digest(capsule) and completion['evidence_sha256']==digest(evidence)
            and completion['publication_sha256']==digest(publication),'root publication exact bytes binding')
