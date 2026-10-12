"""New recovery launch and native child settlement; no ordinary claim reuse."""
import base64
import subprocess
import time

from .codec import canonical,digest,parse_json,require,sha256
from .storage import ProtectedStore
from .transport import ContinuationTransport,utc,validate_command
from .loader import _reconcile
from .recovery_loader import reviewed_recovery,root_argv,create_live,ready_guard,require_budget
from .recovery_admission import require_unused_slot,slot_path,validate_launch_record,_commit_native,hold_slot
from .recovery_permission import verify_recovery_permission
from .recovery_receipt import verify_recovery_receipt
from . import windows

def settle_failed_child(process):
    """Settle a retained Popen child before releasing any reviewed holds."""
    result=dict(schema='task13_failed_child_settlement_v1',pid=process.pid,status='UNKNOWN',retry_allowed=False)
    try:
        # Termination precedes draining: a visible handshake may already have
        # allowed the child to proceed when its parent's durable write fails.
        try:process.kill()
        except OSError:pass  # Already exited is checked by the retained handle.
        stdout,stderr=process.communicate(timeout=5)
        native=windows.retained_process_exit(process._handle)
        require(native['wait_result']==0,'failed child did not settle')
        result.update(native,status='NATIVE_EXIT_OBSERVED',streams_complete=len(stdout)<=4096 and len(stderr)<=32768,
            stdout_sha256=sha256(stdout[:4096]),stderr_sha256=sha256(stderr[:32768]),
            observed_exit_utc=utc(),observed_exit_mono_ns=time.monotonic_ns())
    except Exception as error:result['error_type']=type(error).__name__
    return result

def supervise(root):
    with reviewed_recovery(root,'execution') as b:
        p,h,s=b['prefix'],b['history'],b['store'];require_unused_slot(p,h)
        auth=create_live(b,'launch');observer=windows.observe_controller();require_budget(auth,480)
        transport=ContinuationTransport(s,auth)
        preflight=_reconcile(p,auth,transport,b['operations'],b['entries']);s.create('launch-preflight.json',canonical(preflight))
        argv=root_argv(b['root'],b['control'],'--execute-recovery-v1-child')
        command=validate_command(argv);ready_guard(b,auth,preflight)
        launch=dict(schema='task13_recovery_launch_slot_v1',original=p.binding,history_sha256=digest(h),
            consumed_global_claim_sha256=h['global_claim_sha256'],protocol_version=1,
            protocol_source_sha256=b['closure']['protocol_source_sha256'],implementation_sha=b['closure']['implementation_sha'],
            continuation_id=b['closure']['continuation_id'],gate_sha256=digest(b['gate']),request_sha256=digest(b['request']),
            source_closure_sha256=digest(b['closure']),capsule_sha256=digest(auth.capsule),preflight_sha256=digest(preflight),
            expires_utc=b['request']['expires_utc'],controller=observer)
        validate_launch_record(p,h,launch)
        # First irreversible occupancy: all sources, packets, commands, actual
        # permission, fresh target predicates and full budget passed above.
        _commit_native(slot_path(p,h,'launch'),canonical(launch));hold_slot(b['held'],p,h,'launch',launch)
        s.create('recovery-launch.json',canonical(launch))
        process=None
        try:
            ready_guard(b,auth,preflight);require(validate_command(argv)==command,'final recovery root command binding changed')
            process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                cwd=b['root'],creationflags=0x08000000)
            birth=windows.process_birth(process._handle)
            s.create('recovery-child.json',canonical(dict(schema='task13_recovery_child_identity_v1',pid=process.pid,birth=birth,
                supervisor=observer,launch_slot_sha256=digest(launch))))
            timed_out=False
            try:stdout,stderr=process.communicate(timeout=min(1100,max(1,(auth.capsule['deadline_mono_ns']-time.monotonic_ns())/10**9-2)))
            except subprocess.TimeoutExpired:
                timed_out=True;process.kill();stdout,stderr=process.communicate(timeout=5)
            native=windows.retained_process_exit(process._handle);exit_utc,exit_ns=utc(),time.monotonic_ns()
            require(windows.observe_controller()==observer,'recovery supervisor identity changed')
            bounded=len(stdout)<=4096 and len(stderr)<=32768
            s.create('root-transport.json',canonical(dict({'pid':process.pid,'birth':birth},**native,
                stdout_b64=base64.b64encode(stdout[:4096]).decode(),stderr_b64=base64.b64encode(stderr[:32768]).decode(),
                stdout_sha256=sha256(stdout[:4096]),stderr_sha256=sha256(stderr[:32768]),streams_complete=bounded,
                timed_out=timed_out,observed_exit_utc=exit_utc,observed_exit_mono_ns=exit_ns)))
            require(bounded and not timed_out and native['exit_code']==0 and native['birth']==birth and not stderr,
                'actual recovery root complete normal exit required')
            require(not (b['root']/'recovery-unknown.json').exists(),'recovery UNKNOWN cannot publish canonical acceptance')
            auth.check();verify_recovery_permission(b['request'],b['gate'])
            capsule=parse_json(s.read('execution-capsule.json'));evidence=parse_json(s.read('execution-evidence.json'))
            receipt=parse_json(s.read('receipt-04-compare-after-start.json'));publication=parse_json(s.read('resume-gate.json'))
            completion=dict(schema='task13_root_completion_v1',status='ROOT_NORMAL_EXIT_OBSERVED',controller=capsule['controller'],
                supervisor_controller=observer,root_pid=process.pid,root_birth=birth,exit_code=native['exit_code'],wait_result=native['wait_result'],
                observed_exit_utc=exit_utc,observed_exit_mono_ns=exit_ns,stdout_b64=base64.b64encode(stdout).decode(),stderr_b64=base64.b64encode(stderr).decode(),
                stdout_sha256=sha256(stdout),stderr_sha256=sha256(stderr),receipt_sha256=digest(receipt),continuation_sha256=digest(capsule),
                evidence_sha256=digest(evidence),publication_sha256=digest(publication))
            verify_recovery_receipt(p,capsule,receipt,evidence,publication,completion)
            s.publish('root-completion.json',canonical(completion))
            verify_recovery_receipt(p,capsule,parse_json(s.read('receipt-04-compare-after-start.json')),evidence,
                parse_json(s.read('resume-gate.json')),parse_json(s.read('root-completion.json')))
            return dict(status='PASS',continuation_id=capsule['continuation_id'],receipt_sha256=digest(receipt),
                source_closure_sha256=digest(b['closure']),resume_gate='STOP_BEFORE_SEQ05')
        except Exception as error:
            if process is not None:
                s.create('recovery-child-failure-settlement.json',canonical(settle_failed_child(process)))
            s.create('recovery-supervisor-unknown.json',canonical(dict(status='UNKNOWN',error_type=type(error).__name__,
                slot_consumed=True,retry_allowed=False)))
            raise
