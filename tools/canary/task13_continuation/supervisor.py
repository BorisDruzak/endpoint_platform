"""Local kernel exit witness for the reviewed root; never dispatches to a target."""
import base64
import subprocess
import sys
import time
from pathlib import Path

from .codec import canonical,digest,parse_json,require,sha256
from .loader import reviewed_bundle
from .receipt import verify_continuation_receipt
from .transport import utc
from .recovery import claim_recovery_launch
from .permission import require_seq04_permission
from . import windows


def verify_published(store,prefix,capsule,evidence):
    require(not any((store.root/name).exists() for name in ('unknown.json','supervisor-unknown.json')),
            'UNKNOWN terminal publication cannot be accepted')
    receipt=parse_json(store.read('receipt-04-compare-after-start.json'))
    publication=parse_json(store.read('resume-gate.json'))
    completion=parse_json(store.read('root-completion.json'))
    verify_continuation_receipt(prefix,capsule,receipt,evidence,publication,completion)
    return receipt


def supervise(root):
    root=Path(root).absolute()
    require(Path(sys.argv[0]).absolute()==root/'bootstrap.py' and sys.argv[1:]==['--execute-reviewed-seq04'],
            'fixed reviewed supervisor entry')
    with reviewed_bundle(root) as (store,closure,review,detached,entries,prefix,request,operations,control):
        require_seq04_permission(request)
        observer=windows.observe_controller()
        executable=control['root_interpreter']
        require(str(Path(executable).absolute())==executable and executable in closure['runtime'],
                'direct reviewed root interpreter')
        argv=[executable,'-I','-S','-B','-X','pycache_prefix='+str(root/'no-pyc'),str(root/'bootstrap.py'),'--execute-reviewed-seq04-child']
        store.create('root-launch-claim.json',canonical({'schema':'task13_root_launch_intent_v1',
                                                       'argv_sha256':digest(argv),'observer':observer}))
        try:
            claim_recovery_launch(prefix,closure)
            process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                     cwd=root,creationflags=0x08000000)
            birth=windows.process_birth(process._handle)
            # Child source emits only a bounded final record or exception trace.
            # SSH/native work has its own shorter bounds and independent watchdog.
            timed_out=False
            try:
                stdout,stderr=process.communicate(timeout=1300)
            except subprocess.TimeoutExpired:
                timed_out=True
                process.kill();stdout,stderr=process.communicate(timeout=5)
            native=windows.retained_process_exit(process._handle)
            exit_utc,exit_ns=utc(),time.monotonic_ns()
            require(windows.observe_controller()==observer,'local exit observer identity changed')
            bounded=len(stdout)<=4096 and len(stderr)<=32768
            store.create('root-transport.json',canonical({'pid':process.pid,'birth':birth,**native,
                'stdout_b64':base64.b64encode(stdout[:4096]).decode(),'stderr_b64':base64.b64encode(stderr[:32768]).decode(),
                'stdout_sha256':sha256(stdout[:4096]),'stderr_sha256':sha256(stderr[:32768]),
                'streams_complete':bounded,'timed_out':timed_out,
                'observed_exit_utc':exit_utc,'observed_exit_mono_ns':exit_ns}))
            require(bounded and not timed_out,'root stream/timeout UNKNOWN')
            require(native['exit_code']==0 and native['birth']==birth and not stderr,'root normal exit required')
            require(not (root/'unknown.json').exists(),'root UNKNOWN publication')
            capsule=parse_json(store.read('capsule.json'));evidence=parse_json(store.read('execution-evidence.json'))
            receipt=parse_json(store.read('receipt-04-compare-after-start.json'));publication=parse_json(store.read('resume-gate.json'))
            completion={'schema':'task13_root_completion_v1','status':'ROOT_NORMAL_EXIT_OBSERVED',
                'controller':capsule['controller'],'supervisor_controller':observer,
                'root_pid':process.pid,'root_birth':birth,'exit_code':native['exit_code'],'wait_result':native['wait_result'],
                'observed_exit_utc':exit_utc,'observed_exit_mono_ns':exit_ns,
                'stdout_b64':base64.b64encode(stdout).decode(),'stderr_b64':base64.b64encode(stderr).decode(),
                'stdout_sha256':sha256(stdout),'stderr_sha256':sha256(stderr),
                'receipt_sha256':digest(receipt),'continuation_sha256':digest(capsule),
                'evidence_sha256':digest(evidence),'publication_sha256':digest(publication)}
            verify_continuation_receipt(prefix,capsule,receipt,evidence,publication,completion)
            store.publish('root-completion.json',canonical(completion))
            verify_published(store,prefix,capsule,evidence)
            return {'status':'PASS','continuation_id':capsule['continuation_id'],'continuation_sha256':digest(capsule),
                    'receipt_sha256':digest(receipt),'source_closure_sha256':digest(closure),'resume_gate':'STOP_BEFORE_SEQ05'}
        except Exception as error:
            store.create('supervisor-unknown.json',canonical({'status':'UNKNOWN','error_type':type(error).__name__,
                                                            'retry_allowed':False}))
            raise
