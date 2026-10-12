"""Native read-only settlement and independently reviewed admission gate."""
import base64
import subprocess
import time
from pathlib import Path

from .codec import canonical,digest,instant,parse_json,require,sha256
from .history import read_file,verify_historical_prefix,_relative
from .loader import _hold_file
from .receipt import raw_bytes,observation
from .reconciliation import validate_state
from .storage import ProtectedStore
from .transport import utc,validate_command
from .recovery_admission import capture_history,protocol_sources,slot_state
from . import windows

FILES=('closure.json','review.json','recovery-review.json','trust.json','control.json','recovery-history.json',
       'read-only-admission/window.json','read-only-admission/preflight.json','read-only-admission/gate.json',
       'read-only-native-exit.json','admission-review.json')

def run_observation(root):
    from .recovery_loader import reviewed_recovery,root_argv
    with reviewed_recovery(root,'observation',external_observer=True) as b:
        argv=root_argv(b['root'],b['control'],'--observe-recovery-v1');command=validate_command(argv)
        identity=windows.observe_controller()
        require(validate_command(argv)==command,'exact read-only launch command changed')
        process=None
        try:
            process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                cwd=b['root'],creationflags=0x08000000);birth=windows.process_birth(process._handle);timed_out=False
            try:stdout,stderr=process.communicate(timeout=480)
            except subprocess.TimeoutExpired:
                timed_out=True;process.kill();stdout,stderr=process.communicate(timeout=5)
            native=windows.retained_process_exit(process._handle)
            require(windows.observe_controller()==identity,'read-only native observer identity changed')
            complete=len(stdout)<=16384 and len(stderr)<=32768
            row=dict({'schema':'task13_recovery_readonly_native_exit_v1','pid':process.pid,'birth':birth},**native,
                observer=identity,streams_complete=complete,timed_out=timed_out,observed_exit_utc=utc(),observed_exit_mono_ns=time.monotonic_ns(),
                stdout_b64=base64.b64encode(stdout[:16384]).decode(),stderr_b64=base64.b64encode(stderr[:32768]).decode(),
                stdout_sha256=sha256(stdout[:16384]),stderr_sha256=sha256(stderr[:32768]))
            b['store'].create('read-only-native-exit.json',canonical(row))
            require(complete and not timed_out and native['exit_code']==0 and native['birth']==birth and not stderr,
                'read-only admission root did not complete normally')
            return dict(status='NATIVE_READONLY_EXIT_VERIFIED_AWAITING_INDEPENDENT_REVIEW',native_exit_sha256=digest(row),
                source_closure_sha256=digest(b['closure']),seq04_authorized=False,claims_created=False)
        except Exception:
            if process is not None:
                from .recovery_supervisor import settle_failed_child
                b['store'].create('read-only-child-failure-settlement.json',canonical(settle_failed_child(process)))
            raise

def _root(gate):
    name=gate.get('evidence_bundle')
    require(type(name) is str and Path(name).name==name and name.startswith('task13-additive-recovery-')
        and not any(c in name for c in '\\/:') and not name.endswith(('.', ' ')),'fixed admission evidence namespace')
    return Path.home()/'.codex/task-evidence'/name

def _read(root,name):
    path=root/name;return ProtectedStore(path.parent).read(path.name)

def _verify_records(root):
    raw={n:_read(root,n) for n in FILES};data={n:parse_json(v) for n,v in raw.items()}
    closure,review,extra,trust=(data[n+'.json'] for n in ('closure','review','recovery-review','trust'))
    from .authority import REVIEW_SCOPE
    from .recovery_bundle import RECOVERY_SCOPE
    require(closure['mode']=='observation' and review['status']=='PASS' and review['scope']==REVIEW_SCOPE
        and extra['status']=='PASS' and extra['scope']==RECOVERY_SCOPE
        and digest(closure)==review['source_closure_sha256']==extra['source_closure_sha256']==trust['source_closure_sha256']
        and digest(review)==trust['review_sha256'] and digest(extra)==trust['recovery_review_sha256'],'read-only independent source review')
    entries={}
    for n,spec in closure['execution']['entries'].items():
        value=_read(root,_relative(n).as_posix());require(len(value)==spec['bytes'] and sha256(value)==spec['sha256'],'read-only admission source pin changed')
        entries[n]=value
    require(protocol_sources(entries)==closure['protocol_source_sha256'],'read-only protocol source pin changed')
    for n,spec in closure['runtime'].items():
        path=Path(n)
        with windows.retained(path,security=False,expected_links=spec.get('hardlink_count',1)) as handle:
            value=windows.read_handle(handle,path,expected_links=spec.get('hardlink_count',1))
        require(len(value)==spec['bytes'] and sha256(value)==spec['sha256'],'read-only admission runtime pin changed')
    window=data['read-only-admission/window.json'];preflight=data['read-only-admission/preflight.json']
    provisional=data['read-only-admission/gate.json'];outer=data['read-only-native-exit.json'];audit=data['admission-review.json']
    require(provisional['status']=='PREFLIGHT_VERIFIED_AWAITING_NATIVE_EXIT_REVIEW' and provisional['slot_state']=='ABSENT'
        and provisional['seq04_authorized'] is False and provisional['seq04_dispatched'] is False and provisional['claims_created'] is False
        and provisional['source_closure_sha256']==digest(closure) and provisional['preflight_sha256']==digest(preflight)
        and provisional['window_sha256']==digest(window),'read-only actual preflight binding')
    require(outer['schema']=='task13_recovery_readonly_native_exit_v1' and outer['pid']==window['controller']['pid']
        and outer['birth']==window['controller']['birth'] and type(outer['exit_code']) is int and outer['exit_code']==0
        and type(outer['wait_result']) is int and outer['wait_result']==0
        and outer['streams_complete'] is True and outer['timed_out'] is False,'actual settled read-only native root')
    stdout,stderr=(raw_bytes(outer[n+'_b64']) for n in ('stdout','stderr'))
    require(not stderr and sha256(stdout)==outer['stdout_sha256'] and sha256(stderr)==outer['stderr_sha256']
        and parse_json(stdout.strip())==provisional,'complete actual read-only root verdict bytes')
    require(instant(window['created_utc'])<=instant(preflight['finished_utc'])<=instant(provisional['checked_utc'])
        <=instant(outer['observed_exit_utc'])<instant(window['expires_utc']),'read-only admission chronology')
    require(audit['schema']=='task13_recovery_admission_review_v1' and audit['status']=='PASS'
        and audit['source_closure_sha256']==digest(closure) and audit['protocol_source_sha256']==closure['protocol_source_sha256']
        and audit['implementation_sha']==closure['implementation_sha'] and audit['provisional_gate_sha256']==digest(provisional)
        and audit['native_exit_sha256']==digest(outer) and audit['preflight_sha256']==digest(preflight)
        and audit['history_sha256']==provisional['history_sha256'] and audit['seq04_authorized'] is False
        and audit['claims_created'] is False,'independent complete admission review PASS required')
    require((audit['reviewer_controller']['pid'],audit['reviewer_controller']['birth']) not in
        ((outer['pid'],outer['birth']),(outer['observer']['pid'],outer['observer']['birth'])),'independent admission reviewer process')
    control=data['control.json'];prefix=verify_historical_prefix(Path(control['original_root']))
    require(prefix.binding==closure['original_binding'] and digest(prefix.binding)==provisional['original_binding_sha256'],
        'admission original binding changed')
    history=data['recovery-history.json'];require(capture_history(prefix)==history and digest(history)==provisional['history_sha256'],
        'admission old consumed history changed')
    validate_state(prefix,window,observation(preflight,window,maximum=60),preflight['finished_utc'])
    final=dict(provisional,status='READY_REQUIRES_SEPARATE_AUTHORIZATION',provisional_gate_sha256=digest(provisional),
        native_exit_sha256=digest(outer),admission_review_sha256=digest(audit))
    return final,dict(schema='task13_verified_recovery_gate_evidence_v1',files_sha256={n:sha256(v) for n,v in raw.items()},
        original_binding_sha256=digest(prefix.binding),history_sha256=digest(history))

def finalize_gate(root):
    root=Path(root).absolute();gate,proof=_verify_records(root)
    require(_root(gate)==root,'fixed admission bundle root')
    ProtectedStore(root).create('final-gate.json',canonical(gate))
    return dict(status=gate['status'],gate_sha256=digest(gate),evidence_sha256=digest(proof),claims_created=False)

def capture_verified_gate(gate):
    require(gate.get('schema')=='task13_additive_recovery_gate_v1' and gate.get('status')=='READY_REQUIRES_SEPARATE_AUTHORIZATION',
        'complete independently reviewed read-only admission required')
    root=_root(gate);actual,proof=_verify_records(root)
    require(actual==gate and parse_json(ProtectedStore(root).read('final-gate.json'))==gate,'exact final admission gate')
    return proof

def hold_gate(stack,gate,expected):
    root=_root(gate)
    for parent in reversed((root,*root.parents)):stack.enter_context(windows.retained(parent,directory=True,protected=parent==root,security=parent==root))
    stack.enter_context(windows.retained(root/'read-only-admission',directory=True,protected=True))
    for n,pin in expected['files_sha256'].items():
        path=root/n;raw=_read(root,n);_hold_file(stack,path,dict(bytes=len(raw),sha256=pin),protected=True)
    raw=ProtectedStore(root).read('final-gate.json');_hold_file(stack,root/'final-gate.json',dict(bytes=len(raw),sha256=digest(gate)),protected=True)
    closure=parse_json(_read(root,'closure.json'))
    for n,spec in closure['execution']['entries'].items():
        path=root/_relative(n)
        for parent in reversed((path.parent,*path.parent.parents)):
            if root in parent.parents:stack.enter_context(windows.retained(parent,directory=True,protected=True))
        _hold_file(stack,path,spec,protected=True)
    require(capture_verified_gate(gate)==expected,'held final admission evidence changed')
