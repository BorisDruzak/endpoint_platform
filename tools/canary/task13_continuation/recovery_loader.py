"""Separate additive recovery creator and read-only gate; ordinary loader unchanged."""
import base64
import sys
import time
from contextlib import ExitStack,contextmanager
from datetime import datetime,timezone,timedelta
from pathlib import Path

from .authority import create_capsule,LiveAuthorization,REVIEW_SCOPE
from .codec import canonical,digest,instant,parse_json,require,sha256
from .history import _relative,verify_historical_prefix
from .loader import _hold_file,_reconcile,guard_dispatch
from .receipt import observation,raw_bytes,publication_ack
from .sources import seal_sources
from .storage import ProtectedStore
from .transport import ContinuationTransport,TransportUnknown,utc,envelope
from .reconciliation import validate_state
from .readonly_gate import ReadOnlyWindow
from .recovery_admission import (capture_history,hold_history,protocol_sources,require_unused_slot,slot_state,
    slot_path,validate_launch_record,validate_dispatch_record,_commit_native,hold_slot,BASE_REVISION,OLD_CLAIMS)
from .recovery_bundle import verify_feasibility,RECOVERY_SCOPE
from .recovery_permission import _latest_actual_message,PREFIX
from .recovery_permission_v2 import verify_recovery_permission,capture_consent,MODE,ADMISSION_SECONDS,CONSENT_SECONDS
from . import windows

class RecoveryAuthorization:
    def __init__(self,base,request):self.base,self.request=base,parse_json(canonical(request))
    @property
    def capsule(self):return self.base.capsule
    def check(self):
        self.base.check()
        require(datetime.now(timezone.utc)<instant(self.request['expires_utc']),'recovery authorization expired')

def require_budget(auth,seconds):
    auth.check();c=auth.capsule
    require(time.monotonic_ns()+seconds*10**9<c['deadline_mono_ns']-2*10**9,'insufficient full recovery budget')
    end=min(instant(c['expires_utc']),instant(auth.request['expires_utc'])) if isinstance(auth,RecoveryAuthorization) else instant(c['expires_utc'])
    require(datetime.now(timezone.utc)+timedelta(seconds=seconds)<end,'insufficient authorized recovery budget')

def root_argv(root,control,flag):
    return [control['root_interpreter'],'-I','-S','-B','-X','pycache_prefix='+str(root/'no-pyc'),str(root/'bootstrap.py'),flag]

def entry_flag(control,stage):
    require(stage in ('observe','execute','execute-child'),'fixed recovery stage')
    suffix='-child' if stage=='execute-child' else ''
    action='observe' if stage=='observe' else 'execute'
    return '--'+action+'-recovery-v'+str(control['protocol_version'])+suffix

@contextmanager
def reviewed_recovery(root,mode,*,external_observer=False):
    root=Path(root).absolute();store=ProtectedStore(root)
    require((external_observer is True and mode=='observation') or (Path(__file__).absolute()==root/'tools/canary/task13_continuation/recovery_loader.py'
        and sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
        and sys.pycache_prefix==str(root/'no-pyc')),'only isolated held recovery bundle code may operate')
    with ExitStack() as held:
        for parent in reversed((root,*root.parents)):
            held.enter_context(windows.retained(parent,directory=True,protected=parent==root,security=parent==root))
        closure,review,extra,trust=(parse_json(store.read(n+'.json')) for n in ('closure','review','recovery-review','trust'))
        require(set(trust)=={'schema','source_closure_sha256','review_sha256','recovery_review_sha256','bootstrap_sha256','reviewer_controller'}
            and trust['schema']=='task13_recovery_review_trust_v1','exact detached recovery trust')
        require(closure['schema']=='task13_recovery_reviewed_closure_v1' and closure['mode']==mode
            and review['schema']=='task13_source_review_v1' and review['status']=='PASS' and review['scope']==REVIEW_SCOPE
            and extra['schema']=='task13_recovery_source_review_v1' and extra['status']=='PASS' and extra['scope']==RECOVERY_SCOPE
            and digest(closure)==review['source_closure_sha256']==extra['source_closure_sha256']==trust['source_closure_sha256']
            and digest(review)==trust['review_sha256'] and digest(extra)==trust['recovery_review_sha256']
            and extra['protocol_source_sha256']==closure['protocol_source_sha256']
            and extra['implementation_sha']==closure['implementation_sha'],'independent recovery source review PASS required')
        for n in ('closure','review','recovery-review','trust'):
            raw=store.read(n+'.json');_hold_file(held,root/(n+'.json'),dict(bytes=len(raw),sha256=sha256(raw)),protected=True)
        entries={};dirs={root/Path(n).parent for n in closure['execution']['entries']}
        for parent in sorted({p for d in dirs for p in (d,*d.parents) if root in p.parents},key=lambda p:len(p.parts)):
            held.enter_context(windows.retained(parent,directory=True,protected=True))
        for n,spec in closure['execution']['entries'].items():entries[n]=_hold_file(held,root/_relative(n),spec,protected=True)
        require(seal_sources(entries)==closure['execution'] and protocol_sources(entries)==closure['protocol_source_sha256']
            and sha256(entries['bootstrap.py'])==trust['bootstrap_sha256'],'exact held recovery source closure')
        require(entries['tools/canary/Read-Task13SealedPacket.ps1']==entries['Read-Task13SealedPacket.ps1'],'closed verifier mirror')
        for parent in sorted({p for n in closure['runtime'] for p in Path(n).parents},key=lambda p:len(p.parts)):
            held.enter_context(windows.retained(parent,directory=True,security=False))
        for n,spec in closure['runtime'].items():_hold_file(held,Path(n),spec,runtime=True)
        require(not (root/'no-pyc').exists(),'unreviewed bytecode cache forbidden')
        control=parse_json(entries['control.json']);original=Path(control['original_root'])
        require(control['schema']=='task13_recovery_control_v1' and control['mode']==mode
            and type(control['protocol_version']) is int and control['protocol_version'] in (1,2)
            and control['baseline_revision']==BASE_REVISION and control['implementation_sha']==closure['implementation_sha']
            and Path(control['claim_home'])==original/'continuation-v1-claims','canonical additive recovery control')
        if not external_observer:
            allowed=(entry_flag(control,'observe'),) if mode=='observation' else (entry_flag(control,'execute'),entry_flag(control,'execute-child'))
            require(len(sys.argv)==2 and Path(sys.argv[0]).absolute()==root/'bootstrap.py'
                and sys.argv[1] in allowed,'actual recovery entry/control version mismatch')
        require(str(Path(sys._base_executable).absolute())==control['root_interpreter'],'actual closed recovery interpreter')
        prefix=verify_historical_prefix(original);history=parse_json(entries['recovery-history.json'])
        require(prefix.binding==control['original_binding']==closure['original_binding'],'immutable recovery prefix')
        hold_history(held,prefix,history)
        identity=windows.observe_controller()
        require((identity['pid'],identity['birth'])!=(trust['reviewer_controller']['pid'],trust['reviewer_controller']['birth']),
            'independent recovery reviewer process required')
        operations=parse_json(entries['operations.json'])
        flag=entry_flag(control,'observe' if mode=='observation' else 'execute-child')
        verify_feasibility(prefix,closure,entries,operations,root_argv(root,control,flag))
        if control['protocol_version']==2:
            require(parse_json(entries['human-consent.json'])==capture_consent(),'held natural consent changed or replayed')
        request=gate=None
        if mode=='execution':
            from .recovery_gate import capture_verified_gate,hold_gate
            request=parse_json(entries['operator-request.json']);gate=parse_json(entries['admission-gate.json'])
            require(gate.get('protocol_version',1)==control['protocol_version']
                and request['schema']=='task13_actual_recovery_execution_request_v'+str(control['protocol_version']),
                'exact recovery permission/control protocol version')
            verify_recovery_permission(request,gate)
            admission=capture_verified_gate(gate);hold_gate(held,gate,admission)
            require(admission==parse_json(entries['admission-evidence.json']),'exact independently settled read-only admission')
            require(gate['history_sha256']==digest(history) and gate['original_binding_sha256']==digest(prefix.binding)
                and gate['implementation_sha']==closure['implementation_sha'] and gate['protocol_source_sha256']==closure['protocol_source_sha256']
                and gate['continuation_id']==closure['continuation_id'] and gate['slot_state']=='ABSENT'
                and gate['claims_created'] is False and gate['seq04_dispatched'] is False
                and gate['preflight_verified'] is True,'complete original read-only admission gate')
        yield dict(root=root,store=store,closure=closure,review=review,trust=trust,entries=entries,prefix=prefix,
            history=history,operations=operations,control=control,request=request,gate=gate,held=held)

def fresh_previous(history):
    identity=windows.observe_controller();old=history['prior_controller']
    require(all(identity[k]==old[k] for k in ('host_id','boot_id','token_sid','elevated')),'recovery creator host/boot/token changed')
    dispositions={n:windows.confirm_process_gone(history[n]['pid'],history[n]['birth']) for n in ('prior_root','prior_supervisor')}
    require(all(v in ('ABSENT','PID_REUSED','EXACT_PROCESS_EXITED') for v in dispositions.values()),'prior creator termination UNKNOWN')
    return dispositions

def create_live(b,label):
    identity=windows.observe_controller();closure,request=b['closure'],b['request']
    authority=dict(schema='task13_operator_authority_v1',original=b['prefix'].binding,allowed_seq=4,allowed_step='compare-after-start',
        controller=identity,source_closure_sha256=digest(closure),bootstrap_sha256=b['trust']['bootstrap_sha256'],
        request_sha256=digest(request),request_reference='actual-app-session-recovery-message')
    capsule=create_capsule(b['prefix'],closure,authority,b['review'],identity)
    attestation=dict(schema='task13_creator_attestation_v1',capsule_sha256=digest(capsule),authority_sha256=digest(authority),controller=identity)
    trusted=dict(authority_sha256=digest(authority),attestation_sha256=digest(attestation),
        review_sha256=digest(b['review']),bootstrap_sha256=b['trust']['bootstrap_sha256'],
        source_closure_sha256=digest(closure),request_sha256=digest(request))
    auth=RecoveryAuthorization(LiveAuthorization(capsule,authority,attestation,b['review'],trusted,identity),request)
    for n,v in (('capsule',capsule),('authority',authority),('attestation',attestation),('trust',trusted)):
        b['store'].create(label+'-'+n+'.json',canonical(v))
    return auth

def ready_guard(b,auth,preflight,seconds=420):
    auth.check();verify_recovery_permission(b['request'],b['gate']);require_budget(auth,seconds)
    require(capture_history(b['prefix'])==b['history'],'preclaim historical identities changed');fresh_previous(b['history'])
    plan=verify_feasibility(b['prefix'],b['closure'],b['entries'],b['operations'],root_argv(b['root'],b['control'],entry_flag(b['control'],'execute-child')))
    state=observation(preflight,auth.capsule,maximum=60);validate_state(b['prefix'],auth.capsule,state,utc())
    guard=guard_dispatch(b['prefix'],auth,preflight);guard(utc())
    return plan

def observe(root):
    with reviewed_recovery(root,'observation') as b:
        identity=windows.observe_controller();auth=ReadOnlyWindow(identity);history=b['history']
        out=ProtectedStore.create_root(b['root']/'read-only-admission');out.create('window.json',canonical(auth.capsule))
        initial=slot_state(b['prefix'],history);fresh_previous(history)
        plan=verify_feasibility(b['prefix'],b['closure'],b['entries'],b['operations'],root_argv(b['root'],b['control'],entry_flag(b['control'],'observe')))
        require_budget(auth,420);result=_reconcile(b['prefix'],auth,ContinuationTransport(out,auth),b['operations'],b['entries'])
        out.create('preflight.json',canonical(result));auth.check()
        require(capture_history(b['prefix'])==history and slot_state(b['prefix'],history)==initial,'observation changed historical state/slot')
        gate=dict(schema='task13_additive_recovery_gate_v1',status='PREFLIGHT_VERIFIED_AWAITING_NATIVE_EXIT_REVIEW' if initial=='ABSENT' else 'BLOCKED_SLOT_OCCUPIED',
            implementation_sha=b['closure']['implementation_sha'],protocol_version=b['control']['protocol_version'],protocol_source_sha256=b['closure']['protocol_source_sha256'],
            source_closure_sha256=digest(b['closure']),review_sha256=digest(b['review']),recovery_review_sha256=b['trust']['recovery_review_sha256'],
            original_binding_sha256=digest(b['prefix'].binding),history_sha256=digest(history),consumed_claims_sha256=dict(OLD_CLAIMS),
            continuation_id=b['closure']['continuation_id'],allowed_seq=4,allowed_step='compare-after-start',
            checked_utc=utc(),preflight_sha256=digest(result),preflight_verified=True,slot_state=initial,command_plan=plan,
            window_sha256=digest(auth.capsule),seq04_authorized=False,seq04_dispatched=False,claims_created=False,
            historical_rca='UNKNOWN',runtime_changed=False,resume_gate='STOP_BEFORE_SEQ04_AUTHORIZATION')
        gate['evidence_bundle']=b['root'].name
        if b['control']['protocol_version']==2:
            gate.update(authorization_mode=MODE,consent_sha256=digest(parse_json(b['entries']['human-consent.json'])),
                admission_validity_seconds=ADMISSION_SECONDS,consent_validity_seconds=CONSENT_SECONDS)
        out.create('gate.json',canonical(gate));return gate

def _parent_live(identity):
    kernel=windows.api()[0];handle=kernel.OpenProcess(0x1000|0x100000,False,identity['pid'])
    require(bool(handle),'recovery supervisor native identity unavailable')
    try:
        require(windows.process_birth(handle)==identity['birth'] and kernel.WaitForSingleObject(handle,0)==258,
            'recovery supervisor absent/exited/PID reused')
    finally:kernel.CloseHandle(handle)

def child_registration(b,launch):
    deadline=time.monotonic()+5
    while not (b['root']/'recovery-child.json').exists() and time.monotonic()<deadline:
        _parent_live(launch['controller']);time.sleep(.02)
    row=parse_json(b['store'].read('recovery-child.json'));identity=windows.observe_controller()
    require(row['schema']=='task13_recovery_child_identity_v1' and row['launch_slot_sha256']==digest(launch)
        and row['pid']==identity['pid'] and row['birth']==identity['birth'] and row['supervisor']==launch['controller'],
        'exact independently retained recovery child identity')
    require(all(identity[k]==launch['controller'][k] for k in ('host_id','boot_id','token_sid','elevated')),'recovery child controller changed')
    _parent_live(launch['controller'])
    _hold_file(b['held'],b['root']/'recovery-child.json',dict(bytes=len(canonical(row)),sha256=digest(row)),protected=True)

def run_child(root):
    from .recovery_receipt import make_recovery_receipt,verify_recovery_candidate
    with reviewed_recovery(root,'execution') as b:
        p,h,s=b['prefix'],b['history'],b['store']
        launch=parse_json(ProtectedStore(slot_path(p,h,'launch').parent).read(slot_path(p,h,'launch').name))
        validate_launch_record(p,h,launch);hold_slot(b['held'],p,h,'launch',launch)
        require(launch['request_sha256']==digest(b['request']) and launch['source_closure_sha256']==digest(b['closure'])
            and launch['continuation_id']==b['closure']['continuation_id'],'launched recovery owner')
        child_registration(b,launch);auth=create_live(b,'execution');transport=ContinuationTransport(s,auth)
        preclaim=_reconcile(p,auth,transport,b['operations'],b['entries']);s.create('preclaim-preflight.json',canonical(preclaim))
        ready_guard(b,auth,preclaim)
        dispatch=dict(schema='task13_recovery_dispatch_slot_v1',launch_slot_sha256=digest(launch),continuation_id=b['closure']['continuation_id'],
            original=p.binding,protocol_version=b['control']['protocol_version'],protocol_source_sha256=b['closure']['protocol_source_sha256'],
            consumed_global_claim_sha256=h['global_claim_sha256'],capsule_sha256=digest(auth.capsule),preflight_sha256=digest(preclaim))
        validate_dispatch_record(p,h,launch,dispatch)
        _commit_native(slot_path(p,h,'dispatch'),canonical(dispatch));hold_slot(b['held'],p,h,'dispatch',dispatch)
        s.create('recovery-dispatch.json',canonical(dispatch))
        try:
            ready_guard(b,auth,preclaim)
            ready=transport.powershell(b['operations']['guest_ssh'],b['entries']['delivery-prepare.ps1'].decode(),'prepare',25,b['entries']['packet-prepare.bin'])
            value=observation(ready,auth.capsule,maximum=25)
            require(value['status']=='INDEPENDENT_WATCHDOG_READY' and value['run']==auth.capsule['continuation_id']
                and value['watchdog_sha256']==sha256(b['entries']['Watch-Task13DiagnosticProcess.ps1']),'independent watchdog preparation')
            preflight=_reconcile(p,auth,transport,b['operations'],b['entries']);s.create('dispatch-preflight.json',canonical(preflight))
            def final_guard():
                ready_guard(b,auth,preflight,225);_parent_live(launch['controller'])
                return guard_dispatch(p,auth,preflight)
            try:
                guest=transport.powershell(b['operations']['guest_ssh'],b['entries']['delivery-workload.ps1'].decode(),'compare-after-start',145,
                    b['entries']['packet-workload.bin'],pre_dispatch=final_guard)
            except TransportUnknown:
                try:
                    retained=transport.powershell(b['operations']['guest_ssh'],b['entries']['delivery-collect.ps1'].decode(),'failure-settlement',15,b['entries']['packet-collect.bin'])
                    s.create('failure-retained-collection.json',canonical(retained))
                except Exception:pass
                raise
            collected=transport.powershell(b['operations']['guest_ssh'],b['entries']['delivery-collect.ps1'].decode(),'settlement',15,b['entries']['packet-collect.bin'])
            result=observation(collected,auth.capsule,maximum=15);files={n:raw_bytes(v) for n,v in result['files'].items()}
            row=parse_json(files['identity.json']);identity={k:row[k] for k in ('run','pid','birth')};exit_row=parse_json(files['exit-confirmed.json'])
            require(exit_row['pid']==identity['pid'] and exit_row['birth']==identity['birth'],'watchdog identity')
            watchdog=envelope(canonical(dict(exit_row,run=identity['run'])),b'',0,collected['dispatch_utc'],collected['dispatch_mono_ns'],collected['finished_utc'],collected['finished_mono_ns'],True)
            watchdog['retained_transport_sha256']=digest(collected);postflight=_reconcile(p,auth,transport,b['operations'],b['entries'])
            evidence=dict(schema='task13_recovery_execution_evidence_v1',continuation_id=auth.capsule['continuation_id'],
                source_closure_sha256=digest(b['closure']),preflight=preflight,postflight=postflight,guest=guest,watchdog=watchdog,identity=identity,
                journal_b64=base64.b64encode(files['stages.jsonl']).decode(),journal_sha256=sha256(files['stages.jsonl']),retained_collection=collected,
                watchdog_preparation=ready,recovery_history=h,recovery_launch_slot=launch,recovery_dispatch_slot=dispatch,
                historical_consumed_claims={n:base64.b64encode(ProtectedStore(p.root/'continuation-v1-claims').read(n)).decode() for n in OLD_CLAIMS},
                recovery_authorization=b['request'],admission_gate=b['gate'],preclaim_preflight=preclaim,
                launch_capsule=parse_json(s.read('launch-capsule.json')),launch_preflight=parse_json(s.read('launch-preflight.json')))
            auth.check();verify_recovery_permission(b['request'],b['gate']);require(capture_history(p)==h,'historical preservation after workload')
            receipt=make_recovery_receipt(p,auth.capsule,evidence);s.create('execution-evidence.json',canonical(evidence))
            auth.check();s.publish('receipt-04-compare-after-start.json',canonical(receipt));auth.check()
            publication=publication_ack(auth.capsule,receipt);s.create('resume-gate.json',canonical(publication))
            verify_recovery_candidate(p,auth.capsule,parse_json(s.read('receipt-04-compare-after-start.json')),evidence,publication)
            return dict(status='ROOT_PUBLICATION_READY',continuation_id=auth.capsule['continuation_id'],continuation_sha256=digest(auth.capsule),
                receipt_sha256=digest(receipt),source_closure_sha256=digest(b['closure']),resume_gate='STOP_BEFORE_SEQ05')
        except Exception as error:
            s.create('recovery-unknown.json',canonical(dict(status='UNKNOWN',error_type=type(error).__name__,slot_consumed=True,retry_allowed=False)))
            raise

def _execute_reviewed(root):
    from .recovery_supervisor import supervise
    return supervise(root)

def bootstrap_entry(root):
    root=Path(root).absolute()
    require(Path(sys.argv[0]).absolute()==root/'bootstrap.py' and len(sys.argv)==2,'fixed recovery bootstrap entry')
    flag=sys.argv[1]
    if flag in ('--observe-recovery-v1','--observe-recovery-v2'):
        control=parse_json(ProtectedStore(root).read('control.json'))
        require(type(control.get('protocol_version')) is int and control['protocol_version'] in (1,2)
            and control.get('mode')=='observation' and flag==entry_flag(control,'observe'),'explicit observation version/control required')
        result=observe(root)
    elif flag in ('--execute-recovery-v1','--execute-recovery-v1-child'):
        _,_,(text,_,_)=_latest_actual_message();require(text.startswith(PREFIX),'separate recovery execution authorization required')
        control=parse_json(ProtectedStore(root).read('control.json'))
        require(type(control.get('protocol_version')) is int and control['protocol_version']==1
            and control.get('mode')=='execution','explicit v1 execution control required')
        result=_execute_reviewed(root) if flag=='--execute-recovery-v1' else run_child(root)
    elif flag in ('--execute-recovery-v2','--execute-recovery-v2-child'):
        store=ProtectedStore(root);control=parse_json(store.read('control.json'))
        require(type(control.get('protocol_version')) is int and control['protocol_version']==2
            and control.get('mode')=='execution','explicit v2 execution control required')
        gate=parse_json(store.read('admission-gate.json'))
        request=parse_json(store.read('operator-request.json'))
        require(request['schema']=='task13_actual_recovery_execution_request_v2','explicit natural recovery entry required')
        verify_recovery_permission(request,gate)
        result=_execute_reviewed(root) if flag=='--execute-recovery-v2' else run_child(root)
    else:raise ValueError('explicit versioned recovery entry required')
    print(canonical(result).decode('ascii'))
