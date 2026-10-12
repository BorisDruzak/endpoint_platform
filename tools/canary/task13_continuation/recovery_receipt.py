"""Explicit recovery receipts; genuine old claim plus one new recovery authority."""
from datetime import timedelta

from .codec import canonical,digest,integer,instant,require,sha256,parse_json
from .receipt import raw_bytes,observation,publication_ack
from .journal import validate_journal
from .reconciliation import validate_state
from .recovery_admission import OLD_CLAIMS,GLOBAL_NAME,validate_launch_record,validate_dispatch_record

def validate_recovery_evidence(prefix,capsule,evidence):
    require(evidence.get('schema')=='task13_recovery_execution_evidence_v1' and 'dispatch_claim' not in evidence,
            'explicit recovery evidence required; no fabricated legacy dispatch claim')
    require(evidence['continuation_id']==capsule['continuation_id'] and capsule['original']==prefix.binding
        and evidence['source_closure_sha256']==digest(capsule['source_closure']),'recovery execution identity/source binding')
    h,l,d=(evidence[n] for n in ('recovery_history','recovery_launch_slot','recovery_dispatch_slot'))
    validate_launch_record(prefix,h,l);validate_dispatch_record(prefix,h,l,d)
    require(d['capsule_sha256']==digest(capsule) and d['preflight_sha256']==digest(evidence['preclaim_preflight'])
        and d['continuation_id']==capsule['continuation_id']
        and l['source_closure_sha256']==digest(capsule['source_closure'])
        and l['protocol_source_sha256']==capsule['source_closure']['protocol_source_sha256'],
        'genuine recovery slot/capsule/preflight/source binding')
    old=evidence['historical_consumed_claims']
    require(set(old)==set(OLD_CLAIMS) and {n:sha256(raw_bytes(v)) for n,v in old.items()}==OLD_CLAIMS,
        'all three consumed historical claims required unchanged')
    original_claim=parse_json(raw_bytes(old[GLOBAL_NAME]))
    require(original_claim['original_run_seal_sha256']==prefix.binding['original_run_seal_sha256']
        and original_claim['original_tip']==prefix.binding['original_tip'] and original_claim['seq']==4
        and original_claim['continuation_id']!=capsule['continuation_id'],'old dispatch owner must not be projected to recovery CID')
    permission=evidence['recovery_authorization'];gate=evidence['admission_gate']
    pins=capsule['source_closure']['execution']['entries']
    require(pins['operator-request.json']==dict(bytes=len(canonical(permission)),sha256=digest(permission))
        and pins['admission-gate.json']==dict(bytes=len(canonical(gate)),sha256=digest(gate)),
        'independently pinned actual grant/admission source required')
    version=l['protocol_version']
    require(permission.get('schema')=='task13_actual_recovery_execution_request_v'+str(version)
        and permission['scope']=='seq04-additive-recovery-v'+str(version) and digest(permission)==l['request_sha256']
        and permission['gate_sha256']==digest(gate)==l['gate_sha256']
        and permission['continuation_id']==l['continuation_id']
        and permission['protocol_source_sha256']==l['protocol_source_sha256']
        and permission['implementation_sha']==l['implementation_sha']
        and permission['expires_utc']==l['expires_utc'] and type(permission['allowed_seq']) is int
        and permission['allowed_seq']==4,'recovery actual authorization binding')
    parent=evidence['launch_capsule']
    require(digest(parent)==l['capsule_sha256'] and parent['controller']==l['controller']
        and parent['continuation_id']==capsule['continuation_id'] and parent['source_closure']==capsule['source_closure']
        and digest(evidence['launch_preflight'])==l['preflight_sha256'],'recovery supervisor/preflight binding')
    for env,c in ((evidence['launch_preflight'],parent),(evidence['preclaim_preflight'],capsule)):
        state=observation(env,c,maximum=60);validate_state(prefix,c,state,env['finished_utc'])
    require(instant(evidence['launch_preflight']['finished_utc'])<=instant(evidence['preclaim_preflight']['dispatch_utc']),
            'recovery parent/child chronology')
    for env in (evidence['guest'],evidence['postflight'],evidence['retained_collection']):
        require(instant(env['finished_utc'])<instant(permission['expires_utc']),'recovery observation after human deadline')
    # The comparator, collection, journal, native watchdog and reconciliation
    # predicates below retain the ordinary verifier's complete checks. Authority
    # above is explicitly recovery, rather than a fabricated legacy claim.
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
    pre=observation(evidence['preflight'],capsule,maximum=60);post=observation(evidence['postflight'],capsule,maximum=60)
    validate_state(prefix,capsule,pre,evidence['guest']['dispatch_utc'])
    for state,env in ((pre,evidence['preflight']),(post,evidence['postflight'])):validate_state(prefix,capsule,state,env['finished_utc'])
    guest=observation(evidence['guest'],capsule)
    require(guest['status']=='GUEST_COMPARATOR_PASS' and guest['run_id']==prefix.plan['run_id']
        and guest['plan_sha256']==prefix.binding['original_plan_sha256'] and guest['baselineSha256']==prefix.binding['baseline_sha256']
        and guest['snapshot_identity_sha256']==prefix.binding['snapshot_identity_sha256'] and guest['markerAbsent'] is True,
        'real compare-after-start result required')
    require(instant(evidence['guest']['dispatch_utc'])-timedelta(seconds=5)<=instant(guest['utc'])
        <=instant(evidence['guest']['finished_utc'])+timedelta(seconds=5),'guest result clock bracket')
    prefix.controller.genuine81(guest['native_proof'],prefix.plan)
    require(evidence['preflight']['finished_mono_ns']<=evidence['guest']['dispatch_mono_ns']
        <=evidence['guest']['finished_mono_ns']<=evidence['postflight']['dispatch_mono_ns'],'pre/workload/post chronology')
    identity=evidence['identity']
    require(set(identity)=={'run','pid','birth'} and identity['run']==capsule['continuation_id'],'guest process identity')
    integer(identity['pid'],1,2**32-1);integer(identity['birth'],1)
    require(identity_row==dict(identity,root=root),'retained process identity projection')
    require(ready_row==preparation['ready'] and ready_row['run']==capsule['continuation_id']
        and integer(ready_row['limit'])==120 and integer(ready_row['pid'],1)!=identity['pid'],'retained readiness binding')
    require(instant(evidence['watchdog_preparation']['dispatch_utc'])-timedelta(seconds=5)<=instant(ready_row['utc'])
        <=instant(evidence['watchdog_preparation']['finished_utc'])+timedelta(seconds=5),'watchdog readiness clock bracket')
    require(integer(armed_row['pid'])==identity['pid'] and integer(armed_row['birth'])==identity['birth']
        and armed_row['retained_handle'] is True and integer(armed_row['safety_margin_ms'])==500
        and 0<integer(armed_row['remaining_ms'])<=119500,'retained watchdog arm binding')
    watchdog=observation(evidence['watchdog'],capsule,maximum=15)
    require(watchdog==dict(exit_row,run=identity['run'])
        and evidence['watchdog'].get('retained_transport_sha256')==digest(evidence['retained_collection']),'actual retained exit projection')
    require(all(type(watchdog[k]) is type(v) and watchdog[k]==v for k,v in identity.items())
        and watchdog['terminated'] is False and watchdog['confirmed'] is True
        and type(watchdog['wait_result']) is int and watchdog['wait_result']==0
        and type(watchdog['exit_code']) is int and watchdog['exit_code']==0,'watchdog retained normal exit required')
    require(exit_row['termination_utc'] is None and exit_row['capture_error'] is None
        and integer(exit_row['elapsed_ms'],0,120000)<=120000,'watchdog normal bounded completion')
    journal=raw_bytes(evidence['journal_b64'])
    require(journal==files['stages.jsonl'] and sha256(journal)==evidence['journal_sha256'],'retained journal hash')
    validate_journal(journal,identity,capsule['source_closure']['execution']['entries']['wire.bin']['bytes'])
    rows=[parse_json(line) for line in journal.splitlines()]
    require(instant(evidence['guest']['dispatch_utc'])-timedelta(seconds=5)<=instant(rows[0]['utc'])
        <=instant(rows[-1]['utc'])<=instant(evidence['guest']['finished_utc'])+timedelta(seconds=5),'journal/workload clocks')
    require(evidence['watchdog_preparation']['finished_mono_ns']<=evidence['preflight']['dispatch_mono_ns']
        and evidence['guest']['finished_mono_ns']<=evidence['retained_collection']['dispatch_mono_ns']
        <=evidence['retained_collection']['finished_mono_ns']<=evidence['postflight']['dispatch_mono_ns'],
        'preparation/reconciliation/retained chronology')

def make_recovery_receipt(prefix,capsule,evidence):
    validate_recovery_evidence(prefix,capsule,evidence)
    return dict(schema='task13_additive_recovery_receipt_v1',seq=4,step='compare-after-start',status='PASS',
        continuation_id=capsule['continuation_id'],continuation_sha256=digest(capsule),
        previous_sha256=prefix.binding['original_tip'],original=prefix.binding,
        source_closure_sha256=digest(capsule['source_closure']),evidence_sha256=digest(evidence),
        protocol_version=evidence['recovery_launch_slot']['protocol_version'],history_sha256=digest(evidence['recovery_history']),
        recovery_launch_slot_sha256=digest(evidence['recovery_launch_slot']),
        recovery_dispatch_slot_sha256=digest(evidence['recovery_dispatch_slot']),resume_gate='STOP_BEFORE_SEQ05')

def verify_recovery_candidate(prefix,capsule,receipt,evidence,publication):
    require(receipt==make_recovery_receipt(prefix,capsule,evidence),'canonical recovery seq04 receipt mismatch')
    require(publication==publication_ack(capsule,receipt),'durable recovery publication acknowledgement required')

def verify_recovery_receipt(prefix,capsule,receipt,evidence,publication,completion):
    verify_recovery_candidate(prefix,capsule,receipt,evidence,publication)
    require(type(completion) is dict and set(completion)=={'schema','status','controller','supervisor_controller',
        'root_pid','root_birth','exit_code','wait_result','observed_exit_utc','observed_exit_mono_ns','stdout_b64',
        'stderr_b64','stdout_sha256','stderr_sha256','receipt_sha256','continuation_sha256','evidence_sha256','publication_sha256'}
        and completion['schema']=='task13_root_completion_v1' and completion['status']=='ROOT_NORMAL_EXIT_OBSERVED',
        'actual complete root completion required')
    require(completion['controller']==capsule['controller'] and completion['root_pid']==capsule['controller']['pid']
        and completion['root_birth']==capsule['controller']['birth'] and type(completion['exit_code']) is int
        and completion['exit_code']==0 and type(completion['wait_result']) is int and completion['wait_result']==0,
        'retained normal root exit required')
    from .authority import _identity
    supervisor=completion['supervisor_controller'];_identity(supervisor)
    require(supervisor==evidence['recovery_launch_slot']['controller']
        and supervisor['host_id']==capsule['controller']['host_id'] and supervisor['boot_id']==capsule['controller']['boot_id']
        and (supervisor['pid'],supervisor['birth'])!=(completion['root_pid'],completion['root_birth']),'independent actual recovery supervisor')
    require(instant(capsule['created_utc'])<=instant(completion['observed_exit_utc'])<instant(capsule['expires_utc'])
        and instant(completion['observed_exit_utc'])<instant(evidence['recovery_authorization']['expires_utc'])
        and capsule['created_mono_ns']<=integer(completion['observed_exit_mono_ns'])<capsule['deadline_mono_ns']-2*10**9,
        'root completion outside authority')
    require(abs((instant(completion['observed_exit_utc'])-instant(capsule['created_utc'])).total_seconds()
        -(completion['observed_exit_mono_ns']-capsule['created_mono_ns'])/10**9)<=5,'root exit clocks diverged')
    stdout,stderr=raw_bytes(completion['stdout_b64']),raw_bytes(completion['stderr_b64'])
    require(not stderr and sha256(stdout)==completion['stdout_sha256'] and sha256(stderr)==completion['stderr_sha256'],
        'actual complete root streams')
    expected=dict(status='ROOT_PUBLICATION_READY',continuation_id=capsule['continuation_id'],continuation_sha256=digest(capsule),
        receipt_sha256=digest(receipt),source_closure_sha256=digest(capsule['source_closure']),resume_gate='STOP_BEFORE_SEQ05')
    require(parse_json(stdout.strip())==expected and completion['receipt_sha256']==digest(receipt)
        and completion['continuation_sha256']==digest(capsule) and completion['evidence_sha256']==digest(evidence)
        and completion['publication_sha256']==digest(publication),'root publication exact bytes binding')
