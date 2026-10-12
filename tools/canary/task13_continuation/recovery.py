"""Recovery admission for one fixed, proven pre-dispatch UNKNOWN attempt.

This proves absence of an earlier dispatch, never quiescence or acceptance.
"""
import base64
from datetime import datetime,timezone
from pathlib import Path
from .codec import canonical,digest,parse_json,require,sha256
from .history import _relative
from .storage import ProtectedStore
from . import windows

PRIOR_NAME='task13-continuation-v1-review-20261011-h'
PRIOR_CLOSURE='1f4c4cbc2928ce85d3647816b7f1825963231eadd94697c05100ca36be859602'
ROOT_TRANSPORT_SHA='3dd54085df07ee994de8ed7da5d59ee2205352fe588b2545ed3afffd69bb0ef8'
PRIOR_CAPSULE_SHA='1a6c74a526cee63af080df2e82c7a140f825728ae7d4e31bece33928360cc6ff'
TAGS=('management-state','provider','guest','inventory','current')
EVIDENCE=('closure.json','control.json','capsule.json','review.json','trust.json',
          'authority.json','attestation.json','live-trust.json',
          'root-launch-claim.json','root-transport.json','supervisor-unknown.json',
          'operator-supervisor-stdout.bin','operator-supervisor-stderr.bin',
          *tuple(f'transport-{i:03d}-{tag}-{suffix}.json'
                 for i,tag in enumerate(TAGS,1) for suffix in ('intent','result')))

def claim_path(prefix):
    key={k:prefix.binding[k] for k in ('original_run_seal_sha256','original_tip')}
    return prefix.root/'continuation-v1-claims'/('claim-'+digest({**key,'seq':4})+'.json')

def recovery_launch_path(prefix):
    key={k:prefix.binding[k] for k in ('original_run_seal_sha256','original_tip')}
    return prefix.root/'continuation-v1-claims'/('recovery-launch-'+digest({**key,'prior_closure':PRIOR_CLOSURE})+'.json')

def launch_owner(prefix,closure):
    return {'schema':'task13_single_recovery_launch_v1','prior_closure_sha256':PRIOR_CLOSURE,
            'original_run_seal_sha256':prefix.binding['original_run_seal_sha256'],
            'original_tip':prefix.binding['original_tip'],'allowed_seq':4,
            'continuation_id':closure['continuation_id'],'source_closure_sha256':digest(closure)}

def check_recovery_launch(prefix,owner,required):
    path=recovery_launch_path(prefix)
    if path.exists():
        require(owner is not None and parse_json(ProtectedStore(path.parent).read(path.name))==owner,
                'single recovery launch already consumed by another continuation')
    else:
        require(not required,'actual child requires permanent recovery launch claim')

def claim_recovery_launch(prefix,closure):
    path=recovery_launch_path(prefix)
    try:store=ProtectedStore.create_root(path.parent)
    except OSError:store=ProtectedStore(path.parent)
    store.create(path.name,canonical(launch_owner(prefix,closure)))

def validate_previous(blobs,names,binding,claimed,child_terminated=False):
    closure=parse_json(blobs['closure.json']);capsule=parse_json(blobs['capsule.json'])
    require(sha256(blobs['capsule.json'])==PRIOR_CAPSULE_SHA,'immutable prior actual creator capsule')
    require(digest(closure)==PRIOR_CLOSURE and capsule['source_closure']==closure,
            'fixed failed-attempt reviewed closure')
    require(closure['original_binding']==capsule['original']==binding
            ==parse_json(blobs['control.json'])['original_binding'],'failed-attempt original binding')
    allowed={_relative(name).parts[0] for name in closure['execution']['entries']}
    allowed.update(EVIDENCE);allowed.update(('attestation.json','authority.json','live-trust.json'))
    require(set(names)==allowed and not claimed,'only retained initial preflight; no prior seq04 claim')
    unknown=parse_json(blobs['supervisor-unknown.json'])
    require(unknown=={'status':'UNKNOWN','error_type':'ValueError','retry_allowed':False},
            'fixed initial transport UNKNOWN')
    root=parse_json(blobs['root-transport.json'])
    require(sha256(blobs['root-transport.json'])==ROOT_TRANSPORT_SHA,'immutable prior native terminal witness')
    require(root['exit_code']==1 and root['wait_result']==0 and root['timed_out'] is False
            and root['streams_complete'] is True and child_terminated is True,
            'launcher terminal witness plus separately proven actual creator termination')
    for label in ('stdout','stderr'):
        raw=base64.b64decode(root[label+'_b64'],validate=True)
        require(sha256(raw)==root[label+'_sha256'],
                'failed root retained streams changed')
        require((not raw) if label=='stdout' else bool(raw),'fixed failed root output')
        operator=blobs['operator-supervisor-'+label+'.bin']
        require((not operator) if label=='stdout' else bool(operator),'fixed supervisor terminal output')
    review=parse_json(blobs['review.json']);trust=parse_json(blobs['trust.json'])
    require(review['status']=='PASS' and review['source_closure_sha256']==PRIOR_CLOSURE
            ==trust['source_closure_sha256'] and digest(review)==trust['review_sha256'],
            'failed attempt independent source PASS')
    for i,tag in enumerate(TAGS,1):
        result=parse_json(blobs[f'transport-{i:03d}-{tag}-result.json'])
        require(result['exit_code']==(1 if i==1 else 0)
                and result['status']==('UNKNOWN' if i==1 else 'TRANSPORT_COMPLETE')
                and result['stdin_confirmed'] is True,'fixed bounded readonly preflight results')
        for label in ('stdout','stderr'):
            raw=base64.b64decode(result[label+'_b64'],validate=True)
            require(sha256(raw)==result[label+'_sha256'],'failed preflight raw bytes')
        intent=parse_json(blobs[f'transport-{i:03d}-{tag}-intent.json'])
        require(intent['seconds']==(30 if i==1 else 25),'fixed readonly preflight intent')

def capture_recovery(prefix,owner=None,require_launch=False):
    check_recovery_launch(prefix,owner,require_launch)
    store=ProtectedStore(Path.home()/'.codex/task-evidence'/PRIOR_NAME)
    blobs={name:store.read(name) for name in EVIDENCE}
    capsule=parse_json(blobs['capsule.json']);identity=windows.observe_controller()
    require(all(identity[k]==capsule['controller'][k] for k in ('host_id','boot_id','token_sid','elevated')),
            'prior creator controller host/boot/token changed')
    disposition=windows.confirm_process_gone(capsule['controller']['pid'],capsule['controller']['birth'])
    terminal={'observer':identity,'prior_creator':capsule['controller'],'disposition':disposition,
              'observed_utc':datetime.now(timezone.utc).isoformat()}
    validate_previous(blobs,{p.name for p in store.root.iterdir()},prefix.binding,claim_path(prefix).exists(),True)
    closure=parse_json(blobs['closure.json'])
    for name,spec in closure['execution']['entries'].items():
        path=store.root/_relative(name)
        with windows.retained(path,protected=True) as handle:
            raw=windows.read_handle(handle,path)
        require(sha256(raw)==spec['sha256'] and len(raw)==spec['bytes'],'failed attempt execution source changed')
        blobs[name]=raw
    return {'schema':'task13_pre_dispatch_unknown_recovery_v1','prior_closure_sha256':PRIOR_CLOSURE,
            'original':prefix.binding,'allowed_seq':4,'phase':'INITIAL_READONLY_PREFLIGHT',
            'creator_termination_observation':terminal,
            'files':{name:{'sha256':sha256(raw),'bytes':len(raw)} for name,raw in sorted(blobs.items())}}

def hold_recovery(stack,record,prefix,owner,require_launch=False):
    root=Path.home()/'.codex/task-evidence'/PRIOR_NAME
    require(record['schema']=='task13_pre_dispatch_unknown_recovery_v1','reviewed recovery record')
    directories={root,*root.parents}
    for name in record['files']:
        directories.update((root/_relative(name)).parents)
    for parent in sorted(directories,key=lambda p:len(p.parts)):
        stack.enter_context(windows.retained(parent,directory=True,security=False))
    for name,spec in record['files'].items():
        path=root/_relative(name)
        handle=stack.enter_context(windows.retained(path,protected=True))
        raw=windows.read_handle(handle,path)
        require(sha256(raw)==spec['sha256'] and len(raw)==spec['bytes'],'reviewed recovery evidence changed')
    current=capture_recovery(prefix,owner,require_launch)
    require({k:v for k,v in current.items() if k!='creator_termination_observation'}
            =={k:v for k,v in record.items() if k!='creator_termination_observation'},
            'recovery phase/evidence changed after review')
    old=record['creator_termination_observation'];fresh=current['creator_termination_observation']
    require(old['prior_creator']==fresh['prior_creator']
            and old['disposition'] in ('ABSENT','PID_REUSED','EXACT_PROCESS_EXITED')
            and all(old['observer'][k]==fresh['observer'][k] for k in ('host_id','boot_id','token_sid','elevated')),
            'retained creator termination observation identity')
