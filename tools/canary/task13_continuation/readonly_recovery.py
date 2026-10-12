"""Immutable failed-attempt evidence for observation only, never launch admission."""
from pathlib import Path
from datetime import datetime,timezone
from .codec import canonical,digest,parse_json,require,sha256
from .history import _relative
from .storage import ProtectedStore
from .process_identity import identity_states
from .recovery import claim_path,recovery_launch_path,launch_owner
from . import windows

PRIOR_NAME='task13-pid-identity-seq04-review-20261011-b'
PINS={
    'closure.json':'ef34fc154470552e32221e882f587be2e330fe2243bb4e9b4e70023aff35b2db',
    'review.json':'db71ba0f13549cace91abbd98dd374c3ccb6fc4c4826733ad1cabfe8c3bf2ce3',
    'trust.json':'77f05124bda72133f1100aad40a7ddbf20a88417abcdd416de0bc690ba88c0c1',
    'capsule.json':'66acd1d517485199df593ab9e536fcbac26729041468d437ea202d0239c3f314',
    'root-transport.json':'4e6d1f233f5ca828040b6212fc4f8b475c90864e6ad28dd17b7fe24b9a9c5a82',
    'supervisor-unknown.json':'b03700be53d69a59d1d24f713243dc729b3c106adbb1fa8165ee037a28e0db9a',
    'execution-supervisor-observation.json':'78690dee568c9a69a77f47ad9b34c837004c5780d7672c5bfacb3ff46010e45a',
    'transport-006-process_identity-result.json':'0f25479b4befc5b4e5b2791a01d8d7cdb836b2d3dc16ff943365016e6b018945'}
TAGS=('management-state','provider','guest','inventory','current','process_identity','clock_guest','management-clock')
EXTRAS=('closure.json','review.json','trust.json','capsule.json','authority.json','attestation.json','live-trust.json',
        'root-launch-claim.json','root-transport.json','supervisor-unknown.json','execution-supervisor-observation.json',
        *tuple(f'transport-{i:03d}-{tag}-{suffix}.json' for i,tag in enumerate(TAGS,1) for suffix in ('intent','result')))

def capture_readonly_recovery(prefix):
    store=ProtectedStore(Path.home()/'.codex/task-evidence'/PRIOR_NAME)
    blobs={name:store.read(name) for name in EXTRAS}
    for name,pin in PINS.items():require(sha256(blobs[name])==pin,'immutable failed recovery pin')
    closure=parse_json(blobs['closure.json']);capsule=parse_json(blobs['capsule.json'])
    require(closure['original_binding']==capsule['original']==prefix.binding
            and capsule['source_closure']==closure,'failed recovery historical binding')
    allowed={_relative(name).parts[0] for name in closure['execution']['entries']}|set(EXTRAS)
    require({p.name for p in store.root.iterdir()}==allowed and not claim_path(prefix).exists(),
            'read-only recovery must remain before original seq04 dispatch')
    for name,spec in closure['execution']['entries'].items():
        raw=ProtectedStore((store.root/_relative(name)).parent).read(Path(name).name)
        require(len(raw)==spec['bytes'] and sha256(raw)==spec['sha256'],'failed recovery source changed')
        blobs[name]=raw
    root=parse_json(blobs['root-transport.json'])
    require(root['pid']==capsule['controller']['pid'] and root['birth']==capsule['controller']['birth']
            and root['exit_code']==1 and root['wait_result']==0 and root['streams_complete'] is True
            and root['timed_out'] is False,'failed actual root termination')
    for i,tag in enumerate(TAGS,1):
        result=parse_json(blobs[f'transport-{i:03d}-{tag}-result.json'])
        require(result['status']=='TRANSPORT_COMPLETE' and result['exit_code']==0
                and result['stderr_b64']=='','failed read-only transport raw proof')
    states=identity_states(prefix,parse_json(blobs['transport-006-process_identity-result.json'])['observation'])
    require(list(states.values()).count('IDENTITY_UNKNOWN')==1
            and list(states.values()).count('PROCESS_ABSENT')==13
            and list(states.values()).count('PID_REUSED')==2,'historical UNKNOWN must be preserved')
    claim=recovery_launch_path(prefix);claim_raw=ProtectedStore(claim.parent).read(claim.name)
    require(parse_json(claim_raw)==launch_owner(prefix,closure),'consumed claim owner changed')
    controller=windows.observe_controller();old=capsule['controller']
    require(all(controller[k]==old[k] for k in ('host_id','boot_id','token_sid','elevated')),
            'failed creator host/boot/token changed')
    disposition=windows.confirm_process_gone(old['pid'],old['birth'])
    require(disposition in ('ABSENT','PID_REUSED','EXACT_PROCESS_EXITED'),'failed creator still active or unknown')
    return dict(schema='task13_readonly_unknown_recovery_v1',historical_rca='UNKNOWN',seq04_authorized=False,
                original=prefix.binding,prior_closure_sha256=digest(closure),
                files={name:dict(bytes=len(raw),sha256=sha256(raw)) for name,raw in sorted(blobs.items())},
                consumed_claim=dict(name=claim.name,bytes=len(claim_raw),sha256=sha256(claim_raw)),
                creator_termination_observation=dict(observer=controller,prior_creator=old,disposition=disposition,
                    observed_utc=datetime.now(timezone.utc).isoformat()))

def hold_readonly_recovery(stack,record,prefix):
    from .loader import _hold_file
    root=Path.home()/'.codex/task-evidence'/PRIOR_NAME
    require(record['schema']=='task13_readonly_unknown_recovery_v1' and record['historical_rca']=='UNKNOWN'
            and record['seq04_authorized'] is False,'observation recovery cannot authorize seq04')
    paths={root/_relative(name):spec for name,spec in record['files'].items()}
    claim=recovery_launch_path(prefix)
    require(record['consumed_claim']['name']==claim.name,'canonical consumed claim')
    paths[claim]={k:record['consumed_claim'][k] for k in ('bytes','sha256')}
    directories={parent for path in paths for parent in path.parents}
    for parent in sorted(directories,key=lambda p:len(p.parts)):
        stack.enter_context(windows.retained(parent,directory=True,security=False))
    for path,spec in paths.items():_hold_file(stack,path,spec,protected=True)
    current=capture_readonly_recovery(prefix)
    require({k:v for k,v in current.items() if k!='creator_termination_observation'}
            =={k:v for k,v in record.items() if k!='creator_termination_observation'},'read-only recovery evidence changed')
