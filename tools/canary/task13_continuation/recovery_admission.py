"""Versioned recovery for one pinned pre-prepare refusal; never renew old claims."""
import base64
from pathlib import Path

from .authority import _identity
from .codec import canonical,digest,hex256,instant,parse_json,require,sha256,uuid
from .history import ORIGINAL_FILES,BASELINE_SHA,SNAPSHOT_SHA,read_file,verify_historical_prefix
from .storage import ProtectedStore
from . import windows

PROTOCOL_VERSION=1
BASE_REVISION='47b688c8cc926a9ac43e36426d69b07234f34cad'
HISTORICAL_BINDING_SHA='3c128797676c320d76b8398cea7359613bd28442c17dc823eac012b9a2dc1648'
FAILED_NAME='task13-authorized-seq04-review-20261011-e'
READONLY_NAME='task13-readonly-unknown-recovery-review-20261011-d'
FAILED_TREE_SHA='45ad7cdf6938422f90907af7b322f9aaa5a666656d4e57fe88f819f80f0cffe0'
READONLY_TREE_SHA='4c71e6f27b5637cc6007d9bf01e7a123de0e4a22aab6c7b98cf67a6e39b73f42'
OLD_CLAIMS={
 'claim-bbc3e90d874698817580b483f9f0794c8f212bd84a23960c0ab41e4da95c0abd.json':'79322ea623ada3c552b105ff2ce5aa1cf342f2da5f0fbf14134ae9b08ffa490b',
 'execution-launch-1acbd78bc576db9a37d5ae0867c28988bee49db919722e2c2becf17e0317e0fc.json':'411c2e829e63f9bf6653999dca96c6393421e03424de175be051d0badd6902d8',
 'recovery-launch-ca127badc5a39583e8ca6707f75cdf57ead16e4544d808c7c653a557528edadc.json':'8a1185254bc199ee4f081c2965f16fd24589b1a2fb50877ae02e4b8c784e1a6d'}
GLOBAL_NAME=next(n for n in OLD_CLAIMS if n.startswith('claim-'))
ACCEPTED_SOURCE_ROOT='task13-command-transport-review-20261011-c'
ACCEPTED_SOURCE_SHA='f219ff086d1cf1623107bb66a0638ed2ae8d3d45eaf7a57dce1c68e0ba8c5cac'
MODULES=('recovery_admission.py','recovery_permission.py','recovery_bundle.py',
         'recovery_loader.py','recovery_receipt.py','recovery_supervisor.py','recovery_gate.py','recovery_permission_v2.py')
LAUNCH_KEYS={'schema','original','history_sha256','consumed_global_claim_sha256','protocol_version',
 'protocol_source_sha256','implementation_sha','continuation_id','gate_sha256','request_sha256',
 'source_closure_sha256','capsule_sha256','preflight_sha256','expires_utc','controller'}
DISPATCH_KEYS={'schema','launch_slot_sha256','continuation_id','original','protocol_version',
 'protocol_source_sha256','consumed_global_claim_sha256','capsule_sha256','preflight_sha256'}

def protocol_sources(entries=None):
    """Implementation digest independent of git commit metadata and operator record."""
    return digest({n:sha256(entries['tools/canary/task13_continuation/'+n] if entries is not None
                    else read_file(Path(__file__).parent/n)) for n in MODULES})

def _tree(root):
    return {p.relative_to(root).as_posix():sha256(read_file(p)) for p in sorted(root.rglob('*')) if p.is_file()}

def _canonical_original_root():
    """Physical namespace comes from previously reviewed immutable control."""
    store=ProtectedStore(Path.home()/'.codex/task-evidence'/ACCEPTED_SOURCE_ROOT)
    raw=store.read('closure.json');require(sha256(raw)==ACCEPTED_SOURCE_SHA,'canonical historical root source pin')
    spec=parse_json(raw)['execution']['entries']['control.json'];control=store.read('control.json')
    require(len(control)==spec['bytes'] and sha256(control)==spec['sha256'],'canonical historical root control pin')
    return Path(parse_json(control)['original_root']).absolute()

def require_canonical_root(prefix):
    require(str(Path(prefix.root).absolute()).casefold()==str(_canonical_original_root()).casefold(),
        'canonical historical root required; copied evidence cannot issue recovery')

def validate_original(original):
    require(type(original) is dict and original.get('original_files')==ORIGINAL_FILES
        and original.get('original_plan_sha256')==ORIGINAL_FILES['plan.json']
        and original.get('original_run_seal_sha256')==ORIGINAL_FILES['run-seal.json']
        and original.get('original_tip')==ORIGINAL_FILES['receipt-03-start-after-snapshot.json']
        and original.get('baseline_sha256')==BASELINE_SHA and original.get('snapshot_identity_sha256')==SNAPSHOT_SHA
        and type(original.get('verified_receipt_count')) is int and original['verified_receipt_count']==4,
        'immutable recovery historical prefix')

def capture_history(prefix):
    """Read-only: presence and exact identity of all three old claims is mandatory."""
    require_canonical_root(prefix);validate_original(prefix.binding)
    require(digest(verify_historical_prefix(prefix.root).binding)==digest(prefix.binding)==HISTORICAL_BINDING_SHA,
            'fixed recovery historical binding')
    home=Path.home()/'.codex/task-evidence';failed=home/FAILED_NAME;prior=home/READONLY_NAME
    ft,pt=_tree(failed),_tree(prior)
    require(digest(ft)==FAILED_TREE_SHA and digest(pt)==READONLY_TREE_SHA,'immutable failed/prior evidence tree')
    store=ProtectedStore(prefix.root/'continuation-v1-claims')
    blobs={n:store.read(n) for n in OLD_CLAIMS}
    require({n:sha256(raw) for n,raw in blobs.items()}==OLD_CLAIMS,'consumed historical claim identity')
    fs=ProtectedStore(failed);closure=parse_json(fs.read('closure.json'));capsule=parse_json(fs.read('capsule.json'))
    root=parse_json(fs.read('root-transport.json'));audit=parse_json(fs.read('independent-execution-failure-audit.json'))
    claim=parse_json(blobs[GLOBAL_NAME]);local=parse_json(fs.read('dispatch-claim.json'))
    require(claim==local and claim['schema']=='task13_dispatch_claim_v1' and type(claim['seq']) is int and claim['seq']==4
        and claim['original_run_seal_sha256']==prefix.binding['original_run_seal_sha256']
        and claim['original_tip']==prefix.binding['original_tip'] and claim['continuation_id']==capsule['continuation_id'],
        'consumed original dispatch owner')
    require(closure['original_binding']==capsule['original']==prefix.binding,'failed original identity')
    for n,spec in closure['execution']['entries'].items():
        path=failed/n;raw=ProtectedStore(path.parent).read(path.name)
        require(len(raw)==spec['bytes'] and sha256(raw)==spec['sha256'],'failed source pin')
    require(root['pid']==capsule['controller']['pid'] and root['birth']==capsule['controller']['birth']
        and root['wait_result']==0 and root['exit_code']==1 and root['streams_complete'] is True
        and root['timed_out'] is False,'failed native root termination')
    outer=parse_json(fs.read('operator-execution-observation.json'))
    require(outer['wait_result']==0 and outer['exit_code']==1 and outer['streams_complete'] is True
        and outer['timed_out'] is False,'failed native supervisor termination')
    stdout,stderr=(base64.b64decode(root[k+'_b64'],validate=True) for k in ('stdout','stderr'))
    require(sha256(stdout)==root['stdout_sha256'] and sha256(stderr)==root['stderr_sha256']
        and b'ValueError: Windows command-line bound' in stderr,'retained builder refusal')
    require(audit['prepare_transport_dispatched'] is False and audit['comparator_dispatched'] is False
        and audit['failure']['stage']=='prepare_before_transport_call'
        and audit['failure']['windows_command_line_characters_including_nul']==34172
        and audit['original_dispatch_claim_sha256']==OLD_CLAIMS[GLOBAL_NAME]
        and audit['root_transport_sha256']==sha256(fs.read('root-transport.json'))
        and audit['historical_identity_rca']=='UNKNOWN','independent pre-prepare refusal audit')
    require(len(list(failed.glob('transport-*-intent.json')))==8 and len(list(failed.glob('transport-*-result.json')))==8
        and not any((failed/n).exists() for n in ('dispatch-preflight.json','execution-evidence.json',
            'receipt-04-compare-after-start.json','resume-gate.json','root-completion.json')),'no prior workload dispatch')
    # launch claim hashes above pin their exact prior owners as well as presence.
    return dict(schema='task13_consumed_history_v1',original=prefix.binding,global_claim_sha256=OLD_CLAIMS[GLOBAL_NAME],
        claims=dict(OLD_CLAIMS),failed_bundle_sha256=digest(ft),prior_readonly_sha256=digest(pt),
        prior_root={k:root[k] for k in ('pid','birth')},prior_supervisor={k:outer[k] for k in ('pid','birth')},
        prior_controller=capsule['controller'],
        failure_phase='PREPARE_BUILDER_REFUSED_BEFORE_TRANSPORT',historical_rca='UNKNOWN')

def hold_history(stack,prefix,expected):
    from .loader import _hold_file,_hold_history
    _hold_history(stack,prefix.root)
    home=Path.home()/'.codex/task-evidence'
    for root in (home/FAILED_NAME,home/READONLY_NAME,prefix.root/'continuation-v1-claims'):
        paths=list(root.rglob('*')) if root.name!='continuation-v1-claims' else [root/n for n in OLD_CLAIMS]
        dirs={root,*root.parents,*[p for p in paths if p.is_dir()]}
        for parent in sorted(dirs,key=lambda p:len(p.parts)):
            stack.enter_context(windows.retained(parent,directory=True,security=False))
        for path in paths:
            if path.is_file():
                raw=read_file(path);_hold_file(stack,path,dict(bytes=len(raw),sha256=sha256(raw)),protected=True)
    require(capture_history(prefix)==expected,'held recovery history changed')

def slot_path(prefix,history,kind):
    require_canonical_root(prefix)
    validate_original(prefix.binding)
    require(history['original']==prefix.binding and digest(prefix.binding)==HISTORICAL_BINDING_SHA
            and history['schema']=='task13_consumed_history_v1' and history['claims']==OLD_CLAIMS
            and history['global_claim_sha256']==OLD_CLAIMS[GLOBAL_NAME]
            and history['failed_bundle_sha256']==FAILED_TREE_SHA and history['prior_readonly_sha256']==READONLY_TREE_SHA,
            'recovery historical prefix mismatch')
    hex256(history['global_claim_sha256']);require(kind in ('launch','dispatch'),'fixed recovery phase')
    key=dict(original_run_seal_sha256=prefix.binding['original_run_seal_sha256'],
        original_tip=prefix.binding['original_tip'],seq=4,consumed_global_claim_sha256=history['global_claim_sha256'])
    return prefix.root/'continuation-v1-claims'/('additive-recovery-'+kind+'-'+digest(key)+'.json')

def validate_launch_record(prefix,history,value):
    slot_path(prefix,history,'launch')
    require(type(value) is dict and set(value)==LAUNCH_KEYS and value['schema']=='task13_recovery_launch_slot_v1',
            'exact recovery launch slot')
    require(value['original']==history['original']==prefix.binding and value['history_sha256']==digest(history)
        and value['consumed_global_claim_sha256']==history['global_claim_sha256']
        and type(value['protocol_version']) is int and value['protocol_version'] in (PROTOCOL_VERSION,2),'recovery launch identity')
    validate_original(value['original']);uuid(value['continuation_id']);_identity(value['controller']);instant(value['expires_utc'])
    require(type(value['implementation_sha']) is str and len(value['implementation_sha'])==40
        and all(c in '0123456789abcdef' for c in value['implementation_sha']),'exact implementation revision')
    for n in ('history_sha256','consumed_global_claim_sha256','protocol_source_sha256','gate_sha256',
              'request_sha256','source_closure_sha256','capsule_sha256','preflight_sha256'):hex256(value[n])

def validate_dispatch_record(prefix,history,launch,value):
    validate_launch_record(prefix,history,launch)
    require(type(value) is dict and set(value)==DISPATCH_KEYS and value['schema']=='task13_recovery_dispatch_slot_v1'
        and value['launch_slot_sha256']==digest(launch) and value['continuation_id']==launch['continuation_id']
        and value['original']==prefix.binding and type(value['protocol_version']) is int and value['protocol_version']==launch['protocol_version']
        and value['protocol_source_sha256']==launch['protocol_source_sha256']
        and value['consumed_global_claim_sha256']==history['global_claim_sha256'],'recovery dispatch transition identity')
    hex256(value['capsule_sha256']);hex256(value['preflight_sha256'])

def _exists(path):
    try:path.lstat();return True
    except FileNotFoundError:return False

def slot_state(prefix,history):
    launch,dispatch=(slot_path(prefix,history,k) for k in ('launch','dispatch'))
    if not _exists(launch):return 'OCCUPIED_UNKNOWN' if _exists(dispatch) else 'ABSENT'
    try:
        value=parse_json(ProtectedStore(launch.parent).read(launch.name));validate_launch_record(prefix,history,value)
        if _exists(dispatch):
            next_value=parse_json(ProtectedStore(dispatch.parent).read(dispatch.name));validate_dispatch_record(prefix,history,value,next_value)
            return 'DISPATCH_COMMITTED'
        return 'LAUNCH_COMMITTED'
    except (OSError,ValueError,KeyError,TypeError):return 'OCCUPIED_UNKNOWN'

def require_unused_slot(prefix,history):
    require(slot_state(prefix,history)=='ABSENT','recovery slot already occupied; observation only, no retry')

def _commit_native(path,raw):
    """Final name is occupied before payload write; all uncertain outcomes burn it."""
    store=ProtectedStore(path.parent)
    with store._ancestry(),windows.retained(path,writable=True,create=True,protected=True) as handle:
        windows.write_handle(handle,b'');windows.flush_volume(path)
        windows.write_handle(handle,raw);windows.flush_volume(path)
    require(store.read(path.name)==raw,'committed recovery slot differs')

def hold_slot(stack,prefix,history,kind,expected):
    path=slot_path(prefix,history,kind)
    handle=stack.enter_context(windows.retained(path,protected=True))
    require(windows.read_handle(handle,path)==canonical(expected),'held recovery slot changed')
