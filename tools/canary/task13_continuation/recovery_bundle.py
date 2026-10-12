"""Offline versioned recovery bundles and complete preclaim feasibility."""
import base64
import gzip
import io
import sys
import subprocess
from pathlib import Path
from uuid import uuid4

from .codec import canonical,digest,parse_json,require,sha256,integer
from .history import read_file,verify_historical_prefix
from .sources import build_execution_sources,seal_sources,build_stdin_delivery,delivery_bootstrap
from .operations import build_operations
from .loader import check_operations
from .storage import ProtectedStore
from .transport import validate_command_plan,validate_command
from .recovery_admission import capture_history,protocol_sources,BASE_REVISION,require_unused_slot
from .recovery_permission_v2 import capture_recovery_permission,capture_consent
from . import windows

ACCEPTED_ROOT='task13-command-transport-review-20261011-c'
ACCEPTED_CLOSURE_SHA='f219ff086d1cf1623107bb66a0638ed2ae8d3d45eaf7a57dce1c68e0ba8c5cac'
RECOVERY_SCOPE=['consumed-claim-identities','pre-prepare-refusal','single-native-slot','packet-feasibility',
                'actual-recovery-permission','native-child-handoff','recovery-receipt','no-retry','actual-natural-consent-v2',
                'controller-dependency-v2','joint-readonly-provenance-v2']
OPERATIONS=('guest','inventory','current','process_identity','clock_guest','prepare','workload','collect')

def bind_closed_executables(operations,runtime):
    """Bind historical Windows spellings to the exact already-reviewed path."""
    for name in ('guest_ssh','provider_argv','management_argv'):
        argv=operations[name]
        matches=[p for p in runtime if Path(p)==Path(argv[0])]
        require(len(matches)==1,'selected executable is not uniquely closed')
        argv[0]=matches[0]

def verify_packets(prefix,entries):
    names=OPERATIONS+(('joint_identity',) if 'entry-joint_identity.ps1' in entries else ())
    for name in names:
        pin=parse_json(entries['packet-'+name+'-binding.json']);wire=entries['packet-'+name+'.bin']
        n=integer(pin['wire_bytes'],1,4*1024*1024);bn=integer(pin['body_utf8_bytes'],1,8*1024*1024)
        require(len(wire)==n and sha256(wire)==pin['wire_sha256'],'sealed wire length/SHA before claim')
        require(entries['delivery-'+name+'.ps1']==delivery_bootstrap(pin),'sealed bootstrap source before claim')
        try:
            compressed=base64.b64decode(wire,validate=True)
            require(base64.b64encode(compressed)==wire,'canonical sealed wire')
            with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:body=stream.read(bn+1)
            require(len(body)==bn and sha256(body)==pin['body_utf8_sha256'],'sealed body length/SHA before claim')
            value=parse_json(body)
        except (OSError,EOFError,UnicodeError) as error:raise ValueError('invalid sealed stdin packet') from error
        require(type(value) is dict and set(value)=={'script','parameters'} and type(value['script']) is str
            and sha256(value['script'].encode())==pin['helper_sha256'],'sealed helper/source before claim')
        params=value['parameters'];require(type(params) is dict and params.get('ExecuteReviewedStep') is True,
            'sealed authorized step parameter')
        _,_,expected=build_stdin_delivery(prefix,entries['entry-'+name+'.ps1'].decode('utf-8'),
                                         entries['wire.bin'] if name=='workload' else b'')
        require({k:pin[k] for k in ('body_utf8_bytes','body_utf8_sha256','helper_sha256','parameter_hashes')}
            =={k:expected[k] for k in ('body_utf8_bytes','body_utf8_sha256','helper_sha256','parameter_hashes')},
            'sealed original source/parameter pins')
        require(set(params)==set(expected['parameter_hashes'])|{'ExecuteReviewedStep'}
            and {k:sha256(v.encode()) for k,v in params.items() if type(v) is str}==expected['parameter_hashes'],
            'sealed original parameter identity')
    return dict(verified_packets=len(names))

def verify_feasibility(prefix,closure,entries,operations,root_argv):
    require(closure['execution']==seal_sources(entries),'preclaim exact execution source closure')
    require(entries['operations.json']==canonical(operations),'bound operation parameters changed')
    require(closure['protocol_source_sha256']==protocol_sources(entries),'preclaim recovery protocol source pins')
    if 'control.json' in entries and parse_json(entries['control.json']).get('protocol_version')==2:
        from .recovery_dependencies_v2 import verify_closed_revision
        verify_closed_revision(entries,closure['runtime'])
    check_operations(operations)
    require(operations['continuation_id']==closure['continuation_id'],'preclaim continuation operation identity')
    plan=validate_command_plan(operations,entries);plan['root']=validate_command(root_argv)
    if 'control.json' in entries and parse_json(entries['control.json']).get('protocol_version')==2:
        from .recovery_observation_v2 import verify_operation
        plan['joint_identity']=verify_operation(prefix,entries,operations)
    require(root_argv[0] in closure['runtime'],'preclaim direct closed interpreter')
    require(root_argv[1:5]==['-I','-S','-B','-X'] and Path(root_argv[-2]).name=='bootstrap.py'
        and root_argv[5]=='pycache_prefix='+str(Path(root_argv[-2]).parent/'no-pyc')
        and root_argv[-1] in ('--observe-recovery-v1','--execute-recovery-v1-child',
                             '--observe-recovery-v2','--execute-recovery-v2-child'), 'fixed isolated recovery command')
    require(all(argv[0] in closure['runtime'] for argv in (operations['guest_ssh'],operations['provider_argv'],operations['management_argv'])),
        'all selected transport dependencies must be closed')
    system=windows.system_core_paths()
    require(Path(operations['guest_ssh'][0]) in system and Path(operations['provider_argv'][0]) in system,
        'canonical installed SSH transport required')
    verify_packets(prefix,entries)
    return plan

def _accepted_runtime():
    raw=read_file(Path.home()/'.codex/task-evidence'/ACCEPTED_ROOT/'closure.json')
    require(sha256(raw)==ACCEPTED_CLOSURE_SHA,'fixed accepted dependency closure')
    runtime=parse_json(raw)['runtime']
    require(str(Path(sys._base_executable).absolute()) in runtime,'use the accepted isolated Python3.12 interpreter')
    for name,spec in runtime.items():
        with windows.retained(Path(name),security=False,expected_links=spec.get('hardlink_count',1)) as handle:
            data=windows.read_handle(handle,Path(name),expected_links=spec.get('hardlink_count',1))
        require(len(data)==spec['bytes'] and sha256(data)==spec['sha256'],'accepted dependency/source pin changed')
    return runtime

def _prepare(original_root,root,implementation_sha,mode,gate=None):
    require(mode in ('observation','execution') and len(implementation_sha)==40
        and all(c in '0123456789abcdef' for c in implementation_sha),'exact recovery revision/mode')
    repository=Path(__file__).resolve().parents[3]
    for path in Path(__file__).parent.glob('*.py'):
        relative=path.relative_to(repository).as_posix()
        committed=subprocess.run(['git','-C',str(repository),'show',implementation_sha+':'+relative],capture_output=True,timeout=10)
        require(committed.returncode==0 and committed.stdout==read_file(path),'recovery implementation revision source mismatch')
    prefix=verify_historical_prefix(original_root);history=capture_history(prefix);require_unused_slot(prefix,history)
    request=capture_recovery_permission(gate) if mode=='execution' else None
    if gate is not None:
        require(gate['implementation_sha']==implementation_sha and gate['protocol_source_sha256']==protocol_sources()
            and gate['history_sha256']==digest(history) and gate['original_binding_sha256']==digest(prefix.binding),
            'authorized read-only gate historical/protocol identity')
    cid=gate['continuation_id'] if gate else str(uuid4());root=Path(root).absolute()
    require(root.parent==Path.home()/'.codex/task-evidence' and root.name.startswith('task13-additive-recovery-'),
        'fixed protected recovery evidence namespace')
    entries=build_execution_sources(prefix,cid,'C:\\Task13Continuation-'+cid.replace('-',''))
    for folder in ('tools','tools/canary'):entries[folder+'/__init__.py']=b'"""Protected recovery bundle namespace."""\n'
    for path in sorted(Path(__file__).parent.glob('*.py')):entries['tools/canary/task13_continuation/'+path.name]=read_file(path)
    operations=build_operations(prefix,cid,entries,root)
    from .recovery_observation_v2 import add_operation,SCRIPT
    add_operation(prefix,entries,operations)
    committed=subprocess.run(['git','-C',str(repository),'show',implementation_sha+':tools/canary/'+SCRIPT],
        capture_output=True,timeout=10)
    require(committed.returncode==0 and committed.stdout==entries[SCRIPT],'joint observer implementation source mismatch')
    from .recovery_dependencies_v2 import load_reviewed_runtime
    runtime,revision_entries=load_reviewed_runtime();entries.update(revision_entries)
    bind_closed_executables(operations,runtime)
    operations['management_argv'][1:1]=['-X','pycache_prefix='+str(root/'no-pyc')]
    entries['tools/canary/Read-Task13SealedPacket.ps1']=entries['Read-Task13SealedPacket.ps1']
    entries['operations.json']=canonical(operations);entries['recovery-history.json']=canonical(history)
    control=dict(schema='task13_recovery_control_v1',mode=mode,original_root=str(prefix.root.absolute()),
        original_binding=prefix.binding,claim_home=str((prefix.root/'continuation-v1-claims').absolute()),
        root_interpreter=str(Path(sys._base_executable).absolute()),implementation_sha=implementation_sha,
        protocol_version=2,baseline_revision=BASE_REVISION)
    entries['control.json']=canonical(control)
    entries['human-consent.json']=canonical(request['consent'] if request else capture_consent())
    if mode=='execution':
        from .recovery_gate import capture_verified_gate
        entries['operator-request.json']=canonical(request);entries['admission-gate.json']=canonical(gate)
        entries['admission-evidence.json']=canonical(capture_verified_gate(gate))
    bootstrap=("import sys\nfrom pathlib import Path\nROOT=Path("+repr(str(root))+")\n"
        "if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):raise SystemExit('isolated no-site bytecode-free startup required')\n"
        "if sys.pycache_prefix!=str(ROOT/'no-pyc'):raise SystemExit('fixed empty bytecode prefix required')\n"
        "sys.path.insert(0,str(ROOT))\nfrom tools.canary.task13_continuation.recovery_loader import bootstrap_entry\n"
        "if __name__=='__main__':bootstrap_entry(ROOT)\n")
    entries['bootstrap.py']=bootstrap.encode()
    closure=dict(schema='task13_recovery_reviewed_closure_v1',mode=mode,continuation_id=cid,
        original_binding=prefix.binding,implementation_sha=implementation_sha,protocol_source_sha256=protocol_sources(entries),
        execution=seal_sources(entries),runtime=runtime)
    root_argv=[control['root_interpreter'],'-I','-S','-B','-X','pycache_prefix='+str(root/'no-pyc'),str(root/'bootstrap.py'),
        '--observe-recovery-v2' if mode=='observation' else '--execute-recovery-v2-child']
    verify_feasibility(prefix,closure,entries,operations,root_argv)
    store=ProtectedStore.create_root(root)
    directories={root/Path(n).parent for n in entries if Path(n).parent!=Path('.')}
    for directory in sorted({p for d in directories for p in (d,*d.parents) if root in p.parents},key=lambda p:len(p.parts)):
        ProtectedStore.create_root(directory)
    for name,raw in entries.items():path=root/name;ProtectedStore(path.parent).create(path.name,raw)
    store.create('closure.json',canonical(closure))
    return dict(mode=mode,continuation_id=cid,source_closure_sha256=digest(closure),protocol_source_sha256=closure['protocol_source_sha256'],
        entries=len(entries),runtime_files=len(runtime),seq04_authorized=False,claims_created=False)

def prepare_observation(original_root,root,implementation_sha):
    return _prepare(original_root,root,implementation_sha,'observation')

def prepare_execution(original_root,root,gate):
    # Current implementation-only human message refuses here before bundle creation.
    return _prepare(original_root,root,gate['implementation_sha'],'execution',gate)
