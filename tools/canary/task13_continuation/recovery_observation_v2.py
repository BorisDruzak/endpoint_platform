"""Recovery-only joint observer; ordinary identity and reconciliation guards stay intact."""
import base64
import time
from concurrent.futures import ThreadPoolExecutor

from .codec import canonical,digest,integer,parse_json,require,sha256
from .history import read_file
from .operations import original_source,thin_script
from .process_identity import filetime
from .receipt import observation,raw_bytes
from .reconciliation import validate_state
from .sources import CANARY,build_stdin_delivery,replace_once
from .transport import envelope,utc,powershell_argv,validate_command

MODE='joint-current-identity-v2'
SCRIPT='Observe-Task13RecoveryJoint.ps1'
STREAMS={'error','warning','verbose','debug','information','progress'}
COMPONENT_KEYS={'source_sha256','pipeline_state','had_errors','exception_type','exit_requested','exit_code','exit_count',
                'console_stdout_b64','console_stderr_b64','pipeline_stdout_b64','stream_counts'}


def joint_script(current,identity,parameters):
    require(type(current) is bytes and type(identity) is bytes and type(parameters) is dict,'exact joint source inputs')
    raw_params=canonical(parameters)
    args=dict(CurrentSourceBase64=base64.b64encode(current).decode(),CurrentSourceSha256=sha256(current),
        IdentitySourceBase64=base64.b64encode(identity).decode(),IdentitySourceSha256=sha256(identity),
        IdentityParametersBase64=base64.b64encode(raw_params).decode(),IdentityParametersSha256=sha256(raw_params))
    source=read_file(CANARY/SCRIPT).decode('utf-8')
    return '& {\n'+source+'\n} '+ ' '.join('-'+k+" '"+v+"'" for k,v in args.items())


def add_operation(prefix,entries,operations):
    current=replace_once(original_source(prefix,'Observe-NativeWrapperCurrent.ps1').decode(),
        'a43598a5-59f9-4a01-8486-cea0d4924709',prefix.plan['run_id']).encode()
    identity=entries['Observe-Task13ProcessIdentity.ps1']
    registry=parse_json(entries['process-references.json'])
    params=dict(RunId=registry['run_id'],ExpectedVmUuid=registry['vm_uuid'],RegistrySha256=digest(registry),
                Ids=[v['pid'] for v in registry['refs']])
    spec=dict(schema='task13_joint_observer_binding_v2',mode=MODE,run_id=prefix.plan['run_id'],vm_uuid=prefix.plan['vm_uuid'],
        current_source_sha256=sha256(current),identity_source_sha256=sha256(identity),identity_parameters_sha256=digest(params),
        actual_transport_count=7,logical_constituent_count=8)
    entries['joint-current-source.ps1']=current
    entries['joint-identity-parameters.json']=canonical(params)
    entries['joint-observer-spec.json']=canonical(spec)
    entries[SCRIPT]=read_file(CANARY/SCRIPT)
    entries['tools/canary/'+SCRIPT]=entries[SCRIPT]
    entries['entry-joint_identity.ps1']=thin_script(joint_script(current,identity,params)).encode()
    bootstrap,packet,pin=build_stdin_delivery(prefix,entries['entry-joint_identity.ps1'].decode())
    entries['delivery-joint_identity.ps1']=bootstrap
    entries['packet-joint_identity.bin']=packet
    entries['packet-joint_identity-binding.json']=canonical(pin)
    operations['recovery_observation_mode']=MODE


def verify_operation(prefix,entries,operations):
    require(operations.get('recovery_observation_mode')==MODE,'explicit recovery joint mode required')
    expected=dict(entries);expected_ops=dict(operations);add_operation(prefix,expected,expected_ops)
    for name in ('joint-current-source.ps1','joint-identity-parameters.json','joint-observer-spec.json',SCRIPT,
                 'tools/canary/'+SCRIPT,'entry-joint_identity.ps1'):
        require(entries[name]==expected[name],'joint original source/parameter pin changed')
    require(operations==expected_ops,'joint operation selector changed')
    argv=powershell_argv(operations['guest_ssh'],entries['delivery-joint_identity.ps1'].decode())
    return validate_command(argv,remote_command=argv[-1])


def _binding(prefix,capsule,spec,closure=None):
    if 'source_closure' in capsule:
        require(closure is None or closure==capsule['source_closure'],'joint live source closure changed')
        closure=capsule['source_closure']
        require(capsule['original']==prefix.binding,'joint live original binding changed')
    else:
        require(capsule.get('schema')=='task13_readonly_gate_window_v1' and closure is not None,
            'only reviewed read-only window may supply detached source pins')
    require(type(spec) is dict and set(spec)=={'schema','mode','run_id','vm_uuid','current_source_sha256',
        'identity_source_sha256','identity_parameters_sha256','actual_transport_count','logical_constituent_count'}
        and spec['schema']=='task13_joint_observer_binding_v2' and spec['mode']==MODE
        and spec['run_id']==prefix.plan['run_id']==prefix.binding['original_run_id']
        and spec['vm_uuid']==prefix.plan['vm_uuid'] and type(spec['actual_transport_count']) is int
        and spec['actual_transport_count']==7 and type(spec['logical_constituent_count']) is int
        and spec['logical_constituent_count']==8,'exact joint observer identity/mode')
    pins=closure['execution']['entries']
    require(pins['joint-observer-spec.json']==dict(bytes=len(canonical(spec)),sha256=digest(spec))
        and spec['current_source_sha256']==pins['joint-current-source.ps1']['sha256']
        and spec['identity_source_sha256']==pins['Observe-Task13ProcessIdentity.ps1']['sha256']
        and spec['identity_parameters_sha256']==pins['joint-identity-parameters.json']['sha256'],
        'closed joint source/parameters/specification required')


def _component(value,source,channel):
    require(type(value) is dict and set(value)==COMPONENT_KEYS and value['source_sha256']==source
        and value['pipeline_state']=='Completed' and value['had_errors'] is False and value['exception_type'] is None,
        'complete in-process capture required')
    counts=value['stream_counts']
    require(type(counts) is dict and set(counts)==STREAMS and all(type(v) is int and v==0 for v in counts.values()),
        'unexpected in-process stream output')
    require(type(value['exit_count']) is int and type(value['exit_requested']) is bool,'explicit captured exit request')
    console=raw_bytes(value['console_stdout_b64']);error=raw_bytes(value['console_stderr_b64'])
    pipeline=value['pipeline_stdout_b64']
    require(not error and len(console)<=65536 and type(pipeline) is list and len(pipeline)<=1,'bounded separate captured outputs')
    if channel=='console':
        require(value['exit_requested'] is True and type(value['exit_code']) is int and value['exit_code']==0
            and value['exit_count']==1 and pipeline==[],'original current explicit normal exit required')
        raw=console
    elif channel=='identity_console':
        require(value['exit_requested'] is False and value['exit_code'] is None and value['exit_count']==0
            and pipeline==[],'original identity output/exit semantics required')
        raw=console
    else:raise ValueError('exact original capture channel required')
    parse_json(raw.strip())
    return raw


def project_joint(prefix,capsule,spec,joint,closure=None):
    _binding(prefix,capsule,spec,closure)
    value=observation(joint,capsule,maximum=35)
    require(set(value)=={'schema','status','observer','current','process_identity'}
        and value['schema']=='task13_joint_current_identity_capture_v2' and value['status']=='JOINT_READONLY_CAPTURED',
        'one complete actual joint capture required')
    actor=value['observer']
    require(type(actor) is dict and set(actor)=={'pid','birth_filetime','after_birth_filetime','retained_not_exited'}
        and actor['retained_not_exited'] is True and type(actor['after_birth_filetime']) is int
        and integer(actor['birth_filetime'],1)==actor['after_birth_filetime'],'retained same joint observer birth required')
    integer(actor['pid'],1,2**32-1)
    raw={'current':_component(value['current'],spec['current_source_sha256'],'console'),
        'process_identity':_component(value['process_identity'],spec['identity_source_sha256'],'identity_console')}
    current,identity=(parse_json(raw[n].strip()) for n in ('current','process_identity'))
    require(type(current['observer_pid']) is int and type(identity['caller_context']['pid']) is int
        and current['observer_pid']==identity['caller_context']['pid']==actor['pid']
        and filetime(current['observer_native_birth_utc'])==actor['birth_filetime'],
        'same actual current/native identity observer required')
    rows={}
    for name,data in raw.items():
        projected=envelope(data,b'',0,joint['dispatch_utc'],joint['dispatch_mono_ns'],
            joint['finished_utc'],joint['finished_mono_ns'],True)
        projected.update(kind='IN_PROCESS_CAPTURED_PROJECTION_V2',capture_name=name,joint_transport_sha256=digest(joint))
        rows[name]=projected
    return rows


def validate_joint_state(prefix,capsule,state,at,closure=None):
    meta=state.get('recovery_observation')
    require(type(meta) is dict and set(meta)=={'mode','actual_transport_count','logical_constituent_count',
        'binding','joint_transport','direct_transports_sha256'} and meta['mode']==MODE
        and type(meta['actual_transport_count']) is int and meta['actual_transport_count']==7
        and type(meta['logical_constituent_count']) is int and meta['logical_constituent_count']==8,
        'explicit recovery joint provenance required')
    projections=project_joint(prefix,capsule,meta['binding'],meta['joint_transport'],closure)
    for name,row in projections.items():require(state['constituents'][name]==row,'joint captured projection was replaced')
    direct={n:digest(v) for n,v in state['constituents'].items() if n not in projections}
    require(len(direct)==6 and direct==meta['direct_transports_sha256'],'six real independent peer/clock transports')
    joint=meta['joint_transport']
    for name in ('management','provider','guest','inventory'):
        require(state['constituents'][name]['finished_mono_ns']<=joint['dispatch_mono_ns'],
            'peer transport not settled before joint observation')
    for name in ('clock_guest','clock_management'):
        require(joint['finished_mono_ns']<=state['constituents'][name]['dispatch_mono_ns'],
            'clock observation preceded joint settlement')
    validate_state(prefix,capsule,state,at)


def reconcile(prefix,auth,transport,operations,entries,closure=None):
    sent_utc,sent_ns=utc(),time.monotonic_ns()
    def ps(name,seconds=25):
        return transport.powershell(operations['guest_ssh'],entries['delivery-'+name+'.ps1'].decode(),
            name,seconds,entries['packet-'+name+'.bin'])
    def management(action):
        return transport.call('management-'+action,operations['management_argv'],
            canonical({**operations['management_request'],'action':action}),30 if action=='state' else 5)
    work={'management':lambda:management('state'),
        'provider':lambda:transport.call('provider',operations['provider_argv'],entries['provider-stdin.bin'],25),
        'guest':lambda:ps('guest'),'inventory':lambda:ps('inventory')}
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures={name:pool.submit(fn) for name,fn in work.items()}
        constituents={name:future.result() for name,future in futures.items()}
    auth.check()
    joint=ps('joint_identity',35);binding=parse_json(entries['joint-observer-spec.json'])
    constituents.update(project_joint(prefix,auth.capsule,binding,joint,closure))
    with ThreadPoolExecutor(max_workers=2) as pool:
        guest=pool.submit(ps,'clock_guest',5);management_clock=pool.submit(management,'clock')
        constituents.update(clock_guest=guest.result(),clock_management=management_clock.result())
    meta=dict(mode=MODE,actual_transport_count=7,logical_constituent_count=8,binding=binding,joint_transport=joint,
        direct_transports_sha256={n:digest(v) for n,v in constituents.items() if n not in ('current','process_identity')})
    state=dict(schema='task13_reconciled_state_v1',predicate_version='task13_readonly_reconciliation_v1',status='PASS',
        original=prefix.binding,constituents=constituents,constituent_sha256=digest(constituents),recovery_observation=meta)
    done_utc,done_ns=utc(),time.monotonic_ns()
    validate_joint_state(prefix,auth.capsule,state,done_utc,closure)
    result=envelope(canonical(state),b'',0,sent_utc,sent_ns,done_utc,done_ns,True)
    result['kind']='ROOT_VALIDATED_JOINT_RECONCILIATION_V2';auth.check()
    return result
