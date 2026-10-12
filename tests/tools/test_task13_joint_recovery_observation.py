"""Joint read-only provenance and owned native PowerShell hosting; no target calls."""
import base64
import copy
import importlib
import subprocess
import time
from datetime import datetime,timedelta,timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tools.canary.task13_continuation.codec import canonical,digest,sha256
from tools.canary.task13_continuation.transport import envelope,validate_command
from tools.canary.task13_continuation.sources import build_stdin_delivery
from tests.tools.test_task13_command_transport import historical
from tests.tools.test_task13_additive_recovery import owned,supervisor_case

pytestmark=pytest.mark.no_db

def module():
    return importlib.import_module('tools.canary.task13_continuation.recovery_observation_v2')


@pytest.fixture
def captured():
    now=datetime.now(timezone.utc);mono=time.monotonic_ns();run=str(uuid4());vm=str(uuid4())
    original=dict(original_run_id=run)
    current=dict(observer_pid=123,observer_native_birth_utc='2026-10-12T00:00:00.1234567Z',utc=now.isoformat())
    identity=dict(caller_context=dict(pid=123),utc=now.isoformat())
    params=dict(RunId=run,ExpectedVmUuid=vm,RegistrySha256='c'*64,Ids=[1,2])
    spec=dict(schema='task13_joint_observer_binding_v2',mode='joint-current-identity-v2',run_id=run,vm_uuid=vm,
        current_source_sha256=sha256(b'current'),identity_source_sha256=sha256(b'identity'),
        identity_parameters_sha256=digest(params),actual_transport_count=7,logical_constituent_count=8)
    sources={'joint-current-source.ps1':b'current','Observe-Task13ProcessIdentity.ps1':b'identity',
        'joint-identity-parameters.json':canonical(params),'joint-observer-spec.json':canonical(spec)}
    capsule=dict(original=original,created_utc=(now-timedelta(seconds=2)).isoformat(),
        expires_utc=(now+timedelta(seconds=1200)).isoformat(),created_mono_ns=mono-2*10**9,deadline_mono_ns=mono+1200*10**9,
        source_closure=dict(execution=dict(entries={n:dict(bytes=len(raw),sha256=sha256(raw)) for n,raw in sources.items()})))
    def component(raw,source,channel):
        return dict(source_sha256=sha256(source),pipeline_state='Completed',had_errors=False,exception_type=None,
            exit_requested=channel=='console',exit_code=0 if channel=='console' else None,exit_count=1 if channel=='console' else 0,
            console_stdout_b64=base64.b64encode(raw if channel=='console' else b'').decode(),console_stderr_b64='',
            pipeline_stdout_b64=[] if channel=='console' else [base64.b64encode(raw).decode()],
            stream_counts={n:0 for n in ('error','warning','verbose','debug','information','progress')})
    birth=134362368001234567
    joint=dict(schema='task13_joint_current_identity_capture_v2',status='JOINT_READONLY_CAPTURED',
        observer=dict(pid=123,birth_filetime=birth,after_birth_filetime=birth,retained_not_exited=True),
        current=component(canonical(current)+b'\r\n',b'current','console'),
        process_identity=component(canonical(identity),b'identity','pipeline'))
    raw=envelope(canonical(joint),b'',0,now.isoformat(),mono,now.isoformat(),mono+1,True)
    prefix=SimpleNamespace(binding=original,plan=dict(run_id=run,vm_uuid=vm))
    return prefix,capsule,spec,raw


def test_joint_projections_retain_exact_raw_bytes_and_one_actual_transport(captured):
    p,c,s,j=captured;m=module();rows=m.project_joint(p,c,s,j)
    assert set(rows)=={'current','process_identity'}
    for name,row in rows.items():
        assert row['kind']=='IN_PROCESS_CAPTURED_PROJECTION_V2'
        assert row['joint_transport_sha256']==digest(j) and row['capture_name']==name
        assert row['dispatch_utc']==j['dispatch_utc'] and row['finished_mono_ns']==j['finished_mono_ns']
    assert base64.b64decode(rows['current']['stdout_b64']).endswith(b'\r\n')
    assert rows['current']['observation']['observer_pid']==rows['process_identity']['observation']['caller_context']['pid']


@pytest.mark.parametrize('fault',['native_birth','retained_exit','observer','source_pin','extra_stdout','console_error',
    'error_stream','exit2','missing_exit','identity_exit','overflow','missing_capture','extra_capture','raw_wire'])
def test_invalid_joint_captures_never_become_transport_complete_projections(captured,fault):
    p,c,s,j=captured;m=module();v=copy.deepcopy(j['observation'])
    if fault=='native_birth':v['observer']['after_birth_filetime']+=1
    elif fault=='retained_exit':v['observer']['retained_not_exited']=False
    elif fault=='observer':v['observer']['pid']=124
    elif fault=='source_pin':v['current']['source_sha256']='0'*64
    elif fault=='extra_stdout':v['current']['pipeline_stdout_b64']=['e30=']
    elif fault=='console_error':v['current']['console_stderr_b64']='e30='
    elif fault=='error_stream':v['current']['stream_counts']['error']=1
    elif fault=='exit2':v['current']['exit_code']=2
    elif fault=='missing_exit':v['current'].update(exit_requested=False,exit_code=None,exit_count=0)
    elif fault=='identity_exit':v['process_identity'].update(exit_requested=True,exit_code=0,exit_count=1)
    elif fault=='overflow':v['current']['console_stdout_b64']=base64.b64encode(b'a'*65537).decode()
    elif fault=='missing_capture':del v['current']
    elif fault=='extra_capture':v['synthetic']={}
    if fault!='raw_wire':
        j=dict(j,observation=v,stdout_b64=base64.b64encode(canonical(v)).decode(),stdout_sha256=digest(v))
    else:j=dict(j,stdout_sha256='0'*64)
    with pytest.raises(ValueError):m.project_joint(p,c,s,j)


def test_joint_starts_only_after_all_peer_transports_have_settled(captured,monkeypatch):
    p,c,s,j=captured;m=module();pending=set();finished=set();events=[]
    class Auth:
        capsule=c
        def check(self):pass
    class Transport:
        def call(self,tag,*args,**kwargs):
            pending.add(tag);time.sleep(.02);pending.remove(tag);finished.add(tag);events.append(tag)
            return j
        def powershell(self,prefix,script,tag,*args,**kwargs):
            if tag=='joint_identity':
                assert pending==set() and finished=={'management-state','provider','guest','inventory'}
                events.append('joint_identity');return j
            return self.call(tag)
    ops=dict(guest_ssh=['ssh'],management_argv=['python'],management_request={},provider_argv=['ssh'])
    entries={**{'delivery-'+name+'.ps1':b'closed' for name in ('guest','inventory','joint_identity','clock_guest')},
        **{'packet-'+name+'.bin':b'closed' for name in ('guest','inventory','joint_identity','clock_guest')},
        'provider-stdin.bin':b'closed','joint-observer-spec.json':canonical(s)}
    monkeypatch.setattr(m,'validate_state',lambda *a:None)
    monkeypatch.setattr(m,'validate_joint_state',lambda *a:None)
    result=m.reconcile(p,Auth(),Transport(),ops,entries)
    state=result['observation']
    assert state['recovery_observation']['actual_transport_count']==7
    assert state['recovery_observation']['logical_constituent_count']==8
    assert len(state['constituents'])==8 and events.index('joint_identity')>events.index('inventory')


@pytest.mark.parametrize('fault',[None,'projection','joint_sha','count','early_peer','early_clock','binding','missing_provenance'])
def test_full_state_requires_joint_links_and_causal_settlement(captured,monkeypatch,fault):
    p,c,s,j=captured;m=module();rows=m.project_joint(p,c,s,j)
    constituents={name:copy.deepcopy(j) for name in ('management','provider','guest','inventory','clock_guest','clock_management')}
    for name in ('management','provider','guest','inventory'):
        constituents[name]['dispatch_mono_ns']=j['dispatch_mono_ns']-2
        constituents[name]['finished_mono_ns']=j['dispatch_mono_ns']-1
    for name in ('clock_guest','clock_management'):
        constituents[name]['dispatch_mono_ns']=j['finished_mono_ns']+1
        constituents[name]['finished_mono_ns']=j['finished_mono_ns']+2
    meta=dict(mode=m.MODE,actual_transport_count=7,logical_constituent_count=8,binding=s,joint_transport=j,
        direct_transports_sha256={n:digest(v) for n,v in constituents.items()})
    constituents.update(rows)
    state=dict(constituents=constituents,recovery_observation=meta)
    if fault=='projection':state['constituents']['current']['stdout_sha256']='0'*64
    elif fault=='joint_sha':state['constituents']['process_identity']['joint_transport_sha256']='0'*64
    elif fault=='count':meta['actual_transport_count']=8
    elif fault=='binding':meta['binding']=dict(s,current_source_sha256='0'*64)
    elif fault=='missing_provenance':state.pop('recovery_observation')
    elif fault in ('early_peer','early_clock'):
        name='guest' if fault=='early_peer' else 'clock_guest'
        field='finished_mono_ns' if fault=='early_peer' else 'dispatch_mono_ns'
        state['constituents'][name][field]=j[field]+1 if fault=='early_peer' else j[field]-1
        meta['direct_transports_sha256'][name]=digest(state['constituents'][name])
    guards=[];monkeypatch.setattr(m,'validate_state',lambda *a:guards.append(True))
    if fault is None:
        m.validate_joint_state(p,c,state,j['finished_utc']);assert guards==[True]
    else:
        with pytest.raises(ValueError):m.validate_joint_state(p,c,state,j['finished_utc'])
        assert not guards


def test_readonly_window_requires_the_detached_reviewed_source_closure(captured):
    p,c,s,j=captured;m=module();window={k:v for k,v in c.items() if k not in ('original','source_closure')}
    window['schema']='task13_readonly_gate_window_v1'
    with pytest.raises(ValueError):m.project_joint(p,window,s,j)
    assert m.project_joint(p,window,s,j,c['source_closure'])['current']['observation']['observer_pid']==123


def test_captured_exited_conhost_keeps_identity_unknown_and_current_guard_closed(historical):
    from tools.canary.task13_continuation.codec import parse_json
    from tools.canary.task13_continuation.process_identity import classify_identity
    from tools.canary.task13_continuation.reconciliation import validate_current
    root=Path.home()/'.codex/task-evidence/task13-additive-recovery-execute-20261012-c'
    closure=parse_json((root/'closure.json').read_bytes())
    raw=(root/'process-references.json').read_bytes()
    assert sha256(raw)==closure['execution']['entries']['process-references.json']['sha256']
    references=parse_json(raw)['refs']
    current=parse_json((root/'transport-005-current-result.json').read_bytes())
    identity=parse_json((root/'transport-006-process_identity-result.json').read_bytes())['observation']
    ref=next(r for r in references if r['pid']==4264);row=next(r for r in identity['rows'] if r['pid']==4264)
    assert row['first']['wait_result']==0 and row['second'] is None
    assert classify_identity(ref,row)=='IDENTITY_UNKNOWN'
    with pytest.raises(ValueError,match='safe fixed recovery adapter gate'):validate_current(historical,current,identity)


@pytest.mark.parametrize('case',['pass','exit2','write_error','throw','console_error','overflow',
    'host_ui','extra_pipeline','missing_exit'])
def test_owned_powershell_host_preserves_exit_and_separate_streams(historical,case,monkeypatch):
    m=module();run=str(uuid4());vm=str(uuid4())
    # Owned local hosting failures expose their error; no production reader edit.
    from tools.canary.task13_continuation import sources
    real_read=sources.read_file
    def diagnostic_read(path):
        raw=real_read(path)
        if Path(path).name=='Read-Task13SealedPacket.ps1':
            raw=raw.replace(b'}catch{exit 2}',b'}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 2}')
        return raw
    monkeypatch.setattr(sources,'read_file',diagnostic_read)
    current="[Console]::Out.WriteLine(('{\"observer_pid\":'+$PID+',\"observer_native_birth_utc\":\"'+[Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToString('o')+'\"}'));exit 0"
    if case=='exit2':current=current.replace('exit 0','exit 2')
    elif case=='write_error':current="Write-Error 'owned';"+current
    elif case=='throw':current=current.replace('exit 0',"throw 'owned'")
    elif case=='console_error':current="[Console]::Error.WriteLine('owned');"+current
    elif case=='overflow':current="[Console]::Out.Write('a'*70000);exit 0"
    elif case=='host_ui':current="Write-Host 'owned';"+current
    elif case=='extra_pipeline':current="'owned';"+current
    elif case=='missing_exit':current=current.replace('exit 0','')
    identity="param($RunId,$ExpectedVmUuid,$RegistrySha256,$Ids);'{\"caller_context\":{\"pid\":'+$PID+'}}'"
    params=dict(RunId=run,ExpectedVmUuid=vm,RegistrySha256='a'*64,Ids=[1])
    source=m.joint_script(current.encode(),identity.encode(),params)
    bootstrap,packet,_=build_stdin_delivery(historical,source)
    argv=['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(bootstrap.decode().encode('utf-16-le')).decode()]
    validate_command(argv)
    result=subprocess.run(argv,input=packet,capture_output=True,timeout=40)
    if case=='pass':
        assert result.returncode==0 and not result.stderr, result.stderr.decode(errors='replace')
        from tools.canary.task13_continuation.codec import parse_json
        value=parse_json(result.stdout.strip())
        assert value['current']['exit_requested'] is True and value['current']['exit_code']==0
        assert value['process_identity']['exit_requested'] is False
        assert value['observer']['birth_filetime']==value['observer']['after_birth_filetime']
        assert value['observer']['retained_not_exited'] is True
    else:
        assert result.returncode!=0 or b'JOINT_READONLY_CAPTURED' in result.stdout
        if result.returncode==0:
            from tools.canary.task13_continuation.codec import parse_json
            value=parse_json(result.stdout.strip());component=value['current']
            assert component['exit_code']!=0 or component['had_errors'] or component['exception_type'] is not None \
                or component['console_stderr_b64'] or any(component['stream_counts'].values()) \
                or component['pipeline_stdout_b64'] or not component['exit_requested']


def test_unknown_captured_identity_refuses_before_new_execution_slot(supervisor_case,historical,monkeypatch):
    from tools.canary.task13_continuation.codec import parse_json
    from tools.canary.task13_continuation.reconciliation import validate_current
    from tools.canary.task13_continuation.recovery_admission import slot_state
    m,b=supervisor_case;root=Path.home()/'.codex/task-evidence/task13-additive-recovery-execute-20261012-c'
    current=parse_json((root/'transport-005-current-result.json').read_bytes())
    identity=parse_json((root/'transport-006-process_identity-result.json').read_bytes())['observation']
    def refused(*args):validate_current(historical,current,identity)
    monkeypatch.setattr(m,'reconcile_recovery',refused)
    monkeypatch.setattr(m.subprocess,'Popen',lambda *a,**k:pytest.fail('UNKNOWN cannot spawn'))
    with pytest.raises(ValueError,match='safe fixed recovery adapter gate'):m.supervise(b['root'])
    assert slot_state(b['prefix'],b['history'])=='ABSENT'


@pytest.mark.parametrize('ending',["exit 2","throw 'owned'","[Console]::Out.Write('a'*70000)",
    "[Console]::Error.WriteLine('owned');exit 0"])
def test_owned_console_out_and_error_are_restored_after_each_failure(historical,ending):
    m=module();params=dict(RunId=str(uuid4()),ExpectedVmUuid=str(uuid4()),RegistrySha256='a'*64,Ids=[1])
    source=m.joint_script(ending.encode(),b"param($RunId,$ExpectedVmUuid,$RegistrySha256,$Ids);'{}'",params)
    wrapped=("$savedOut=[Console]::Out;$savedError=[Console]::Error;$captured=@("+source+"\n);"
        "if(-not [Object]::ReferenceEquals($savedOut,[Console]::Out) -or -not [Object]::ReferenceEquals($savedError,[Console]::Error)){throw 'not restored'};"
        "if($captured.Count -ne 1){throw 'missing capture'};[Console]::Error.WriteLine('OWNED_CONSOLE_RESTORED');[Console]::Out.WriteLine($captured[0])")
    bootstrap,packet,_=build_stdin_delivery(historical,wrapped)
    argv=['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(bootstrap.decode().encode('utf-16-le')).decode()]
    validate_command(argv);result=subprocess.run(argv,input=packet,capture_output=True,timeout=40)
    assert result.returncode==0 and result.stderr==b'OWNED_CONSOLE_RESTORED\r\n'
    from tools.canary.task13_continuation.codec import parse_json
    assert parse_json(result.stdout.strip())['schema']=='task13_joint_current_identity_capture_v2'


def test_real_joint_factory_closes_ninth_packet_without_changing_old_payloads(historical):
    from tools.canary.task13_continuation.sources import build_execution_sources
    from tools.canary.task13_continuation.operations import build_operations
    from tools.canary.task13_continuation.recovery_bundle import verify_packets
    m=module();cid=str(uuid4());entries=build_execution_sources(historical,cid,'C:\\Task13Continuation-'+cid.replace('-',''))
    ops=build_operations(historical,cid,entries,Path('C:/Task13OwnedOfflineJoint'))
    before=dict(entries)
    m.add_operation(historical,entries,ops)
    assert all(entries[k]==value for k,value in before.items())
    assert verify_packets(historical,entries)=={'verified_packets':9}
    assert m.verify_operation(historical,entries,ops)['utf16_units_with_nul']<8192
    for name in ('joint-current-source.ps1','joint-identity-parameters.json','entry-joint_identity.ps1'):
        changed={**entries,name:entries[name]+b'changed'}
        with pytest.raises(ValueError):m.verify_operation(historical,changed,ops)
