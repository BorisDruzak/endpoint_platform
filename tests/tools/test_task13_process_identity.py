"""Instance guard faults; synthetic rows never stand for VM acceptance."""
import copy
from pathlib import Path
import os,subprocess,json,uuid
import pytest
from tools.canary.task13_continuation.codec import sha256

def sample(birth=200,image='C:\\Windows\\System32\\OpenSSH\\sshd.exe'):
    return {'status':'PRESENT','pid':400,'birth_filetime':birth,'image':image,'image_sha256':sha256(image.encode()),
            'parent_pid':300,'session_id':0,'handle_count':80,'wait_result':258,'native_error':0,
            'cim_count':1,'cim_birth_filetime':birth,'cim_image_equal':True,'cim_session_equal':True}

def case(birth=200):
    first=sample(birth)
    return {'pid':400,'first':first,'second':copy.deepcopy(first),'retained_first_not_exited':True,'error_type':None}

def reference(original=50):
    return {'pid':400,'absence_filetime':100,'original_birth_filetime':original}

def classify(row,ref=None):
    from tools.canary.task13_continuation.process_identity import classify_identity
    return classify_identity(reference() if ref is None else ref,row)

def test_native_reused_pid_with_live_ssh_service_is_eligible():
    assert classify(case())=='PID_REUSED'

def test_original_process_active_stays_blocked_even_if_image_differs():
    assert classify(case(50))=='ORIGINAL_PROCESS_ACTIVE'

def test_pinned_absence_witness_can_prove_reuse_without_invented_original_birth():
    assert classify(case(),reference(None))=='PID_REUSED'

def test_unexplained_pre_witness_birth_is_unknown():
    assert classify(case(90),reference(None))=='IDENTITY_UNKNOWN'

def test_two_consistent_native_absence_samples_are_absent():
    absent={'status':'ABSENT','pid':400,'birth_filetime':None,'image':None,'image_sha256':None,
            'parent_pid':None,'session_id':None,'handle_count':None,'wait_result':None,'native_error':87,
            'cim_count':0,'cim_birth_filetime':None,'cim_image_equal':None,'cim_session_equal':None}
    row={'pid':400,'first':absent,'second':copy.deepcopy(absent),'retained_first_not_exited':None,'error_type':None}
    assert classify(row)=='PROCESS_ABSENT'

@pytest.mark.parametrize('field,value',[('native_error',5),('cim_count',0),('cim_birth_filetime',201),
 ('cim_image_equal',False),('cim_session_equal',False),('image',None),('wait_result',0),('handle_count',None)])
def test_identity_read_denial_or_missing_field_is_unknown(field,value):
    row=case();row['first'][field]=value
    assert classify(row)=='IDENTITY_UNKNOWN'

@pytest.mark.parametrize('mutation',['new_birth','new_image','first_exit','second_absent','parent_changed','session_changed'])
def test_exit_restart_or_changed_identity_race_is_unknown(mutation):
    row=case()
    if mutation=='new_birth':row['second']=sample(201)
    elif mutation=='new_image':row['second']=sample(200,'C:\\Other.exe')
    elif mutation=='first_exit':row['retained_first_not_exited']=False
    elif mutation=='second_absent':row['second']['status']='ABSENT'
    elif mutation=='parent_changed':row['second']['parent_pid']=301
    else:row['second']['session_id']=1
    assert classify(row)=='IDENTITY_UNKNOWN'

def test_guest_label_cannot_override_unknown():
    row=case();row['state']='PID_REUSED';row['error_type']='AccessDenied'
    assert classify(row)=='IDENTITY_UNKNOWN'

def test_cim_microsecond_projection_keeps_exact_native_identity():
    row=case()
    for s in (row['first'],row['second']):s['birth_filetime']=209
    assert classify(row)=='PID_REUSED'

def test_native_change_inside_one_cim_microsecond_is_unknown():
    row=case();row['second']['birth_filetime']=201
    assert classify(row)=='IDENTITY_UNKNOWN'

def test_observer_never_queries_command_arguments_or_terminates_processes():
    path=Path(__file__).resolve().parents[2]/'tools/canary/Observe-Task13ProcessIdentity.ps1'
    text=path.read_text()
    assert 'QueryFullProcessImageName' in text and 'GetProcessHandleCount' in text
    assert 'CommandLine' not in text and 'TerminateProcess' not in text and 'Stop-Process' not in text

@pytest.mark.skipif(os.name!='nt',reason='owned native observer')
def test_actual_observer_retains_two_native_handles_for_owned_live_process():
    from tools.canary.task13_continuation.process_identity import classify_identity
    path=Path(__file__).resolve().parents[2]/'tools/canary/Observe-Task13ProcessIdentity.ps1'
    source=path.read_text()
    script=("$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';& {"+source+"} -RunId '"+str(uuid.uuid4())+"' -ExpectedVmUuid ([Guid](Get-CimInstance Win32_ComputerSystemProduct).UUID)"
            " -RegistrySha256 '"+'0'*64+"' -Ids @("+str(os.getpid())+")")
    import base64
    argv=[str(Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe'),
          '-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16-le')).decode()]
    result=subprocess.run(argv,input=b'',capture_output=True,timeout=30,creationflags=0x08000000)
    assert result.returncode==0 and result.stderr==b''
    value=json.loads(result.stdout)
    row=value['rows'][0]
    assert row['error_type'] is None
    ref={'pid':os.getpid(),'absence_filetime':1,'original_birth_filetime':row['first']['birth_filetime']}
    diagnostics={k:row['first'][k] for k in ('status','native_error','cim_count','wait_result','cim_image_equal','cim_session_equal')}
    diagnostics['birth_delta']=row['first']['birth_filetime']-row['first']['cim_birth_filetime']
    diagnostics['changed_fields']=[k for k in row['first'] if row['first'][k]!=row['second'][k]]
    diagnostics['retained']=row['retained_first_not_exited']
    assert classify_identity(ref,row)=='ORIGINAL_PROCESS_ACTIVE',json.dumps(diagnostics)
