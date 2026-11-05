from contextlib import nullcontext
from types import SimpleNamespace
from uuid import uuid4

import pytest

from pc_agent.platform.windows import staged_recovery as recovery
from pc_agent.tests.windows.test_staged_update_state import staged, native_protected_root


def test_native_acceptance_restores_both_roles_even_when_nothing_was_captured(monkeypatch):
    sessions = [{'session_id': 2, 'sid': 'S-1-5-21-100'}]
    running = []
    monkeypatch.setattr(recovery, '_active_sessions', lambda: sessions)
    monkeypatch.setattr(recovery, '_probe_companions', lambda _: list(running))
    def launch(paths, operation, item):
        running.append(item)
        return True
    monkeypatch.setattr(recovery, '_restore_companion_task', launch)
    result = recovery.restore_expected_companions(SimpleNamespace(), str(uuid4()), checkpoint=lambda: None)
    assert result == 'running'
    assert {row['role'] for row in running} == {'sensor', 'tray'}


def test_native_continuation_does_not_call_a_launch_request_running(monkeypatch):
    monkeypatch.setattr(recovery, '_active_sessions', lambda: [{'session_id': 2, 'sid': 'S-1-5-21-100'}])
    monkeypatch.setattr(recovery, '_probe_companions', lambda _: [])
    monkeypatch.setattr(recovery, '_restore_companion_task', lambda *_: True)
    with pytest.raises(ValueError, match='RECOVERY_REQUIRED'):
        recovery.restore_expected_companions(SimpleNamespace(), str(uuid4()), checkpoint=lambda: None, timeout_seconds=0)


def test_native_continuation_never_launches_into_a_replaced_session(monkeypatch):
    original = {'session_id': 2, 'sid': 'S-1-5-21-100'}
    samples = iter([[original], [{'session_id': 2, 'sid': 'S-1-5-21-200'}]])
    monkeypatch.setattr(recovery, '_active_sessions', lambda: next(samples, []))
    monkeypatch.setattr(recovery, '_probe_companions', lambda _: [])
    monkeypatch.setattr(recovery, '_restore_companion_task', lambda *_: pytest.fail('replaced session launch'))
    assert recovery.restore_expected_companions(SimpleNamespace(), str(uuid4()), checkpoint=lambda: None) == 'session-unavailable'

@pytest.mark.parametrize('case', ['no-record', 'trial', 'rolled-back', 'wrong-owner', 'wrong-package'])
def test_unaccepted_native_state_cannot_provision_observer(monkeypatch, case):
    from pc_agent.platform.windows import native_setup_continuation as continuation
    cap = {'operation': 'install', 'transaction_id': str(uuid4()), 'package': {'version':'3.2.166'},
           'owner': {'pid':1}, 'recovery':False, 'uninstall_finalization':False}
    record = SimpleNamespace(phase='accepted', binding=SimpleNamespace(operation_id=cap['transaction_id'], new_release=cap['package']))
    if case == 'no-record': record = None
    elif case in {'trial', 'rolled-back'}: record.phase = case
    elif case == 'wrong-package': record.binding.new_release = {'version':'3.2.165'}
    monkeypatch.setattr(continuation.state, 'read_staged_update', lambda _: record)
    monkeypatch.setattr(continuation.recovery, 'owner_authorized', lambda *_: case != 'wrong-owner')
    monkeypatch.setattr(continuation, '_completed_native_receipt', lambda *_: (_ for _ in ()).throw(ValueError('RECOVERY_REQUIRED')))
    monkeypatch.setattr(continuation, '_settled_native', lambda _: None)
    monkeypatch.setattr(continuation, 'pending_continuation', lambda _: None)
    with pytest.raises(ValueError, match='RECOVERY_REQUIRED'):
        continuation.accepted_native_record(SimpleNamespace(), cap)


def test_fresh_native_uses_completed_owner_receipt_without_core_pending(monkeypatch):
    from pc_agent.platform.windows import native_setup_continuation as continuation
    cap = {'operation': 'install', 'transaction_id': str(uuid4()), 'package': {}, 'owner': {},
           'recovery':False, 'uninstall_finalization':False}
    checked = []
    monkeypatch.setattr(continuation, 'pending_continuation', lambda _: None)
    monkeypatch.setattr(continuation.state, 'read_staged_update', lambda _: None)
    monkeypatch.setattr(continuation, '_settled_native', lambda _: checked.append('settled'))
    monkeypatch.setattr(continuation, '_completed_native_receipt', lambda _, value: checked.append(value))
    assert continuation.accepted_native_record(SimpleNamespace(), cap) is None
    assert checked == ['settled', cap]

@pytest.mark.parametrize('defect', ['source', 'unsigned', 'version'])
def test_native_helper_packaging_rejects_unbound_observer(tmp_path, defect):
    from tools.canary.setup_client_payload import signed_setup_client_payload
    source = tmp_path / 'packaging/windows/EndpointSetupUpdater.ps1'
    source.parent.mkdir(parents=True)
    source.write_text("$script:ClientVersion='1.0.6'\nsource")
    asset = tmp_path / 'signed.ps1'
    text = source.read_text() + '\n# SIG # Begin signature block\nsigned\n# SIG # End signature block\n'
    if defect == 'source': text = text.replace('source', 'other')
    elif defect == 'unsigned': text = source.read_text()
    else: source.write_text(source.read_text().replace('1.0.6','../bad')); text = text.replace('1.0.6','../bad')
    asset.write_text(text)
    with pytest.raises(ValueError):
        signed_setup_client_payload(tmp_path, tmp_path/'work', asset)


def test_native_helper_packages_exact_signed_bytes_and_source_binding(tmp_path):
    import json, hashlib
    from tools.canary.setup_client_payload import signed_setup_client_payload
    source = tmp_path / 'packaging/windows/EndpointSetupUpdater.ps1'
    source.parent.mkdir(parents=True)
    source.write_text("$script:ClientVersion='1.0.6'\nsource")
    asset = tmp_path / 'signed.ps1'
    asset.write_text(source.read_text()+'\n# SIG # Begin signature block\nsigned\n# SIG # End signature block\n')
    datas = signed_setup_client_payload(tmp_path, tmp_path/'work', asset)
    assert (str(asset.resolve()), 'setup-updater') in datas
    metadata = next(path for path, target in datas if path.endswith('.json'))
    value = json.loads(__import__('pathlib').Path(metadata).read_text())
    assert value['script_sha256'] == hashlib.sha256(asset.read_bytes()).hexdigest()
    assert value['client_version'] == '1.0.6'

@pytest.mark.parametrize('defect', ['digest', 'source', 'version', 'extra'])
def test_native_observer_refuses_corrupt_source_bound_payload(tmp_path, defect):
    import json, hashlib
    from pc_agent.platform.windows import native_setup_observer as observer
    body = "$script:ClientVersion='1.0.6'"
    script = tmp_path/'EndpointSetupUpdater.ps1'
    script.write_text(body+'\n# SIG # Begin signature block\nsigned\n# SIG # End signature block\n')
    value = {'schema_version':1, 'client_version':'1.0.6', 'script_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),
             'source_sha256':hashlib.sha256(body.encode()).hexdigest()}
    if defect == 'digest': value['script_sha256'] = '0'*64
    elif defect == 'source': value['source_sha256'] = '0'*64
    elif defect == 'version': value['client_version'] = '../bad'
    else: value['arbitrary'] = 'bad'
    (tmp_path/'EndpointSetupUpdater.payload.json').write_text(json.dumps(value))
    with pytest.raises(ValueError): observer.read_packaged_observer(tmp_path)


def test_native_observer_requires_frozen_packaged_input(monkeypatch):
    from pc_agent.platform.windows import native_setup_observer as observer
    monkeypatch.setattr(observer.sys, 'frozen', False, raising=False)
    with pytest.raises(ValueError, match='RECOVERY_REQUIRED'):
        observer.provision_packaged_observer(SimpleNamespace())

def test_owner_bridge_exposes_only_authenticated_native_continuation(monkeypatch):
    from pc_agent.platform.windows import installer_transaction_bridge as bridge
    from pc_agent.platform.windows import native_setup_continuation as continuation
    from pc_agent.platform.windows.installer_host_entry import _parser
    assert 'native-continuation' in bridge.PHASES
    assert _parser().parse_args(['--installer-phase','native-continuation','--installer-session',str(uuid4())]).installer_phase == 'native-continuation'
    calls = []
    monkeypatch.setattr(continuation, 'execute_native_continuation', lambda c,p: calls.append((c,p)) or {'users':'running'})
    client = SimpleNamespace(phase='native-continuation', capability={})
    paths = SimpleNamespace()
    assert bridge.execute_authorized_phase(client, paths) == {'users':'running'}
    assert calls == [(client, paths)]

@pytest.mark.parametrize('users,observer,passes', [('running','provisioned',True),('not-required','provisioned',True),('session-unavailable','provisioned',True),('launch-requested','provisioned',False),('running','missing',False)])
def test_wrapper_continuation_checks_observer_and_observed_companions(tmp_path, users, observer, passes):
    import subprocess
    from pathlib import Path
    source = Path(__file__).resolve().parents[3]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path/'continuation.ps1'
    script.write_text(r'''param($Source,$Users,$Observer,$Expected)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse'}
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Complete-NativeContinuation'},$true)
if(!$node){throw 'missing native continuation'}
Invoke-Expression $node.Extent.Text
function Invoke-InstallerHelper {param($Bridge,$Phase);if($Phase -cne 'native-continuation'){throw 'wrong phase'};return [pscustomobject]@{operation_id=$Bridge.TransactionId;users=$Users;observer=$Observer}}
$ok=$true
try{Complete-NativeContinuation ([pscustomobject]@{TransactionId='operation'})}catch{$ok=$false}
if($ok -ne ($Expected -eq 'True')){throw 'wrong acceptance'}
'passed'
''')
    result = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source),users,observer,str(passes)], capture_output=True,text=True,timeout=15)
    assert result.returncode == 0, result.stderr


def test_continuation_hold_binds_native_acceptance_and_cannot_be_replaced(staged):
    from pc_agent.platform.windows import native_setup_continuation as continuation, durable_state
    _, paths, binding, owner = staged
    cap = {'transaction_id':binding.operation_id, 'package':binding.new_release}
    with durable_state.installer_mutation_checkpoints(lambda:None):
        continuation.begin_continuation_hold(paths, cap)
        assert continuation.pending_continuation(paths) == cap
        with pytest.raises(ValueError):
            continuation.begin_continuation_hold(paths, {**cap,'transaction_id':str(uuid4())})
        continuation.finish_continuation_hold(paths, cap)
        assert continuation.pending_continuation(paths) is None

@pytest.mark.skipif(__import__('os').name != 'nt', reason='actual Windows task registration')
def test_actual_interactive_task_registration_uses_resolved_account_without_trigger(monkeypatch, staged):
    import os
    import win32api, win32con, win32security, win32ts, win32com.client
    from pc_agent.platform.windows import durable_state
    _, paths, binding, owner = staged
    token=win32security.OpenProcessToken(win32api.GetCurrentProcess(),win32con.TOKEN_QUERY)
    try: sid=win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token,win32security.TokenUser)[0])
    finally: token.Close()
    session=win32ts.ProcessIdToSessionId(os.getpid())
    if session <= 0: pytest.skip('interactive operator token required for registration-only proof')
    item={'role':'sensor','session_id':session,'sid':sid}
    real_dispatch=win32com.client.Dispatch
    real=real_dispatch('Schedule.Service');real.Connect()
    folder=real.GetFolder('\\')
    calls=[]; errors=[]
    class Task:
        def __init__(self,registered): self.Xml=registered.Xml
        def RunEx(self,*args): calls.append(args)  # Intentionally never run a process.
    class Folder:
        def RegisterTaskDefinition(self,name,definition,flags,account,password,logon,security):
            assert definition.Triggers.Count == 0
            assert account != sid
            try: registered=folder.RegisterTaskDefinition(name,definition,flags,account,password,logon,security)
            except Exception as error:
                errors.append(repr(error)); raise
            from xml.etree import ElementTree as ET
            xml=ET.fromstring(registered.Xml)
            assert xml.findtext('{*}Principals/{*}Principal/{*}UserId')==sid
            return Task(registered)
        def DeleteTask(self,*args): folder.DeleteTask(*args)
    class Scheduler:
        def Connect(self): pass
        def GetFolder(self,_): return Folder()
        def NewTask(self,n): return real.NewTask(n)
    monkeypatch.setattr(win32com.client,'Dispatch',lambda value,*args,**kwargs:Scheduler() if value == 'Schedule.Service' else real_dispatch(value,*args,**kwargs))
    monkeypatch.setattr(recovery,'_active_sessions',lambda:[{'session_id':session,'sid':sid}])
    try:
        with durable_state.installer_mutation_checkpoints(lambda:None):
            assert recovery._restore_companion_task(paths,binding.operation_id,item) is True, errors
    finally:
        try: folder.DeleteTask('EndpointCompanionRestore-'+binding.operation_id+'-sensor-'+str(session),0)
        except Exception: pass
    assert calls==[(None,4,session,'')]


def test_native_continuation_rejects_duplicate_companion_processes(monkeypatch):
    sessions=[{'session_id':2,'sid':'S-1-5-21-100'}]
    roles=[{'role':role,**sessions[0]} for role in ('sensor','tray')]
    monkeypatch.setattr(recovery,'_active_sessions',lambda:sessions)
    monkeypatch.setattr(recovery,'_probe_companions',lambda _:roles+[roles[0]])
    with pytest.raises(ValueError,match='RECOVERY_REQUIRED'):
        recovery.restore_expected_companions(SimpleNamespace(),str(uuid4()),checkpoint=lambda:None,timeout_seconds=0)

@pytest.mark.parametrize('mode', ['fresh','staged'])
@pytest.mark.parametrize('failure', ['observer','companions','interrupt'])
def test_native_failure_retains_hold_and_truth_then_exact_retry_only_finishes_continuation(staged, monkeypatch, mode, failure):
    from pc_agent.platform.windows import native_setup_continuation as continuation, native_setup_observer as observer
    from pc_agent.platform.windows import installer_data_security, msi_inventory
    from pc_agent.tests.windows.test_staged_update_state import begin, move
    _,paths,binding,owner=staged
    record=None
    if mode=='staged':
        begin(staged)
        for before,after in [('preparing','prepared'),('prepared','switching'),('switching','native-settled')]: move(staged,before,after)
        move(staged,'native-settled','trial',attempt_id=str(uuid4()));move(staged,'trial','accepted')
        record=continuation.state.read_staged_update(paths)
    leaf=continuation.state._path(paths)
    original=leaf.read_bytes() if leaf.exists() else None
    cap={'operation':'install','transaction_id':binding.operation_id,'package':binding.new_release,'owner':owner,
         'session_id':str(uuid4()),'selected':None,'previous':None,'recovery':False,'uninstall_finalization':False}
    client=SimpleNamespace(capability=cap,checkpoint=lambda:None,request=lambda *args:None)
    monkeypatch.setattr(continuation,'accepted_native_record',lambda *_:record)
    monkeypatch.setattr(msi_inventory,'read_expected_package',lambda *_:SimpleNamespace(package=SimpleNamespace(version=binding.new_release['version'])))
    monkeypatch.setattr(continuation.provenance,'verified_foundation_release',lambda _:binding.new_release)
    monkeypatch.setattr(continuation.provenance,'inspect_installed_core',lambda *a,**kw:SimpleNamespace(current=object()))
    monkeypatch.setattr(installer_data_security,'verify_preserved',lambda *_:None)
    monkeypatch.setattr(msi_inventory,'verified_foundation_bytes',lambda *_:nullcontext())
    monkeypatch.setattr(recovery,'_service_outcomes',lambda *_:{})
    def fail(*a,**kw):
        if failure=='interrupt': raise KeyboardInterrupt()
        raise ValueError('RECOVERY_REQUIRED')
    monkeypatch.setattr(observer,'provision_packaged_observer',fail if failure=='observer' else lambda _:'provisioned')
    monkeypatch.setattr(recovery,'restore_expected_companions',fail if failure!='observer' else lambda *a,**kw:'running')
    with pytest.raises(KeyboardInterrupt if failure=='interrupt' else ValueError): continuation.execute_native_continuation(client,paths)
    assert continuation.pending_continuation(paths)=={'transaction_id':binding.operation_id,'package':binding.new_release}
    assert (leaf.read_bytes() if leaf.exists() else None)==original
    assert not paths.pending_path.exists()
    monkeypatch.setattr(observer,'provision_packaged_observer',lambda _:'provisioned')
    monkeypatch.setattr(recovery,'restore_expected_companions',lambda *a,**kw:'running')
    assert continuation.execute_native_continuation(client,paths)['users']=='running'
    assert continuation.pending_continuation(paths) is None
    assert (leaf.read_bytes() if leaf.exists() else None)==original


def test_native_hold_is_visible_to_readonly_core_and_fleet_gate(staged,monkeypatch):
    from pc_agent.platform.windows import native_setup_continuation as continuation, update_transaction, durable_state
    _,paths,binding,owner=staged
    cap={'transaction_id':binding.operation_id,'package':binding.new_release}
    monkeypatch.setattr(update_transaction,'_assert_install_directory_security',lambda _:None)
    monkeypatch.setattr(update_transaction,'_assert_state_security',lambda _:None)
    assert update_transaction.active_update_state(paths) is None
    with durable_state.installer_mutation_checkpoints(lambda:None): continuation.begin_continuation_hold(paths,cap)
    assert update_transaction.active_update_state(paths)=='native-continuation-pending'

@pytest.mark.parametrize('defect',['owner','helper','transaction','package'])
def test_fresh_continuation_cannot_recreate_an_unrelated_native_owner(monkeypatch,defect):
    from pc_agent.platform.windows import native_setup_continuation as continuation, installer_transaction_bridge as bridge, installer_data_security as security
    cap={'owner':{'pid':1},'helper_sha256':'a'*64,'transaction_id':str(uuid4()),'package':{'version':'3.2.166'},'session_id':str(uuid4())}
    original={**cap,'operation':'install'}
    original[{'owner':'owner','helper':'helper_sha256','transaction':'transaction_id','package':'package'}[defect]]=None
    monkeypatch.setattr(bridge,'_request_data',lambda *_:{})
    monkeypatch.setattr(security,'_read',lambda *_:{'binding':{'session_id':str(uuid4())}})
    monkeypatch.setattr(bridge,'_read_capability',lambda *_:original)
    with pytest.raises(ValueError,match='RECOVERY_REQUIRED'):
        continuation.assert_original_native_owner(SimpleNamespace(),cap)


def test_actual_owner_policy_rejects_native_continuation_without_settlement_proof(tmp_path):
    import subprocess
    from pathlib import Path
    source=Path(__file__).resolve().parents[3]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'native-policy.ps1'
    script.write_text(r'''param($Source)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $node.Extent.Text;Initialize-InstallerBridgeTypes
$owner=[EndpointInstallerBridge.Identity]::new(100,1000,('a'*64),'S-1-5-18',$true)
$peer=[EndpointInstallerBridge.Identity]::new(200,2000,('b'*64),'S-1-5-18',$true)
foreach($mode in @('fresh','exit-zero','recovery','uninstall')){
 $operation=if($mode -ceq 'uninstall'){'uninstall'}else{'install'}
 $p=[EndpointInstallerBridge.Policy]::new('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222',('c'*64),$operation,$owner,('b'*64),[byte[]](1..32))
 $p.MarkQuiescent()
 if($mode -ceq 'exit-zero'){$p.MarkMsiExited(0)}
 if($mode -ceq 'recovery'){$p.Recovery=$true}
 $rejected=$false;try{$p.RegisterHelper($peer,'native-continuation')}catch{$rejected=$true}
 if(!$rejected){throw 'unauthorized native continuation'}
}
'passed'
''')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source)],capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stderr


def test_observer_schedule_readback_accepts_canonical_system_sid_and_checks_repetition(monkeypatch):
    from pathlib import Path
    from pc_agent.platform.windows import native_setup_observer as observer
    import win32security
    target=Path('C:/Program Files/EndpointPlatformSetupUpdater/1.0.6/EndpointSetupUpdater.ps1')
    powershell=Path('C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe')
    trigger=SimpleNamespace(Type=1,Enabled=True,Repetition=SimpleNamespace(Interval='PT1M'))
    logon=SimpleNamespace(Type=9,Enabled=True)
    definition=SimpleNamespace(Principal=SimpleNamespace(UserId='S-1-5-18',LogonType=5,RunLevel=1),
        Actions=SimpleNamespace(Count=1,Item=lambda _:SimpleNamespace(Type=0,Path=str(powershell),Arguments=observer._arguments(target),WorkingDirectory='')),
        Triggers=SimpleNamespace(Count=2,Item=lambda i:[trigger,logon][i-1]),
        Settings=SimpleNamespace(Enabled=True,MultipleInstances=2,ExecutionTimeLimit='PT0S',StartWhenAvailable=True,DisallowStartIfOnBatteries=False,StopIfGoingOnBatteries=False))
    task=SimpleNamespace(Definition=definition,GetSecurityDescriptor=lambda _:observer._SDDL)
    original=win32security.LookupAccountName
    monkeypatch.setattr(win32security,'LookupAccountName',lambda _,name:(_ for _ in ()).throw(AssertionError('SID lookup as account')) if name.startswith('S-1-') else original(_,name))
    observer._verify_task(task,target,powershell)
    trigger.Repetition.Interval='PT5M'
    with pytest.raises(ValueError,match='RECOVERY_REQUIRED'): observer._verify_task(task,target,powershell)


def test_native_asset_signature_gate_keeps_all_signed_and_fixed_vendor(monkeypatch,tmp_path):
    import base64
    from pathlib import Path
    from pc_agent.platform.windows import native_setup_observer as observer
    calls=[]
    monkeypatch.setattr(observer,'system_powershell',lambda:Path('C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'))
    monkeypatch.setattr(observer.subprocess,'run',lambda args,**kwargs:calls.append((args,kwargs)) or SimpleNamespace(returncode=21))
    with pytest.raises(ValueError,match='RECOVERY_REQUIRED'):observer._verify_signature(tmp_path/'EndpointSetupUpdater.ps1')
    args,kwargs=calls[0]
    code=base64.b64decode(args[-1]).decode('utf-16-le')
    assert args[args.index('-ExecutionPolicy')+1]=='AllSigned'
    assert "TimeStamperCertificate" in code and observer._PUBLISHER in code
    assert "TrustedPublisher','LocalMachine" in code
    assert 'Bypass' not in code and '-Mode Install' not in code
    assert kwargs['shell'] is False and kwargs['timeout']==30


@pytest.mark.skipif(__import__('os').name!='nt',reason='native inherited administrative ACL')
def test_native_provision_accepts_existing_signed_observer_inherited_admin_file_acl(native_protected_root):
    import win32security
    from pc_agent.platform.windows import native_setup_observer as observer
    asset=native_protected_root/'existing-observer.ps1'
    asset.write_bytes(b'fixture')
    descriptor=win32security.GetNamedSecurityInfo(str(asset),win32security.SE_FILE_OBJECT,win32security.DACL_SECURITY_INFORMATION)
    assert not descriptor.GetSecurityDescriptorControl()[0]&win32security.SE_DACL_PROTECTED
    observer._assert_administrative_file(asset)
