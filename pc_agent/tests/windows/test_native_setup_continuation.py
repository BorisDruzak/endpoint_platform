from contextlib import nullcontext
import os
import shutil
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
    powershell = shutil.which('powershell.exe') or shutil.which('pwsh')
    if powershell is None:
        pytest.skip('PowerShell wrapper parser and continuation')
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
    result = subprocess.run([powershell,'-NoProfile','-NonInteractive','-File',str(script),str(source),users,observer,str(passes)], capture_output=True,text=True,timeout=15)
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

@pytest.mark.skipif(os.name != 'nt', reason='actual Windows task registration')
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
        def __init__(self,registered): self.registered=registered;self.Xml=registered.Xml
        def __getattr__(self,key): return getattr(self.registered,key)
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
    monkeypatch.setattr(continuation,'mark_continuation_finished',lambda *_:None)
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
def test_fresh_continuation_cannot_recreate_an_unrelated_native_owner(reserved_native,defect):
    c,paths,cap,completed,before=reserved_native
    changed={**cap,{'owner':'owner','helper':'helper_sha256','transaction':'transaction_id','package':'package'}[defect]:None}
    if defect=='transaction':changed['transaction_id']=str(uuid4())
    with pytest.raises(ValueError):c.assert_original_native_owner(paths,changed)


@pytest.mark.skipif(os.name != 'nt', reason='compiled Windows owner policy')
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
 foreach($phase in @('native-continuation','recover-native-continuation')){
  $rejected=$false;try{$p.RegisterHelper($peer,$phase)}catch{$rejected=$true}
  if(!$rejected){throw 'unauthorized native continuation'}
 }
}
'passed'
''')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source)],capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stderr


@pytest.mark.skipif(os.name != 'nt', reason='native Windows SID canonicalization')
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


@pytest.mark.skipif(os.name != 'nt',reason='native inherited administrative ACL')
def test_native_provision_accepts_existing_signed_observer_inherited_admin_file_acl(native_protected_root):
    import win32security
    from pc_agent.platform.windows import native_setup_observer as observer
    asset=native_protected_root/'existing-observer.ps1'
    asset.write_bytes(b'fixture')
    descriptor=win32security.GetNamedSecurityInfo(str(asset),win32security.SE_FILE_OBJECT,win32security.DACL_SECURITY_INFORMATION)
    assert not descriptor.GetSecurityDescriptorControl()[0]&win32security.SE_DACL_PROTECTED
    observer._assert_administrative_file(asset)


def _observer_directory_sddl(path):
    import win32security as security
    flags = security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION
    descriptor = security.GetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT, flags)
    return security.ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor, 1, flags)


@pytest.mark.skipif(os.name != 'nt', reason='native administrative directory admission')
def test_native_observer_creates_missing_version_below_existing_protected_root(native_protected_root):
    from pc_agent.platform.windows import native_setup_observer as observer, durable_state
    before = _observer_directory_sddl(native_protected_root)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        version = observer._administrative_directory(native_protected_root, '1.0.6')
    assert version.is_dir()
    observer.fence.assert_state_security(version, secret=True)
    assert _observer_directory_sddl(native_protected_root) == before


@pytest.mark.skipif(os.name != 'nt', reason='native administrative directory admission')
def test_native_observer_missing_directory_requires_live_mutation_scope(native_protected_root):
    from pc_agent.platform.windows import native_setup_observer as observer
    with pytest.raises(ValueError, match='installer mutation scope is absent'):
        observer._administrative_directory(native_protected_root, '1.0.6')
    assert not (native_protected_root / '1.0.6').exists()


@pytest.mark.skipif(os.name != 'nt', reason='native administrative directory admission')
@pytest.mark.parametrize('defect', ['unsafe-parent', 'file', 'reparse', 'broken-reparse'])
def test_native_observer_rejects_unsafe_directory_without_repairing_acl(native_protected_root, defect):
    import win32security as security
    from pc_agent.platform.windows import native_setup_observer as observer, durable_state
    parent = native_protected_root / 'client'
    parent.mkdir()
    observer.fence.protect_state(parent, secret=True)
    target = parent / '1.0.6'
    if defect == 'unsafe-parent':
        acl = security.GetNamedSecurityInfo(str(parent), security.SE_FILE_OBJECT,
            security.DACL_SECURITY_INFORMATION).GetSecurityDescriptorDacl()
        acl.AddAccessAllowedAce(security.ACL_REVISION, 0x40, security.ConvertStringSidToSid('S-1-1-0'))
        security.SetNamedSecurityInfo(str(parent), security.SE_FILE_OBJECT,
            security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, acl, None)
    elif defect == 'file':
        target.write_bytes(b'preserve existing file')
        observer.fence.protect_state(target, secret=True)
    else:
        destination = native_protected_root / 'unrelated'
        if defect == 'reparse': destination.mkdir()
        try:
            target.symlink_to(destination, target_is_directory=True)
        except OSError as error:
            pytest.skip('directory symlink unavailable: ' + str(error.winerror))
    before = _observer_directory_sddl(parent)
    with durable_state.installer_mutation_checkpoints(lambda: None), pytest.raises((ValueError, OSError)):
        observer._administrative_directory(parent, '1.0.6')
    assert _observer_directory_sddl(parent) == before
    if defect == 'unsafe-parent': assert not target.exists()
    elif defect == 'file': assert target.read_bytes() == b'preserve existing file'
    else: assert target.is_symlink() and destination.exists() == (defect == 'reparse')


@pytest.mark.skipif(os.name != 'nt', reason='native packaged observer provisioning')
def test_native_observer_provisions_new_version_with_existing_client_roots(native_protected_root, monkeypatch):
    import hashlib
    import json
    from pc_agent.platform.windows import native_setup_observer as observer, durable_state
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    machine = native_protected_root
    program_files, program_data = machine / 'ProgramFiles', machine / 'ProgramData'
    program_files.mkdir()
    program_data.mkdir()
    client_root = program_files / 'EndpointPlatformSetupUpdater'
    state_root = program_data / 'EndpointPlatformSetupUpdates'
    for root in (client_root, state_root):
        root.mkdir()
        observer.fence.protect_state(root, secret=True)
    old = client_root / '1.0.5'
    old.mkdir()
    (old / 'EndpointSetupUpdater.ps1').write_bytes(b'preserve old observer')
    before = {root: _observer_directory_sddl(root) for root in (client_root, state_root)}
    paths = WindowsUpdatePaths(program_files / 'Endpoint Platform' / 'Agent',
        program_data / 'Endpoint Platform' / 'Agent' / 'updates' / 'pending_update.json')
    packaged = machine / 'frozen' / 'setup-updater'
    packaged.mkdir(parents=True)
    body = "$script:ClientVersion='1.0.6'\n# source-bound observer"
    raw = (body + '\n# SIG # Begin signature block\nsigned fixture\n# SIG # End signature block\n').encode()
    metadata = {'schema_version': 1, 'client_version': '1.0.6',
        'script_sha256': hashlib.sha256(raw).hexdigest(), 'source_sha256': hashlib.sha256(body.encode()).hexdigest()}
    asset = packaged / 'EndpointSetupUpdater.ps1'
    asset.write_bytes(raw)
    (packaged / 'EndpointSetupUpdater.payload.json').write_text(json.dumps(metadata))
    monkeypatch.setattr(observer.sys, 'frozen', True, raising=False)
    monkeypatch.setattr(observer.sys, '_MEIPASS', str(packaged.parent), raising=False)
    monkeypatch.setattr(WindowsUpdatePaths, 'production', classmethod(lambda cls: paths))
    # Authenticode and Scheduler are external OS boundaries; payload binding,
    # parent/child security, byte pinning and durable publication remain real.
    monkeypatch.setattr(observer, '_verify_signature', lambda _: None)
    monkeypatch.setattr(observer, '_register_observer', lambda _: None)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        assert observer.provision_packaged_observer(paths) == 'provisioned'
    target = client_root / '1.0.6' / 'EndpointSetupUpdater.ps1'
    assert target.read_bytes() == raw
    observer.fence.assert_state_security(target.parent, secret=True)
    observer.fence.assert_state_security(target, secret=True)
    installed = json.loads((state_root / 'client.json').read_bytes())
    assert installed['client_version'] == '1.0.6' and installed['script_sha256'] == metadata['script_sha256']
    assert (old / 'EndpointSetupUpdater.ps1').read_bytes() == b'preserve old observer'
    assert {root: _observer_directory_sddl(root) for root in before} == before


def test_completion_reserves_exclusion_before_native_fence_publication(staged,monkeypatch):
    from pc_agent.platform.windows import installer_transaction_bridge as bridge, installer_fence as fence, native_setup_continuation as continuation, durable_state
    from pc_agent.tests.windows.test_installer_fence import state as native_fence
    _,paths,binding,owner=staged
    cap={'transaction_id':binding.operation_id,'package':binding.new_release,'operation':'install','owner':owner,
         'helper_sha256':'f'*64,'session_id':str(uuid4()),'selected':'c'*64,'previous':None,
         'service_states':{'EndpointAgent':'running','EndpointAgentUpdater':'stopped'}}
    current=native_fence();current.update(transaction_id=cap['transaction_id'],phase='reconciling')
    current['package'].update(sha256=cap['package']['package_sha256'],version=cap['package']['version'],source_revision=cap['package']['source_revision'],product_code=cap['package']['product_code'])
    fence.protect_state(paths.install_root)
    with durable_state.installer_mutation_checkpoints(lambda:None):fence.publish_fence(paths,current)
    expected=SimpleNamespace(package=SimpleNamespace(sha256=current['package']['sha256'],product_code=current['package']['product_code'],package_code=current['package']['package_code'],version=current['package']['version']),identity=SimpleNamespace(source_revision=current['package']['source_revision']))
    client=SimpleNamespace(capability=cap,identity=SimpleNamespace(value={'pid':1,'created':1,'hash':'f'*64}))
    events=[]
    def reserve(*a,**kw):events.append('reserved');raise KeyboardInterrupt()
    monkeypatch.setattr(continuation,'reserve_native_continuation',reserve,raising=False)
    original=fence.fence_path(paths).read_bytes()
    with durable_state.installer_mutation_checkpoints(lambda:None):
        with pytest.raises(KeyboardInterrupt):bridge._advance_fence(paths,client,expected,'complete')
    assert events==['reserved']
    assert fence.fence_path(paths).read_bytes()==original


def test_fresh_native_recovery_has_explicit_setup_entrypoint():
    from pc_agent.platform.windows import setup_entry
    operation=str(uuid4())
    assert setup_entry._parser().parse_args(['--recover-native-continuation',operation]).recover_native_continuation==operation


def test_reserved_grant_precedes_first_continuation_and_authorizes_only_dead_exact_owner(staged,monkeypatch):
    from pc_agent.platform.windows import native_setup_continuation as c, installer_fence as f, durable_state
    from pc_agent.tests.windows.test_installer_fence import state as native_fence
    _,paths,binding,owner=staged
    cap={'transaction_id':binding.operation_id,'package':binding.new_release,'owner':owner,'helper_sha256':'f'*64,'session_id':str(uuid4()),'operation':'install','recovery':False,'uninstall_finalization':False}
    completed=native_fence();completed.update(transaction_id=binding.operation_id,phase='complete',startup_restored=True)
    completed['package'].update(sha256=binding.new_release['package_sha256'],version=binding.new_release['version'],source_revision=binding.new_release['source_revision'],product_code=binding.new_release['product_code'])
    before={**completed,'phase':'reconciling','startup_restored':False}
    monkeypatch.setattr(c,'_capture_authority',lambda *_:{'session_id':cap['session_id'],'capture_sha256':'a'*64})
    monkeypatch.setattr(c,'_selected_scope',lambda *_:{'selected_sha256':'b'*64,'previous_sha256':None,'tree_sha256':'c'*64})
    with durable_state.installer_mutation_checkpoints(lambda:None): c.reserve_native_continuation(paths,cap,completed,before)
    assert c.pending_continuation(paths)=={'transaction_id':binding.operation_id,'package':binding.new_release}
    grant=c.read_continuation_grant(paths,cap)
    assert grant['owner']==owner and grant['completion']==completed
    newcap={**cap,'owner':{**owner,'pid':owner['pid']+10,'created':owner['created']+1},'session_id':str(uuid4())}
    monkeypatch.setattr(c.recovery,'_assert_owner_dead',lambda _:(_ for _ in ()).throw(ValueError('RECOVERY_REQUIRED')))
    with durable_state.installer_mutation_checkpoints(lambda:None):
        with pytest.raises(ValueError): c.authorize_continuation_recovery(paths,newcap)
    monkeypatch.setattr(c.recovery,'_assert_owner_dead',lambda _:None)
    with durable_state.installer_mutation_checkpoints(lambda:None): c.authorize_continuation_recovery(paths,newcap)
    c.assert_original_native_owner(paths,newcap)
    monkeypatch.setattr(c,'_selected_scope',lambda *_:{'selected_sha256':'d'*64,'previous_sha256':None,'tree_sha256':'c'*64})
    with pytest.raises(ValueError):c.assert_original_native_owner(paths,newcap)


@pytest.mark.skipif(os.name!='nt',reason='real no-trigger Scheduler interruption boundary')
@pytest.mark.parametrize('foreign',[False,True])
def test_real_interrupted_companion_launcher_retry_reuses_only_exact_owned_task(staged,monkeypatch,foreign):
    import win32api,win32con,win32security,win32ts,win32com.client
    from pc_agent.platform.windows import durable_state
    _,paths,binding,owner=staged
    token=win32security.OpenProcessToken(win32api.GetCurrentProcess(),win32con.TOKEN_QUERY)
    try:sid=win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token,win32security.TokenUser)[0])
    finally:token.Close()
    session=win32ts.ProcessIdToSessionId(os.getpid())
    if session<=0:pytest.skip('interactive operator session')
    item={'role':'sensor','sid':sid,'session_id':session}
    dispatch=win32com.client.Dispatch;real=dispatch('Schedule.Service');real.Connect();folder=real.GetFolder('\\')
    name='EndpointCompanionRestore-'+binding.operation_id+'-sensor-'+str(session)
    attempts=[]; checkpoints=[]
    class Task:
        def __init__(self,task):self.task=task
        def __getattr__(self,key):return getattr(self.task,key)
        def RunEx(self,*args):
            attempts.append(args)
            if len(attempts)==1:raise KeyboardInterrupt()
    class Folder:
        def RegisterTaskDefinition(self,*args):return Task(folder.RegisterTaskDefinition(*args))
        def GetTask(self,*args):return Task(folder.GetTask(*args))
        def DeleteTask(self,*args):return folder.DeleteTask(*args)
    class Scheduler:
        def Connect(self):pass
        def GetFolder(self,_):return Folder()
        def NewTask(self,n):return real.NewTask(n)
    monkeypatch.setattr(win32com.client,'Dispatch',lambda value,*args,**kwargs:Scheduler() if value=='Schedule.Service' else dispatch(value,*args,**kwargs))
    monkeypatch.setattr(recovery,'_active_sessions',lambda:[{'sid':sid,'session_id':session}])
    def interrupted_checkpoint():
        checkpoints.append(1)
        if len(checkpoints)==3:raise ValueError('owner-gone')
    try:
        with durable_state.installer_mutation_checkpoints(interrupted_checkpoint):
            with pytest.raises(ValueError,match='owner-gone'):recovery._restore_companion_task(paths,binding.operation_id,item)
        assert folder.GetTask(name).Definition.Triggers.Count==0
        if foreign:
            definition=folder.GetTask(name).Definition;definition.Actions.Item(1).Path='C:\\Windows\\System32\\cmd.exe'
            account=win32security.LookupAccountSid(None,win32security.ConvertStringSidToSid(sid))
            folder.RegisterTaskDefinition(name,definition,6,account[1]+'\\'+account[0],None,3,'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;'+sid+')')
            foreign_xml=folder.GetTask(name).Xml
        with durable_state.installer_mutation_checkpoints(lambda:None):
            if foreign:
                with pytest.raises(ValueError,match='RECOVERY_REQUIRED'):recovery._restore_companion_task(paths,binding.operation_id,item)
                assert folder.GetTask(name).Xml==foreign_xml and len(attempts)==1
            else:assert recovery._restore_companion_task(paths,binding.operation_id,item) is True
        if not foreign:assert len(attempts)==2
    finally:
        try:folder.DeleteTask(name,0)
        except Exception:pass


@pytest.fixture
def reserved_native(staged,monkeypatch):
    from pc_agent.platform.windows import native_setup_continuation as c, durable_state
    from pc_agent.tests.windows.test_installer_fence import state as native_fence
    _,paths,binding,owner=staged
    cap={'transaction_id':binding.operation_id,'package':binding.new_release,'owner':owner,'helper_sha256':'f'*64,
         'session_id':str(uuid4()),'operation':'install','recovery':False,'uninstall_finalization':False,'selected':None,'previous':None}
    completed=native_fence();completed.update(transaction_id=binding.operation_id,phase='complete',startup_restored=True)
    completed['package'].update(sha256=binding.new_release['package_sha256'],version=binding.new_release['version'],source_revision=binding.new_release['source_revision'],product_code=binding.new_release['product_code'])
    before={**completed,'phase':'reconciling','startup_restored':False}
    monkeypatch.setattr(c,'_capture_authority',lambda *_:{'session_id':cap['session_id'],'capture_sha256':'a'*64})
    monkeypatch.setattr(c,'_selected_scope',lambda *_:{'selected_sha256':'b'*64,'previous_sha256':None,'tree_sha256':'c'*64})
    with durable_state.installer_mutation_checkpoints(lambda:None):c.reserve_native_continuation(paths,cap,completed,before)
    return c,paths,cap,completed,before


@pytest.fixture
def accepted_candidate_grant(staged, monkeypatch):
    """Reserve the real167 native selector, then run the actual staged trial writer."""
    from dataclasses import replace
    from pc_agent.platform.windows import native_setup_continuation as c, durable_state
    from pc_agent.platform.windows import msi_inventory
    from pc_agent.platform.windows import staged_trial_proof as proof
    from pc_agent.tests.windows.test_staged_update_state import begin, move
    from pc_agent.tests.windows.test_installer_fence import state as native_fence
    state, paths, binding, owner = staged
    source = 'ab313225e04b7cccefc0c30ae17b949d8fdd964d'
    tree = '5d81e12d78d07c2caca984c5ee3614299825c454befeb44a2eb35629be74f9ce'
    selected = b'{"schema_version":1,"version":"3.2.165","source_revision":"ed7f77a559e19500df75b9ec169c5336e308b304"}'
    previous = b'{"schema_version":1,"source_revision":"1c2e54a06d1a7dfb6c2c2e0d2ef2cde2d0fe9896","version":"3.2.164"}'
    package = {**binding.new_release, 'version': '3.2.167', 'source_revision': source,
               'package_sha256': 'ffb3e7def4573a33551f424c0bbb9b7dde6a8617ce8dfb673993d129788bee70',
               'product_code': '{86ADD870-38BF-420F-A5B9-98E176C8E418}',
               'initial_runtime_tree_sha256': 'e0ce0ce8f513c432ff898bb5961acada8de982d205e5103f60562eeb05c4216a'}
    old = {**binding.old_release, 'version': '3.2.165',
           'source_revision': 'ed7f77a559e19500df75b9ec169c5336e308b304',
           'package_sha256': '831ed1996daae0bf68a046828ff0e8f3775b879e14bf05e9a086304672cee5a9',
           'product_code': '{2784BFCB-4D3E-4BD5-A92D-57D1DEBFA447}',
           'initial_runtime_tree_sha256': 'ac6284d140dd6e312fc7c778a98dd71d73ab738d4263025ee8c38499dd443562'}
    binding = replace(binding, old_release=old, new_release=package, selected_before=selected, previous_before=previous,
                      selected_tree_sha256_before='54182cf3ae02a623dad64f338dbd984f44feb0a605e619c59987c861a73f2ded',
                      previous_tree_sha256_before='a2435f187cb99c4eb92c478d2898ac28a861f815f46e225286a116db2d39e9d3', candidate_version='3.2.167',
                      candidate_source_revision=source, candidate_tree_sha256=tree)
    paths.current_path.write_bytes(selected)
    paths.previous_path.write_bytes(previous)
    c.fence.protect_state(paths.previous_path)
    staged = state, paths, binding, owner
    begin(staged)
    move(staged, 'preparing', 'prepared')
    move(staged, 'prepared', 'switching')
    identity = SimpleNamespace(version='3.2.167', source_revision=source, tree_sha256=tree)
    expected = SimpleNamespace(identity=identity, package=SimpleNamespace(version='3.2.167'))
    monkeypatch.setattr(msi_inventory, 'read_expected_package', lambda *_: expected)
    monkeypatch.setattr(c.provenance, 'verified_foundation_release', lambda _: package)
    monkeypatch.setattr(c.provenance, '_inspect_core_value', lambda *_: SimpleNamespace(identity=identity))
    monkeypatch.setattr(c.provenance, 'inspect_installed_core', lambda *a, **kw: SimpleNamespace(current=SimpleNamespace(identity=identity)))
    monkeypatch.setattr(proof.gate, 'create_trial_gate', lambda *_: None)
    # Exact native-finalization bytes, before the existing trial writer runs.
    paths.current_path.write_bytes(b'{"schema_version":1,"source_revision":"ab313225e04b7cccefc0c30ae17b949d8fdd964d","version":"3.2.167"}')
    paths.previous_path.write_bytes(selected)
    session = str(uuid4())
    cap = {'schema_version': 1, 'transaction_id': binding.operation_id, 'package': package, 'owner': owner,
           'helper_sha256': 'f' * 64, 'session_id': session, 'operation': 'install', 'recovery': False,
           'uninstall_finalization': False, 'selected': 'c' * 64, 'previous': 'd' * 64,
           'pipe_name': 'EndpointInstaller-' + session + '-' + 'e' * 32,
           'secret': 'e' * 64, 'service_states': {}}
    private = c.fence.state_root(paths) / 'capabilities'
    private.mkdir()
    c.fence.protect_state(private, secret=True)
    monkeypatch.setattr(c, '_capture_authority', lambda *_: {'session_id': session, 'capture_sha256': 'a' * 64})
    completed = native_fence()
    completed.update(transaction_id=binding.operation_id, phase='complete', startup_restored=True)
    completed['package'].update(sha256=package['package_sha256'], version=package['version'],
                                source_revision=source, product_code=package['product_code'])
    with durable_state.installer_mutation_checkpoints(lambda: None):
        durable_state.write_json_atomic(private / (session + '.json'), cap, trusted_root=private,
                                        max_bytes=16384, protect=lambda leaf: c.fence.protect_state(leaf, secret=True))
        c.reserve_native_continuation(paths, cap, completed, {**completed, 'phase': 'reconciling'})
        proof.begin_staged_trial(paths, binding.operation_id, owner=owner)
    move(staged, 'trial', 'accepted')
    return c, paths, cap, expected, staged


def test_accepted_staged_trial_preserves_native_grant_selection_and_continues(accepted_candidate_grant, monkeypatch):
    from pc_agent.platform.windows import msi_inventory, installer_data_security as security, native_setup_observer as observer
    c, paths, cap, expected, _ = accepted_candidate_grant
    leaf = c._grant_path(paths, cap['transaction_id'])
    original = leaf.read_bytes()
    grant = c.recovery._read(leaf)
    assert grant['selection'] == {'selected_sha256': 'dc8e070cf7dc7fb1beff241e153fa75a56af9ceaf58efa3e7f166e3ef51e2086',
                                  'previous_sha256': '6138efe66a5cbed3583130b74db5f173f9d7d531e545a25a29c91fc297d3d863',
                                  'tree_sha256': '5d81e12d78d07c2caca984c5ee3614299825c454befeb44a2eb35629be74f9ce'}
    assert c._selected_scope(paths, cap) == grant['selection']
    monkeypatch.setattr(msi_inventory, 'verified_foundation_bytes', lambda *_: nullcontext())
    monkeypatch.setattr(security, 'verify_preserved', lambda *_: None)
    monkeypatch.setattr(observer, 'provision_packaged_observer', lambda _: 'provisioned')
    monkeypatch.setattr(c.recovery, 'restore_expected_companions', lambda *a, **kw: 'running')
    monkeypatch.setattr(c.recovery, '_service_outcomes', lambda *_: {'EndpointAgent': 'running'})
    client = SimpleNamespace(capability=cap, checkpoint=lambda: None, request=lambda *_: None)
    result = c.execute_native_continuation(client, paths)
    assert result['observer'] == 'provisioned' and result['users'] == 'running'
    assert c.pending_continuation(paths) is None
    assert leaf.read_bytes() == original


@pytest.mark.parametrize('defect', ['alternate-serialization', 'wrong-source', 'wrong-tree', 'changed-previous'])
def test_continuation_grant_keeps_exact_selection_after_trial(accepted_candidate_grant, monkeypatch, defect):
    c, paths, cap, _, staged = accepted_candidate_grant
    _, _, binding, _ = staged
    if defect == 'alternate-serialization':
        paths.current_path.write_bytes(b'{"schema_version":1,"version":"3.2.167","source_revision":"ab313225e04b7cccefc0c30ae17b949d8fdd964d"}')
    elif defect == 'wrong-source':
        paths.current_path.write_bytes(b'{"schema_version":1,"source_revision":"' + b'9' * 40 + b'","version":"3.2.167"}')
    elif defect == 'wrong-tree':
        monkeypatch.setattr(c.provenance, 'inspect_installed_core', lambda *a, **kw: SimpleNamespace(current=SimpleNamespace(identity=SimpleNamespace(tree_sha256='9' * 64))))
    elif defect == 'changed-previous':
        paths.previous_path.write_bytes(binding.previous_before)
    with pytest.raises(ValueError): c.read_continuation_grant(paths, cap)
    assert c.pending_continuation(paths) is not None


@pytest.mark.parametrize('owner_alive', [False, True])
def test_accepted_staged_trial_preserves_fresh_recovery_only_after_owner_death(accepted_candidate_grant, monkeypatch, owner_alive):
    from pc_agent.platform.windows import msi_inventory, installer_data_security as security
    c, paths, cap, _, _ = accepted_candidate_grant
    fresh = {**cap, 'session_id': str(uuid4()),
             'owner': {**cap['owner'], 'pid': cap['owner']['pid'] + 100, 'created': cap['owner']['created'] + 100}}
    leaf = c._grant_path(paths, cap['transaction_id'])
    original = leaf.read_bytes()
    monkeypatch.setattr(msi_inventory, 'verified_foundation_bytes', lambda *_: nullcontext())
    monkeypatch.setattr(security, 'verify_preserved', lambda *_: None)
    def death(owner):
        assert owner == cap['owner']
        if owner_alive:
            raise ValueError('RECOVERY_REQUIRED')
    monkeypatch.setattr(c.recovery, '_assert_owner_dead', death)
    with pytest.raises(ValueError):
        c.assert_original_native_owner(paths, fresh)
    client = SimpleNamespace(capability=fresh, checkpoint=lambda: None, request=lambda *_: None)
    if owner_alive:
        with pytest.raises(ValueError): c.recover_native_continuation(client, paths)
        assert not c._owner_receipt(paths, fresh).exists()
    else:
        assert c.recover_native_continuation(client, paths) == {
            'operation_id': cap['transaction_id'], 'result': 'native-settled-for-staged-recovery'}
        c.assert_original_native_owner(paths, fresh)
        with pytest.raises(ValueError): c.accepted_native_record(paths, fresh)
    assert leaf.read_bytes() == original
    assert c.pending_continuation(paths) == {'transaction_id': cap['transaction_id'], 'package': cap['package']}


@pytest.mark.parametrize('boundary',['before-public-hold','before-completed-receipt','before-first-continuation'])
@pytest.mark.parametrize('defect',[None,'capture','selection','payload','owner-alive','pending','missing-grant'])
def test_exact_new_owner_recovers_native_boundaries_without_msi(reserved_native,monkeypatch,boundary,defect):
    from pc_agent.platform.windows import installer_fence as f, durable_state, msi_inventory, installer_data_security as security
    from pc_agent.platform.windows import native_setup_observer as observer, update_transaction, compound_upgrade_plan as plan
    c,paths,cap,completed,before=reserved_native
    newcap={**cap,'owner':{**cap['owner'],'pid':cap['owner']['pid']+100,'created':cap['owner']['created']+100},'session_id':str(uuid4())}
    grant=c.read_continuation_grant(paths,cap);completion=f.state_root(paths)/grant['completion_relative']
    with durable_state.installer_mutation_checkpoints(lambda:None):
        if boundary in {'before-public-hold','before-completed-receipt'}:f.publish_fence(paths,before)
        else:durable_state.write_json_atomic(completion,completed,trusted_root=completion.parent,max_bytes=16384,protect=f.protect_state)
    if boundary=='before-public-hold':(f.state_root(paths)/'native-continuation.json').unlink()
    original_fence=f.fence_path(paths).read_bytes() if f.fence_path(paths).exists() else None
    monkeypatch.setattr(update_transaction,'active_update_state',lambda _:'pending' if defect=='pending' else None if boundary=='before-public-hold' else 'native-continuation-pending')
    monkeypatch.setattr(plan,'has_active_upgrade',lambda _:False)
    monkeypatch.setattr(c.provenance,'verified_foundation_release',lambda _:{} if defect=='payload' else cap['package'])
    monkeypatch.setattr(msi_inventory,'read_expected_package',lambda *_:SimpleNamespace(package=SimpleNamespace(version=cap['package']['version'])))
    monkeypatch.setattr(msi_inventory,'verified_foundation_bytes',lambda *_:nullcontext())
    monkeypatch.setattr(c.provenance,'inspect_installed_core',lambda *a,**kw:SimpleNamespace(current=object()))
    monkeypatch.setattr(security,'verify_preserved',lambda *_:None)
    def dead(_):
        if defect=='owner-alive':raise ValueError('RECOVERY_REQUIRED')
    monkeypatch.setattr(c.recovery,'_assert_owner_dead',dead)
    if defect=='capture':monkeypatch.setattr(c,'_capture_authority',lambda *_:{'session_id':cap['session_id'],'capture_sha256':'9'*64})
    if defect=='selection':monkeypatch.setattr(c,'_selected_scope',lambda *_:{})
    if defect=='missing-grant':c._grant_path(paths,cap['transaction_id']).unlink()
    calls=[]
    monkeypatch.setattr(observer,'provision_packaged_observer',lambda _:calls.append('observer') or 'provisioned')
    monkeypatch.setattr(c.recovery,'restore_expected_companions',lambda *a,**kw:calls.append('companions') or 'running')
    client=SimpleNamespace(capability=newcap,checkpoint=lambda:None,request=lambda *args:None)
    if defect is None:
        assert c.recover_native_continuation(client,paths)['users']=='running'
        assert calls==['observer','companions'] and not f.fence_path(paths).exists()
        assert c.pending_continuation(paths) is None
        assert plan._read(completion)==completed
    else:
        with pytest.raises(ValueError):c.recover_native_continuation(client,paths)
        assert not calls
        assert (c.pending_continuation(paths) is None)==(boundary=='before-public-hold')
        assert (f.fence_path(paths).read_bytes() if f.fence_path(paths).exists() else None)==original_fence
    assert not paths.pending_path.exists()


from pc_agent.tests.windows.test_compound_upgrade_plan import inputs as compound_inputs


@pytest.mark.parametrize('phase',['reconciled','ready'])
@pytest.mark.parametrize('defect',[None,'old-msi-present','changed-capability','changed-plan'])
def test_scoped_native_grant_finishes_only_its_committed_compound_plan(staged,compound_inputs,monkeypatch,phase,defect):
    from pc_agent.platform.windows import native_setup_continuation as c, compound_upgrade_plan as plan, durable_state, msi_inventory, installer_transaction_bridge as bridge
    _,paths,_,_=staged
    cap,old,old_fence=compound_inputs
    record=plan.make_plan(cap,old,old_fence)
    for target in ('old-script-returned','new-script-returned','committed','retired','reconciled'):
        record=plan.next_phase(record,cap,target,native_result=0 if target in {'old-script-returned','new-script-returned','committed'} else None)
    grant={'native_session_id':cap['session_id'],'native_capability_sha256':c._digest(cap),'owner':cap['owner'],'compound_plan_sha256':c._digest(record)}
    with durable_state.installer_mutation_checkpoints(lambda:None):
        plan.publish_plan(paths,cap,record)
        if phase=='ready':plan.ready_receipt(paths,cap)
    assert plan.has_active_upgrade(paths)
    original={**cap}
    if defect=='changed-capability':original={**cap,'helper_sha256':'9'*64}
    monkeypatch.setattr(bridge,'_read_capability',lambda *_:original)
    monkeypatch.setattr(msi_inventory,'NativeMsi',lambda:SimpleNamespace(product=lambda _:5 if defect=='old-msi-present' else -1))
    if defect=='changed-plan':grant['compound_plan_sha256']='0'*64
    current={**cap,'owner':{**cap['owner'],'pid':200},'session_id':str(uuid4())};current.pop('compound')
    with durable_state.installer_mutation_checkpoints(lambda:None):
        if defect is not None:
            with pytest.raises(ValueError):c._finish_reserved_compound(paths,current,grant)
            assert plan.has_active_upgrade(paths)
        else:
            c._finish_reserved_compound(paths,current,grant)
            assert not plan.has_active_upgrade(paths)
            assert plan.committed_marker(paths)['new_transaction_id']==cap['transaction_id']


def test_native_recovery_setup_dispatch_never_enters_normal_install(monkeypatch):
    from pc_agent.platform.windows import setup_entry
    operation=str(uuid4());seen=[]
    monkeypatch.setattr(setup_entry,'_run_native_continuation_recovery',lambda value:seen.append(value) or 17)
    monkeypatch.setattr(setup_entry,'_install_embedded_msi',lambda *_:pytest.fail('native replay'))
    assert setup_entry.main(['--recover-native-continuation',operation])==17
    assert seen==[operation]


def test_preaccept_hold_release_keeps_staged_exclusion_and_cannot_release_acceptance(reserved_native,staged):
    from pc_agent.tests.windows.test_staged_update_state import begin,move
    from pc_agent.platform.windows import durable_state,update_transaction
    c,paths,cap,completed,before=reserved_native
    begin(staged)
    for a,b in [('preparing','prepared'),('prepared','switching'),('switching','native-settled')]:move(staged,a,b)
    move(staged,'native-settled','trial',attempt_id=str(uuid4()))
    record=c.state.read_staged_update(paths)
    with durable_state.installer_mutation_checkpoints(lambda:None):c.release_preaccept_hold(paths,cap,record)
    assert c.pending_continuation(paths) is None and c.state.read_staged_update(paths).phase=='trial'
    with pytest.raises(update_transaction.UpdateInProgress):c.state.assert_staged_update_allowed(paths,purpose='setup')
    move(staged,'trial','accepted')
    with durable_state.installer_mutation_checkpoints(lambda:None):
        c.begin_continuation_hold(paths,cap)
        with pytest.raises(ValueError):c.release_preaccept_hold(paths,cap,c.state.read_staged_update(paths))
    assert c.pending_continuation(paths) is not None


def test_continuation_recovery_cannot_replace_a_still_live_adopted_owner(reserved_native,monkeypatch):
    from pc_agent.platform.windows import durable_state
    c,paths,cap,*_=reserved_native
    first={**cap,'owner':{**cap['owner'],'pid':cap['owner']['pid']+10}}
    second={**cap,'owner':{**cap['owner'],'pid':cap['owner']['pid']+20}}
    monkeypatch.setattr(c.recovery,'_assert_owner_dead',lambda _:None)
    with durable_state.installer_mutation_checkpoints(lambda:None):c.authorize_continuation_recovery(paths,first)
    receipt=c._owner_receipt(paths,first).read_bytes()
    def dead(value):
        if value==first['owner']:raise ValueError('RECOVERY_REQUIRED')
    monkeypatch.setattr(c.recovery,'_assert_owner_dead',dead)
    with durable_state.installer_mutation_checkpoints(lambda:None):
        with pytest.raises(ValueError):c.authorize_continuation_recovery(paths,second)
    assert c._owner_receipt(paths,first).read_bytes()==receipt


def test_successful_continuation_grant_is_not_a_fresh_owner_recreation_capability(reserved_native,monkeypatch):
    from pc_agent.platform.windows import durable_state
    c,paths,cap,*_=reserved_native
    with durable_state.installer_mutation_checkpoints(lambda:None):c.mark_continuation_finished(paths,cap)
    with durable_state.installer_mutation_checkpoints(lambda:None):c.finish_continuation_hold(paths,cap)
    called=[]
    monkeypatch.setattr(c.recovery,'_assert_owner_dead',lambda _:called.append('death'))
    with durable_state.installer_mutation_checkpoints(lambda:None):
        with pytest.raises(ValueError):c.authorize_continuation_recovery(paths,{**cap,'owner':{**cap['owner'],'pid':cap['owner']['pid']+100}})
    assert not called


@pytest.mark.parametrize('operation,reserved,denied',[('RecoverInterruptedInstall',True,True),('RecoverInterruptedInstall',False,False),('RecoverNativeContinuation',True,False),('RecoverStagedUpdate',True,False)])
def test_wrapper_refuses_ordinary_msi_recovery_after_scoped_native_reservation(tmp_path,operation,reserved,denied):
    import subprocess
    from pathlib import Path
    powershell=shutil.which('powershell.exe') or shutil.which('pwsh')
    if powershell is None:pytest.skip('PowerShell')
    source=Path(__file__).resolve().parents[3]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'no-replay.ps1'
    script.write_text(r'''param($Source,$Operation,$Reserved,$Denied)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse'}
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-NoReservedNativeReplay'},$true)
Invoke-Expression $node.Extent.Text
function Read-UpdateGateState {param($Path,$Limit);if($Limit -ne 32768){throw 'scope bound'};if($Reserved -ceq 'True'){return [pscustomobject]@{Value=@{schema_version=1}}};return $null}
$failed=$false;try{Assert-NoReservedNativeReplay -Operation $Operation -Fence ([pscustomobject]@{transaction_id='11111111-1111-4111-8111-111111111111'}) -StateRoot $env:TEMP}catch{$failed=$true}
if($failed -ne ($Denied -ceq 'True')){throw 'replay guard'}
'passed'
''')
    result=subprocess.run([powershell,'-NoProfile','-NonInteractive','-File',str(script),str(source),operation,str(reserved),str(denied)],capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
