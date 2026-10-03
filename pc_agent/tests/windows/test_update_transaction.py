"""Native process exclusion and fail-closed lifecycle inspection."""
from __future__ import annotations
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4
import pytest
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

@pytest.fixture
def transaction(monkeypatch):
    from pc_agent.platform.windows import update_transaction as module
    monkeypatch.setattr(module, '_MUTEX_NAME', 'Local\\EndpointUpdateTest-' + uuid4().hex)
    return module

@pytest.mark.parametrize('leaf,payload,expected', [
    ('pending_update.json', {'operation_id':'operation','version':'3.2.82'}, 'pending'),
    ('startup-attempt.json', {'operation_id':'operation','version':'3.2.82','attempt_id':'a'*32}, 'verifying'),
    ('terminal-outcome.json', {'operation_id':'operation','reported_version':'3.2.79','status':'failed','safe_code':'launcher_apply_failed'}, 'terminal-report-pending'),
])
def test_active_lifecycle_blocks_setup(transaction, tmp_path, leaf, payload, expected):
    paths = WindowsUpdatePaths(tmp_path / 'install', tmp_path / 'updates' / 'pending_update.json')
    paths.updates_root.mkdir()
    _protect(tmp_path);_protect(paths.updates_root)
    path = paths.updates_root / leaf
    path.write_text(json.dumps(payload))
    _protect(path)
    assert transaction.active_update_state(paths) == expected

@pytest.mark.parametrize('raw', ['{', '{}', '[]', '{"operation_id":[],"version":"3.2.82"}', '{"operation_id":"x","version":7}', '{"operation_id":"x","operation_id":"y","version":"3.2.82"}'])
def test_malformed_state_is_rejected_separately(transaction, tmp_path, raw):
    paths = WindowsUpdatePaths(tmp_path / 'install', tmp_path / 'updates' / 'pending_update.json')
    paths.updates_root.mkdir();_protect(paths.updates_root);_protect(tmp_path)
    paths.pending_path.write_text(raw)
    _protect(paths.pending_path)
    with pytest.raises(ValueError):
        transaction.active_update_state(paths)

@pytest.mark.skipif(os.name != 'nt', reason='native Windows process evidence')
def test_competing_process_cannot_publish_until_setup_releases(transaction, tmp_path):
    paths = WindowsUpdatePaths(tmp_path, tmp_path / 'pending_update.json')
    code = '''
import sys
from pathlib import Path
from pc_agent.platform.windows import update_transaction as t
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
t._MUTEX_NAME = sys.argv[1]
root=Path(sys.argv[2])
(root/'ready').write_text('ready')
with t.update_transaction(WindowsUpdatePaths(root,root/'pending_update.json')):
    (root/'published').write_text('pending')
'''
    with transaction.update_transaction(paths):
        child = subprocess.Popen([sys.executable, '-c', code, transaction._MUTEX_NAME, str(tmp_path)])
        try:
            import time
            deadline=time.monotonic()+10
            while not (tmp_path/'ready').exists() and time.monotonic()<deadline:
                time.sleep(.01)
            assert (tmp_path/'ready').exists()
            with pytest.raises(subprocess.TimeoutExpired):
                child.wait(timeout=.2)
            assert not (tmp_path/'published').exists()
        except BaseException:
            child.kill(); child.wait(); raise
    assert child.wait(timeout=10) == 0
    assert (tmp_path/'published').read_text() == 'pending'

@pytest.mark.skipif(os.name != 'nt', reason='native Windows process evidence')
def test_abandoned_owner_is_recovered(transaction, tmp_path):
    # A second open handle keeps the abandoned kernel object alive after death.
    import win32event
    paths = WindowsUpdatePaths(tmp_path, tmp_path/'updates'/'pending_update.json')
    _protect(tmp_path)
    code = '''
import os,sys
from pathlib import Path
from pc_agent.platform.windows import update_transaction as t
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
t._MUTEX_NAME=sys.argv[1]
with t.update_transaction(WindowsUpdatePaths(Path(sys.argv[2]),Path(sys.argv[2])/'pending_update.json')):
    print('owned',flush=True)
    sys.stdin.readline()
    os._exit(17)
'''
    child = subprocess.Popen([sys.executable,'-c',code,transaction._MUTEX_NAME,str(tmp_path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    try:
        assert child.stdout.readline().strip() == 'owned'
        handle=win32event.OpenMutex(0x120001,False,transaction._MUTEX_NAME)
        child.communicate('\n',timeout=10)
        assert child.returncode == 17
        with transaction.update_transaction(paths):
            assert transaction.active_update_state(paths) is None
        handle.Close()
    finally:
        if child.poll() is None: child.kill(); child.wait()


def _protect(path):
    if os.name == 'nt':
        import win32security
        descriptor=win32security.ConvertStringSecurityDescriptorToSecurityDescriptor('D:P(A;;FA;;;SY)(A;;FA;;;BA)',1)
        win32security.SetNamedSecurityInfo(str(path),win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION|win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None,None,descriptor.GetSecurityDescriptorDacl(),None)


@pytest.mark.skipif(os.name != 'nt', reason='native Windows ACL evidence')
def test_spoofed_mutex_permissions_are_rejected(transaction,tmp_path):
    import win32event,win32security
    attributes=win32security.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR=win32security.ConvertStringSecurityDescriptorToSecurityDescriptor('D:P(A;;GA;;;WD)',1)
    handle=win32event.CreateMutex(attributes,False,transaction._MUTEX_NAME)
    try:
        with pytest.raises(ValueError):
            with transaction.update_transaction(WindowsUpdatePaths(tmp_path,tmp_path/'pending_update.json')):
                pytest.fail('spoofed mutex accepted')
    finally:
        handle.Close()


@pytest.mark.skipif(os.name != 'nt', reason='native Windows restricted-token ACL evidence')
def test_ordinary_token_cannot_open_or_precreate_trusted_mutex(transaction,tmp_path):
    import win32api,win32security,win32event
    token=win32security.OpenProcessToken(win32api.GetCurrentProcess(),0xF01FF)
    restricted=win32security.CreateRestrictedToken(token,1,[(win32security.ConvertStringSidToSid('S-1-5-32-544'),0)],None,None)
    paths=WindowsUpdatePaths(tmp_path,tmp_path/'pending_update.json')
    try:
        with transaction.update_transaction(paths):
            win32security.ImpersonateLoggedOnUser(restricted)
            try:
                with pytest.raises(PermissionError):
                    with transaction.update_transaction(paths): pytest.fail('ordinary caller accepted')
                with pytest.raises(win32api.error):
                    win32event.OpenMutex(0x120001,False,transaction._MUTEX_NAME)
            finally:
                win32security.RevertToSelf()
        win32security.ImpersonateLoggedOnUser(restricted)
        try:
            with pytest.raises(PermissionError):
                with transaction.update_transaction(paths): pytest.fail('ordinary caller created trusted mutex')
        finally:
            win32security.RevertToSelf()
    finally:
        restricted.Close();token.Close()

@pytest.mark.skipif(os.name != 'nt', reason='native PowerShell/Python shared policy evidence')
@pytest.mark.parametrize('kind',['idle','pending','verifying','terminal','recovery','handoff','report','delivered','duplicate','oversized','bad_acl','bad_root_acl','null_acl','null'])
def test_powershell_and_python_state_gate_agree(transaction,tmp_path,kind):
    paths=WindowsUpdatePaths(tmp_path/'install',tmp_path/'data'/'updates'/'pending_update.json')
    paths.install_root.mkdir();paths.updates_root.mkdir(parents=True)
    for root in (paths.install_root,paths.updates_root.parent,paths.updates_root):_protect(root)
    operation='caa31a48-bf2f-4f1c-8b77-d1be77e12b4e'
    handoff=dict(operation_id=operation,assigned_version='3.2.82',rollback_version='3.2.79',scheduled_ack_delivered_at='2026-10-03T00:00:00+00:00')
    report=dict(operation_id=operation,report_key='a'*32,status='failed',reported_version='3.2.79',safe_code='launcher_apply_failed',delivered_at=None)
    leaves={
        'pending':(paths.pending_path,dict(operation_id=operation,version='3.2.82')),
        'verifying':(paths.updates_root/'startup-attempt.json',dict(operation_id=operation,version='3.2.82',attempt_id='a'*32)),
        'terminal':(paths.updates_root/'terminal-outcome.json',{k:v for k,v in report.items() if k not in ('report_key','delivered_at')}),
        'recovery':(paths.restore_path,{'version':'3.2.79'}),
        'handoff':(paths.updates_root/'endpoint_update_state.json',[handoff]),
        'report':(paths.updates_root/'endpoint_update_reports.json',[report]),
    }
    if kind in leaves:
        path,payload=leaves[kind];path.write_text(json.dumps(payload));_protect(path)
    elif kind=='delivered':
        report['delivered_at']='2026-10-03T00:00:00+00:00'
        for path,payload in [(paths.updates_root/'endpoint_update_state.json',[handoff]),(paths.updates_root/'endpoint_update_reports.json',[report])]:
            path.write_text(json.dumps(payload));_protect(path)
    elif kind in ('duplicate','oversized','bad_acl','bad_root_acl','null_acl','null'):
        paths.pending_path.write_text('{"operation_id":"x","operation_id":"y","version":"3.2.82"}' if kind=='duplicate' else 'x'*16385 if kind=='oversized' else 'null' if kind=='null' else '{"operation_id":"x","version":"3.2.82"}')
        _protect(paths.pending_path)
        if kind in ('bad_acl','bad_root_acl','null_acl'):
            import win32security
            acl=None if kind=='null_acl' else win32security.ConvertStringSecurityDescriptorToSecurityDescriptor('D:P(A;;FA;;;WD)',1).GetSecurityDescriptorDacl()
            win32security.SetNamedSecurityInfo(str(paths.updates_root if kind=='bad_root_acl' else paths.pending_path),1,
                win32security.DACL_SECURITY_INFORMATION|win32security.PROTECTED_DACL_SECURITY_INFORMATION,None,None,acl,None)
    try:
        actual='ACTIVE' if transaction.active_update_state(paths) else 'IDLE'
    except ValueError:
        actual='INVALID'
    script=tmp_path/'gate.ps1'
    source=Path(__file__).resolve().parents[3]/'packaging'/'windows'/'Install-EndpointAgentCanary.ps1'
    script.write_text('''param($Source,$Name,$Install,$Data)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Parse failed'}
foreach($node in $tree.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {
    Invoke-Expression ($node.Extent.Text.Replace('Global\\EndpointPlatform.Agent.UpdateTransaction',$Name))
}
$mutex=New-UpdateTransaction
try {
    Assert-UpdateTransactionSecurity $mutex
    if(-not $mutex.WaitOne(0)){throw 'Busy isolated mutex'}
    try { if(Test-ActiveUpdateState $Install $Data){'ACTIVE'}else{'IDLE'} } catch {[Console]::Error.WriteLine($_);'INVALID'}
    finally {$mutex.ReleaseMutex()}
}finally{$mutex.Dispose()}
''')
    result=subprocess.run([str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'powershell.exe'),'-NoProfile','-File',str(script),str(source),transaction._MUTEX_NAME,str(paths.install_root),str(paths.updates_root.parent)],capture_output=True,text=True,timeout=20,env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')})
    assert result.returncode==0,result.stderr
    expected='INVALID' if kind in ('duplicate','oversized','bad_acl','bad_root_acl','null_acl','null') else 'IDLE' if kind in ('idle','delivered') else 'ACTIVE'
    assert actual==expected
    assert result.stdout.strip()==expected,result.stderr


@pytest.mark.skipif(os.name != 'nt', reason='native Windows Authz owner-rights evidence')
@pytest.mark.parametrize('sid,desired,allowed',[
    ('S-1-5-19',0x40000,False), ('S-1-5-19',0x100001,False), ('S-1-5-19',0x20000,True),
    ('S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691',0x120001,True),
])
def test_localservice_owner_has_no_implicit_mutation_rights(transaction,sid,desired,allowed):
    # Authz evaluates actual Windows owner-rights semantics using a SID-only
    # context; this does not impersonate or run an installed service.
    import ctypes as c
    from ctypes import wintypes as w
    import win32security
    class Luid(c.Structure):
        _fields_=[('low',w.DWORD),('high',w.LONG)]
    class Request(c.Structure):
        _fields_=[('desired',w.DWORD),('self_sid',c.c_void_p),('types',c.c_void_p),('count',w.DWORD),('optional',c.c_void_p)]
    class Reply(c.Structure):
        _fields_=[('count',w.DWORD),('granted',c.POINTER(w.DWORD)),('sacl',c.POINTER(w.DWORD)),('error',c.POINTER(w.DWORD))]
    api=c.WinDLL('authz',use_last_error=True)
    init=api.AuthzInitializeResourceManager
    init.argtypes=[w.DWORD,c.c_void_p,c.c_void_p,c.c_void_p,w.LPCWSTR,c.POINTER(c.c_void_p)];init.restype=w.BOOL
    context_init=api.AuthzInitializeContextFromSid
    context_init.argtypes=[w.DWORD,c.c_void_p,c.c_void_p,c.c_void_p,Luid,c.c_void_p,c.POINTER(c.c_void_p)];context_init.restype=w.BOOL
    check=api.AuthzAccessCheck
    check.argtypes=[w.DWORD,c.c_void_p,c.POINTER(Request),c.c_void_p,c.c_void_p,c.c_void_p,w.DWORD,c.POINTER(Reply),c.c_void_p];check.restype=w.BOOL
    for name in ('AuthzFreeContext','AuthzFreeResourceManager'):
        getattr(api,name).argtypes=[c.c_void_p];getattr(api,name).restype=w.BOOL
    manager=c.c_void_p();context=c.c_void_p()
    sid_buffer=c.create_string_buffer(bytes(win32security.ConvertStringSidToSid(sid)))
    descriptor=c.create_string_buffer(bytes(win32security.ConvertStringSecurityDescriptorToSecurityDescriptor('O:LSG:LS'+transaction._MUTEX_SDDL,1)))
    assert init(1,None,None,None,'Endpoint isolated test',c.byref(manager)),c.get_last_error()
    try:
        assert context_init(2,sid_buffer,manager,None,Luid(),None,c.byref(context)),c.get_last_error()
        granted=w.DWORD();error=w.DWORD();sacl=w.DWORD()
        reply=Reply(1,c.pointer(granted),c.pointer(sacl),c.pointer(error))
        assert check(0,context,c.byref(Request(desired,None,None,0,None)),None,descriptor,None,0,c.byref(reply),None),c.get_last_error()
        assert (error.value==0 and granted.value==desired)==allowed
    finally:
        if context.value:api.AuthzFreeContext(context)
        api.AuthzFreeResourceManager(manager)

@pytest.mark.parametrize('defect',[None,'mode','links','owner'])
def test_posix_fallback_checks_lock_metadata_and_reentrancy(transaction,tmp_path,monkeypatch,defect):
    """Exercise fallback control flow on Windows; this is not Linux flock proof."""
    import stat
    from types import SimpleNamespace
    paths=WindowsUpdatePaths(tmp_path,tmp_path/'updates'/'pending_update.json')
    calls=[]
    fake=SimpleNamespace(LOCK_EX=2,LOCK_NB=4,LOCK_UN=8,flock=lambda fd,flags:calls.append(flags))
    monkeypatch.setitem(sys.modules,'fcntl',fake)
    proxy=SimpleNamespace(name='posix',O_CREAT=os.O_CREAT,O_RDWR=os.O_RDWR,O_NOFOLLOW=getattr(os,'O_NOFOLLOW',0),open=os.open,close=os.close,
        geteuid=lambda:0,fstat=lambda _:SimpleNamespace(st_mode=stat.S_IFREG|(0o666 if defect=='mode' else 0o600),st_nlink=2 if defect=='links' else 1,st_uid=1 if defect=='owner' else 0))
    monkeypatch.setattr(transaction,'os',proxy)
    original_lstat=Path.lstat
    monkeypatch.setattr(Path,'lstat',lambda path,*a,**k: SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0) if path==tmp_path else original_lstat(path,*a,**k))
    if defect:
        with pytest.raises(ValueError,match='lock is unsafe'):
            with transaction.update_transaction(paths,timeout_ms=0):pytest.fail('unsafe lock accepted')
        assert calls==[]
    else:
        with transaction.update_transaction(paths,timeout_ms=0):
            with transaction.update_transaction(paths,timeout_ms=0):
                assert calls==[6]
        assert calls==[6,8]

@pytest.mark.skipif(os.name!='nt',reason='native ordinary-owner spoof evidence')
def test_ordinary_precreated_object_cannot_spoof_canonical_owner(transaction,tmp_path):
    import win32api,win32security,win32event
    token=win32security.OpenProcessToken(win32api.GetCurrentProcess(),0xF01FF)
    ordinary=win32security.CreateRestrictedToken(token,1,[(win32security.ConvertStringSidToSid('S-1-5-32-544'),0)],None,None)
    attributes=win32security.SECURITY_ATTRIBUTES()
    descriptor=win32security.ConvertStringSecurityDescriptorToSecurityDescriptor('D:P(A;;GA;;;WD)',1)
    descriptor.SetSecurityDescriptorOwner(win32security.GetTokenInformation(token,win32security.TokenUser)[0],False)
    attributes.SECURITY_DESCRIPTOR=descriptor
    handle=None
    try:
        win32security.ImpersonateLoggedOnUser(ordinary)
        try:handle=win32event.CreateMutex(attributes,False,transaction._MUTEX_NAME)
        finally:win32security.RevertToSelf()
        with pytest.raises(ValueError,match='security is invalid'):
            with transaction.update_transaction(WindowsUpdatePaths(tmp_path,tmp_path/'updates'/'pending_update.json')):
                pytest.fail('ordinary precreation accepted')
    finally:
        if handle is not None:handle.Close()
        ordinary.Close();token.Close()
