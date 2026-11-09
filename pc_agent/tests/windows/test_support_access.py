from datetime import datetime, timezone, timedelta
import importlib
import uuid

import pytest

MODULE = 'pc_agent.platform.windows.support_access'
DEVICE = str(uuid.UUID('11111111-2222-4333-8444-555555555555'))
CREDENTIAL_ID = '00000000-0000-4000-8000-000000000001'
TOKEN = 'eps1.00000000000040008000000000000001.' + 'a'*64
KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'


def module():
    try:
        return importlib.import_module(MODULE)
    except ModuleNotFoundError:
        pytest.fail('independent support supervisor is not implemented')


def policy(now):
    return dict(device_id=DEVICE, enabled=True, expires_at=(now + timedelta(seconds=90)).isoformat(),
                gateway_host='endpoint.sosnadmin.local', gateway_port=2222, tunnel_user='eps-111111112222433384445555',
                gateway_host_public_key=KEY, remote_port=32001, local_port=22222,
                windows_admin_username='test_agent_win', operator_public_keys=[KEY], revision=1)


def test_expired_policy_rejected_before_any_process_can_start():
    now = datetime.now(timezone.utc)
    raw = policy(now)
    raw['expires_at'] = (now - timedelta(seconds=1)).isoformat()
    with pytest.raises(ValueError):
        module().SupportPolicy.parse(raw, device_id=DEVICE, now=now)


@pytest.mark.parametrize('field,value', [('device_id', str(uuid.uuid4())), ('gateway_host', 'host\nProxyCommand evil'),
    ('tunnel_user', '-oProxyCommand=evil'), ('windows_admin_username', 'user\nMatch all'),
    ('remote_port', 22), ('local_port', 22), ('operator_public_keys', ['command="evil" '+KEY]),
    ('expires_at', '2035-01-01T00:00:00Z')])
def test_untrusted_policy_cannot_supply_ssh_options_or_unbounded_lease(field, value):
    now = datetime.now(timezone.utc)
    raw = policy(now)
    raw[field] = value
    with pytest.raises(ValueError):
        module().SupportPolicy.parse(raw, device_id=DEVICE, now=now)


def test_tunnel_uses_device_alias_and_strict_hostkey_with_only_assigned_loopback_port(tmp_path):
    now = datetime.now(timezone.utc)
    p = module().SupportPolicy.parse(policy(now), device_id=DEVICE, now=now)
    args = module().tunnel_command('ssh.exe', tmp_path, p)
    assert '-N' in args and '-T' in args
    assert '127.0.0.1:32001:127.0.0.1:22222' in args
    assert 'StrictHostKeyChecking=yes' in args
    assert 'HostKeyAlias=endpoint-support-gateway' in args
    assert 'IdentitiesOnly=yes' in args
    assert 'BatchMode=yes' in args


def test_owned_sshd_config_only_loopback_and_explicit_existing_login(tmp_path):
    now = datetime.now(timezone.utc)
    p = module().SupportPolicy.parse(policy(now), device_id=DEVICE, now=now)
    cfg = module().sshd_config(tmp_path, p)
    assert 'ListenAddress 127.0.0.1' in cfg
    assert 'AllowUsers test_agent_win' in cfg
    assert 'PasswordAuthentication no' in cfg
    assert 'AllowTcpForwarding no' in cfg
    assert 'AllowAgentForwarding no' in cfg
    assert 'Match Group administrators' not in cfg
    assert str(tmp_path / 'authorized_keys').replace('\\', '/') in cfg


class Children:
    def __init__(self):
        self.active = False
        self.starts = 0
        self.stops = 0
    def start(self, p):
        self.active = True
        self.starts += 1
    def stop(self):
        self.active = False
        self.stops += 1
    def alive(self):
        return self.active


def test_api_outage_cannot_extend_local_monotonic_lease_or_leave_children_running():
    now = datetime.now(timezone.utc)
    children = Children()
    state = module().SupportSupervisor(DEVICE, children)
    state.accept(policy(now), now=now, monotonic_now=100)
    assert children.active
    state.tick(monotonic_now=159)
    assert children.active
    state.tick(monotonic_now=160)
    assert not children.active
    assert state.state == 'expired'
    state.tick(monotonic_now=200)
    assert children.starts == 1


def test_disable_or_wrong_identity_immediately_closes_existing_owned_children():
    now = datetime.now(timezone.utc)
    children = Children()
    state = module().SupportSupervisor(DEVICE, children)
    state.accept(policy(now), now=now, monotonic_now=100)
    raw = policy(now)
    raw['enabled'] = False
    state.accept(raw, now=now, monotonic_now=101)
    assert not children.active
    assert state.state == 'disabled'
    state.accept(policy(now), now=now, monotonic_now=102)
    raw['device_id'] = str(uuid.uuid4())
    with pytest.raises(ValueError):
        state.accept(raw, now=now, monotonic_now=103)
    assert not children.active


def test_no_successful_refresh_means_freshness_expires_within_sixty_seconds():
    now = datetime.now(timezone.utc)
    children = Children()
    state = module().SupportSupervisor(DEVICE, children)
    raw = policy(now)
    raw['expires_at'] = (now + timedelta(hours=23)).isoformat()
    state.accept(raw, now=now, monotonic_now=100)
    state.tick(monotonic_now=160)
    assert not children.active


def test_supervisor_can_failclosed_while_policy_request_is_blocked():
    from threading import Event, Thread
    now = datetime.now(timezone.utc)
    children = Children()
    state = module().SupportSupervisor(DEVICE, children)
    state.accept(policy(now), now=now, monotonic_now=100)
    entered = Event()
    unblock = Event()
    def blocked_request():
        entered.set()
        unblock.wait(2)
    worker = Thread(target=blocked_request)
    worker.start()
    assert entered.wait(1)
    try:
        state.tick(monotonic_now=161)
        assert not children.active
    finally:
        unblock.set()
        worker.join()


def test_http_origin_requires_canonical_https_hostname_and_no_userinfo_or_path(tmp_path):
    for origin in ['http://endpoint.sosnadmin.local','https://192.168.100.19',
                   'https://user:pass@endpoint.sosnadmin.local', 'https://endpoint.sosnadmin.local/evil']:
        with pytest.raises(ValueError):
            module().SupportHTTPClient(origin, tmp_path/'ca.pem', 'x'*43)


class _PayloadTestOps:
    def prepare_readiness(self,target,candidate,config_path):pass
    def activation_lock(self):
        import contextlib
        return contextlib.nullcontext()
    def private(self,path):pass
    def remove_runtime(self):pass
    def inspect_payload(self,path):
        import hashlib
        return {'version':(1,0,0,0),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    def prove_service_ready(self,target):pass
    def capture_service(self,target):return None
    def restore_service(self,target,state):pass
    def prepare_payload(self,source,target):
        from pc_agent.platform.windows.support_access_native import PayloadActivation
        return PayloadActivation(self,source,target)


def test_registration_reuses_existing_keys_and_persists_only_independent_credential(tmp_path):
    support = module()
    class Ops(_PayloadTestOps):
        def protect(self, p): p.mkdir(parents=True, exist_ok=True) if not p.exists() else None
        def dependencies(self,**kwargs): return {'ssh': 'ssh.exe','sshd': 'sshd.exe','keygen':'ssh-keygen.exe','version':'test'}
        def key(self, root, name):
            path = root/(name+'.pub')
            if not path.exists():
                path.write_text(KEY if name == 'tunnel_ed25519' else KEY[:-4]+'AQID')
            return path.read_text()
        def stop_for_update(self, executable): self.stopped = executable
        def install_service(self, executable):
            assert self.stopped == executable
            self.installed = executable
    class Client:
        def status(self,**kwargs):pytest.fail('installer cannot attest runtime version')
        def register(self, body):
            assert 'device_token' not in body
            assert body['component_version'] == support.COMPONENT_VERSION
            return dict(device_id=DEVICE, support_token=TOKEN, credential_id=CREDENTIAL_ID, policy={'enabled':False})
    (tmp_path/'signed.exe').write_bytes(b'signed-fixture')
    ops = Ops()
    data = tmp_path/'data'/'Agent'
    install = tmp_path/'programs'/'Agent'
    support.install_support_access(data, install, origin='https://endpoint.sosnadmin.local',
        ca_pem='CA-COPY',device_id=DEVICE,device_token='CORE-SECRET',
        service_executable=tmp_path/'signed.exe',_ops=ops,_client=Client())
    root = data.parent/'Support'
    contents = '\n'.join(p.read_text() for p in root.iterdir() if p.is_file())
    assert 'CORE-SECRET' not in contents
    assert TOKEN in contents
    assert 'CA-COPY' in contents
    assert ops.installed == install.parent/'Support'/'EndpointSupportAccess.exe'


def test_native_private_root_rejects_link_before_mutating_target(tmp_path):
    native = importlib.import_module('pc_agent.platform.windows.support_access_native')
    victim = tmp_path/'victim'
    victim.mkdir()
    link = tmp_path/'link'
    try:
        link.symlink_to(victim, target_is_directory=True)
    except OSError:
        pytest.skip('symlink creation privilege unavailable')
    with pytest.raises(ValueError):
        native.WindowsSupportOps().protect(link)


def test_restart_hash_guard_rejects_replaced_os_binary(tmp_path,monkeypatch):
    native = importlib.import_module('pc_agent.platform.windows.support_access_native')
    root = tmp_path/'System32'/'OpenSSH'
    root.mkdir(parents=True)
    dependencies={'hashes':{}}
    for role,name in [('ssh','ssh.exe'),('sshd','sshd.exe'),('keygen','ssh-keygen.exe')]:
        binary=root/name
        binary.write_bytes(b'replaced')
        dependencies[role]=str(binary)
        dependencies['hashes'][role]='0'*64
    monkeypatch.setattr(native,'windows_root',lambda:tmp_path)
    with pytest.raises(ValueError, match='dependency_changed'):
        native.verify_dependencies(dependencies)


def test_policy_can_only_name_existing_enabled_windows_admin(monkeypatch):
    native = importlib.import_module('pc_agent.platform.windows.support_access_native')
    import sys, types
    fake = types.SimpleNamespace(NetUserGetInfo=lambda *args:{'flags':0},
        NetUserGetLocalGroups=lambda *args:['Users'])
    monkeypatch.setitem(sys.modules,'win32net',fake)
    monkeypatch.setattr(native,'administrators_name',lambda:'Administrators',raising=False)
    with pytest.raises(ValueError, match='existing_admin_required'):
        native.validate_windows_admin('ordinary_user')

def test_job_cleanup_covers_both_children_when_second_launch_fails(tmp_path,monkeypatch):
    native = importlib.import_module('pc_agent.platform.windows.support_access_native')
    closed = []
    class Job:
        def __init__(self): self.count=0
        def launch(self,args,**kwargs):
            self.count += 1
            if self.count == 2: raise OSError('tunnel launch failed')
        def close(self): closed.append(True)
        def alive(self): return True
    monkeypatch.setattr(native,'NativeProcessJob',Job,raising=False)
    monkeypatch.setattr(native,'validate_windows_admin',lambda username:username)
    monkeypatch.setattr(native,'verify_dependencies',lambda deps:None)
    monkeypatch.setattr(native,'assert_private',lambda p:None)
    monkeypatch.setattr(native.WindowsSupportOps,'protect',lambda self,p:None)
    monkeypatch.setattr(native.subprocess,'run',lambda *args,**kw:__import__('types').SimpleNamespace(returncode=0))
    child = native.SupportChildren(tmp_path,{'ssh':'ssh.exe','sshd':'sshd.exe'})
    now = datetime.now(timezone.utc)
    p = module().SupportPolicy.parse(policy(now),device_id=DEVICE,now=now)
    with pytest.raises(OSError): child.start(p)
    assert closed
    assert not child.alive()

def test_real_windows_job_kills_child_on_support_stop():
    import sys
    import win32api, win32event, win32con
    native = importlib.import_module('pc_agent.platform.windows.support_access_native')
    job = native.NativeProcessJob()
    retained = None
    try:
        job.launch([sys.executable,'-c','import time; time.sleep(30)'])
        assert job.alive()
        retained = win32api.DuplicateHandle(win32api.GetCurrentProcess(),job.processes[0],
            win32api.GetCurrentProcess(),0,False,win32con.DUPLICATE_SAME_ACCESS)
        job.close()
        assert win32event.WaitForSingleObject(retained,5000) == win32event.WAIT_OBJECT_0
    finally:
        job.close()
        if retained: retained.Close()

def test_service_loop_forbidden_reply_stops_active_job_without_waiting_for_expiry(tmp_path):
    import threading
    service = importlib.import_module('pc_agent.platform.windows.support_access_service')
    now = datetime.now(timezone.utc)
    children = Children()
    stop = threading.Event()
    class Client:
        def __init__(self): self.calls=0
        def policy(self):
            self.calls+=1
            if self.calls==1: return policy(now)
            raise module().SupportHTTPError(403)
        def status(self,**kwargs): raise module().SupportHTTPError(403)
    observed = []
    def publish(state):
        observed.append(state)
        if state == 'revoked': stop.set()
    thread = threading.Thread(target=service.run_supervisor,args=(DEVICE,Client(),children,stop),kwargs={'publish':publish})
    thread.start()
    thread.join(3)
    stop.set()
    thread.join(2)
    assert 'revoked' in observed
    assert children.starts == 1
    assert not children.active

def test_standalone_install_reads_enrollment_once_and_never_requires_core(monkeypatch,tmp_path):
    service = importlib.import_module('pc_agent.platform.windows.support_access_service')
    data = tmp_path/'data'/'Support'
    programs = tmp_path/'programs'/'Support'
    agent = data.parent/'Agent'
    agent.mkdir(parents=True)
    (agent/'device-credential').write_text('c'*43)
    (agent/'endpoint-origin').write_text('https://endpoint.sosnadmin.local\n')
    (agent/'endpoint-ca.crt').write_text('CA-COPY')
    (agent/'enrollment-identity.json').write_text(__import__('json').dumps({'schema_version':'endpoint_enrollment_identity_v1','device_id':DEVICE}))
    monkeypatch.setattr(service,'production_roots',lambda:(data,programs))
    monkeypatch.setattr(service,'assert_bootstrap_file',lambda p:None,raising=False)
    received = []
    monkeypatch.setattr(service,'install_support_access',lambda *args,**kw:received.append(kw) or {'installed':True},raising=False)
    assert service.install_from_enrollment()['installed']
    assert received[0]['device_id'] == DEVICE
    assert received[0]['device_token'] == 'c'*43
    assert received[0]['origin'] == 'https://endpoint.sosnadmin.local'

def test_living_ssh_process_is_not_tunnel_connected_before_remote_forward_confirmation(tmp_path):
    native = importlib.import_module('pc_agent.platform.windows.support_access_native')
    child = native.SupportChildren(tmp_path,{})
    child.job = type('Job',(),{'alive':lambda self:True})()
    child.remote_port = 32001
    child.confirmation = native.ForwardConfirmation(32001)
    assert not child.connected()
    child.confirmation.feed(b'debug1: remote forward success for: listen 127.0.0.1:32001, connect 127.0.0.1:22222\n')
    assert child.connected()


def test_client_unregister_accepts_only_explicit204_without_following_redirect(monkeypatch,tmp_path):
    import http.client,ssl
    support = module()
    (tmp_path/'ca.pem').write_text('test')
    class Context:
        def load_verify_locations(self,**kwargs): pass
    monkeypatch.setattr(ssl,'SSLContext',lambda *args:Context())
    class Connection:
        def __init__(self,*args,**kw): pass
        def request(self,method,path,**kw):
            assert method=='POST'
            assert path=='/agent/v1/support-access/unregister'
        def getresponse(self): return type('Response',(),{'status':204,'read':lambda self,n:b''})()
        def close(self): pass
    monkeypatch.setattr(http.client,'HTTPSConnection',Connection)
    assert support.SupportHTTPClient('https://endpoint.sosnadmin.local',tmp_path/'ca.pem',TOKEN).unregister() == {}

def test_support_removal_revokes_then_stops_only_owned_service(tmp_path,monkeypatch):
    support = module()
    native = importlib.import_module('pc_agent.platform.windows.support_access_native')
    root = tmp_path/'Support'
    root.mkdir()
    (root/'credential').write_text('s'*43)
    order=[]
    class Client:
        def unregister(self): order.append('revoke'); return {}
    class Ops(_PayloadTestOps):
        def remove_service(self): order.append('stop')
        def remove_runtime(self):pass
        def remove_payload(self,program):return False
    monkeypatch.setattr(native,'production_roots',lambda:(root,tmp_path/'ProgramSupport'))
    monkeypatch.setattr(native,'assert_private',lambda p:None)
    result = support.uninstall_support_access(_ops=Ops(),_client=Client())
    assert order == ['revoke','stop']
    assert not (root/'credential').exists()
    assert result['revoked']

def test_parent_delete_child_permission_cannot_bypass_protected_support_root(monkeypatch,tmp_path):
    native = importlib.import_module('pc_agent.platform.windows.support_access_native')
    import sys,types
    class ACL:
        def GetAceCount(self): return 1
        def GetAce(self,index): return ((0,0),0x40,'S-1-5-19')
    class Descriptor:
        def GetSecurityDescriptorOwner(self): return 'S-1-5-32-544'
        def GetSecurityDescriptorDacl(self): return ACL()
    security=types.SimpleNamespace(GetNamedSecurityInfo=lambda *args:Descriptor(),SE_FILE_OBJECT=1,
        OWNER_SECURITY_INFORMATION=1,DACL_SECURITY_INFORMATION=4,ACCESS_ALLOWED_ACE_TYPE=0,
        INHERIT_ONLY_ACE=8,ConvertSidToStringSid=lambda sid:sid)
    monkeypatch.setitem(sys.modules,'win32security',security)
    with pytest.raises(ValueError,match='unsafe_support_namespace'):
        native.assert_namespace(tmp_path/'Support')

@pytest.mark.parametrize('binary,account', [('"C:\\Other\\unrelated.exe"','LocalSystem'),
    ('"C:\\Support\\EndpointSupportAccess.exe"','NT AUTHORITY\\LocalService'),
    ('"C:\\Support\\EndpointSupportAccess.exe" --evil','LocalSystem')])
def test_install_refuses_existing_unrelated_service_identity(binary,account):
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    config=(16,2,1,binary,'',0,[],account,'display')
    with pytest.raises(ValueError,match='support_service_conflict'):
        native.validate_service_config(config,__import__('pathlib').Path('C:/Support/EndpointSupportAccess.exe'))



def test_spaced_known_hosts_path_is_one_ssh_config_argument(tmp_path):
    import shlex
    root=tmp_path/'Endpoint Platform'/'Support'
    now=datetime.now(timezone.utc)
    p=module().SupportPolicy.parse(policy(now),device_id=DEVICE,now=now)
    args=module().tunnel_command('ssh.exe',root,p)
    option=next(value for value in args if value.startswith('UserKnownHostsFile='))
    assert shlex.split(option.split('=',1)[1]) == [str(root/'known_hosts').replace('\\','/')]

def test_bootstrap_accepts_real_canonical172_protected_credential_acl(tmp_path,monkeypatch):
    import win32security
    from pc_agent.platform.windows.acl import PyWin32AclAdapter
    from pc_agent.platform.windows.update_transaction import _SERVICE_SIDS
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    original=win32security.LookupAccountName
    identities={'NT SERVICE\\EndpointAgent':_SERVICE_SIDS[0],'NT SERVICE\\EndpointAgentUpdater':_SERVICE_SIDS[1]}
    def lookup(system,name):
        if name in identities: return win32security.ConvertStringSidToSid(identities[name]),'',5
        return original(system,name)
    monkeypatch.setattr(win32security,'LookupAccountName',lookup)
    path=tmp_path/'device-credential'
    path.write_text('c'*43)
    PyWin32AclAdapter().protect_credential(path)
    native.assert_bootstrap_file(path)

def test_remove_refuses_unrelated_service_before_any_stop_or_delete(monkeypatch,tmp_path):
    import sys,types
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    mutations=[]
    service=types.SimpleNamespace(SC_MANAGER_CONNECT=1,SERVICE_QUERY_CONFIG=1,
        OpenSCManager=lambda *a:'manager',OpenService=lambda *a:'service',
        QueryServiceConfig=lambda *a:(16,2,1,'"C:\\Other\\unrelated.exe"','',0,[],'LocalSystem','display'),
        CloseServiceHandle=lambda *a:None,SERVICE_STOPPED=1)
    util=types.SimpleNamespace(StopService=lambda *a:mutations.append('stop'),RemoveService=lambda *a:mutations.append('delete'),WaitForServiceStatus=lambda *a:None)
    monkeypatch.setitem(sys.modules,'win32service',service)
    monkeypatch.setitem(sys.modules,'win32serviceutil',util)
    monkeypatch.setattr(native,'production_roots',lambda:(tmp_path/'data',tmp_path/'program'))
    with pytest.raises(ValueError,match='support_service_conflict'):
        native.WindowsSupportOps().remove_service()
    assert mutations==[]



def test_real_keygen_under_elevated_admin_becomes_system_owned_private_support_key():
    import shutil
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    root=native.native_folder(0x23)/('EndpointSupportAccessTest-'+uuid.uuid4().hex)
    ops=native.WindowsSupportOps()
    try:
        ops.protect(root)
        key=ops.key(root,'tunnel_ed25519')
        assert key.startswith('ssh-ed25519 ')
        native.assert_private(root/'tunnel_ed25519')
        native.assert_private(root/'tunnel_ed25519.pub')
        native.atomic_write(root/'credential','eps1.test-fixture')
        ops.protect(root/'credential')
        native.assert_private(root/'credential')
        import win32security
        foreign=root/'foreign-owner'
        foreign.write_bytes(b'not adopted')
        win32security.SetNamedSecurityInfo(str(foreign),win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION,
            win32security.ConvertStringSidToSid('S-1-5-32-545'),None,None,None)
        with pytest.raises(ValueError,match='unsafe_support_acl'):
            ops.protect(foreign)
    finally:
        # Unique test-created root only, never a product directory.
        assert root.parent==native.native_folder(0x23) and root.name.startswith('EndpointSupportAccessTest-')
        if root.exists(): shutil.rmtree(root)

def test_real_pywin32_binds_enabled_local_administrator_status_and_sid():
    import win32api,win32net,win32netcon,win32security
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    admin_group=native.administrators_name().casefold()
    admins=[entry['name'] for entry in win32net.NetUserEnum(None,1,0)[0]
            if not entry['flags']&win32netcon.UF_ACCOUNTDISABLE and admin_group in
            {group.casefold() for group in win32net.NetUserGetLocalGroups(None,entry['name'],win32netcon.LG_INCLUDE_INDIRECT)}]
    assert admins,'A real enabled local administrator is required for native API qualification'
    name=admins[0];qualified=win32api.GetComputerName()+'\\'+name
    sid,domain,kind=win32security.LookupAccountName(None,qualified)
    info=win32net.NetUserGetInfo(None,name,4)
    assert kind==win32security.SidTypeUser
    assert win32security.ConvertSidToStringSid(info['user_sid'])==win32security.ConvertSidToStringSid(sid)
    assert not info['flags']&win32netcon.UF_ACCOUNTDISABLE
    assert admin_group in {group.casefold() for group in win32net.NetUserGetLocalGroups(None,qualified,win32netcon.LG_INCLUDE_INDIRECT)}
    try:module().windows_ssh_principal(name)
    except ValueError:
        # This operator host has only a Unicode/spaced local admin, outside the
        # policy's existing ASCII SAM grammar; no new test account is created.
        with pytest.raises(ValueError):native.validate_windows_admin(name)
    else:
        assert native.validate_windows_admin(name)==name.lower()
        assert native.validate_windows_admin(qualified)==name.lower()


@pytest.mark.parametrize('marker',[DEVICE,str(uuid.uuid4()),None])
def test_registration_rotation_requires_authenticated_own_device_reset_marker(tmp_path,marker):
    support=module()
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    events=[]
    rotated=[False]
    new_tunnel=KEY[:-4]+'AQID'
    new_host=KEY[:-4]+'BAUG'
    class Ops(_PayloadTestOps):
        def protect(self,p):
            if not p.exists():p.mkdir(parents=True)
        def dependencies(self,**kwargs):return {}
        def key(self,root,name):return (new_tunnel if name=='tunnel_ed25519' else new_host) if rotated[0] else (KEY if name=='tunnel_ed25519' else new_tunnel)
        def stop_for_update(self,path):events.append('stop')
        def rotate_keys(self,root):events.append('rotate');rotated[0]=True
        def install_service(self,path):events.append('install')
    class Client:
        calls=0
        def register(self,body):
            self.calls+=1
            if self.calls==1:raise support.SupportHTTPError(409,reset_device_id=marker)
            assert body['tunnel_public_key']==new_tunnel and body['host_public_key']==new_host
            return dict(device_id=DEVICE,credential_id=CREDENTIAL_ID,support_token=TOKEN)
    client=Client()
    exe=tmp_path/'signed.exe';exe.write_bytes(b'fixture')
    def install():return support.install_support_access(tmp_path/'data'/'Agent',tmp_path/'program'/'Agent',
        origin='https://endpoint.sosnadmin.local',ca_pem='CA',device_id=DEVICE,device_token='c'*43,
        service_executable=exe,_ops=Ops(),_client=client)
    if marker==DEVICE:
        assert install()['installed']
        assert events.index('stop')<events.index('rotate')
        assert events.count('rotate')==1 and client.calls==2
    else:
        with pytest.raises(support.SupportHTTPError):install()
        assert events==[] and client.calls==1

@pytest.mark.parametrize('status,marker,bootstrap,expected',[(409,DEVICE,True,DEVICE),(409,'bad',True,None),(403,DEVICE,True,None),(409,DEVICE,False,None)])
def test_http_reset_marker_only_from_authenticated_registration_conflict(monkeypatch,tmp_path,status,marker,bootstrap,expected):
    import http.client,ssl
    support=module()
    class Context:
        def load_verify_locations(self,**kw):pass
    class Response:
        def read(self,n):return b'{}'
        def getheader(self,name):return marker
    response=Response();response.status=status
    class Connection:
        def __init__(self,*a,**k):pass
        def request(self,*a,**k):pass
        def getresponse(self):return response
        def close(self):pass
    monkeypatch.setattr(ssl,'SSLContext',lambda *a:Context())
    monkeypatch.setattr(http.client,'HTTPSConnection',Connection)
    client=support.SupportHTTPClient('https://endpoint.sosnadmin.local',tmp_path/'ca.pem','c'*43 if bootstrap else TOKEN,bootstrap=bootstrap)
    with pytest.raises(support.SupportHTTPError) as caught:
        client.request('register' if bootstrap else 'policy',{} if bootstrap else None)
    assert caught.value.reset_device_id==expected


def test_real_reset_rotation_changes_only_owned_support_keys():
    import shutil
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    root=native.native_folder(0x23)/('EndpointSupportAccessTest-'+uuid.uuid4().hex)
    ops=native.WindowsSupportOps()
    try:
        ops.protect(root)
        old=[ops.key(root,name) for name in ('tunnel_ed25519','host_ed25519')]
        native.atomic_write(root/'credential','preserve-independent-credential');ops.protect(root/'credential')
        ops.rotate_keys(root)
        new=[ops.key(root,name) for name in ('tunnel_ed25519','host_ed25519')]
        assert all(a!=b for a,b in zip(old,new)) and new[0]!=new[1]
        assert (root/'credential').read_text()=='preserve-independent-credential'
    finally:
        assert root.parent==native.native_folder(0x23) and root.name.startswith('EndpointSupportAccessTest-')
        if root.exists():shutil.rmtree(root)

def test_owned_image_wait_tracks_real_exit_before_payload_replacement():
    import sys,subprocess,time
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    process=subprocess.Popen([sys.executable,'-c','import time;time.sleep(.3)'])
    try:
        started=time.monotonic()
        with native.OwnedImageProcesses(__import__('pathlib').Path(sys.executable),only_pids={process.pid}) as retained:
            assert len(retained.handles)==1
            retained.wait(timeout=5)
            assert process.poll()==0
        assert time.monotonic()-started>=.15
    finally:
        if process.poll() is None:process.terminate();process.wait()

def test_real_captured_job_bounds_diagnostics_and_excludes_unrelated_inheritable_handle():
    import sys,time,win32event,win32security,win32api
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    security=win32security.SECURITY_ATTRIBUTES();security.bInheritHandle=True
    unrelated=win32event.CreateEvent(security,True,False,None)
    collector=native.ForwardConfirmation(32001)
    job=native.NativeProcessJob()
    code=("import ctypes,sys,time;from ctypes import wintypes;"
          f"leaked=ctypes.windll.kernel32.SetEvent(wintypes.HANDLE({int(unrelated)}));"
          "sys.stderr.write('x'*20000+'\\n');"
          "sys.stderr.write('remote forward success for: listen 127.0.0.1:32001, connect 127.0.0.1:22222\\n');"
          "sys.stderr.flush();time.sleep(30)")
    try:
        job.launch([sys.executable,'-c',code],stderr=collector)
        deadline=time.monotonic()+5
        while not collector.confirmed and time.monotonic()<deadline:time.sleep(.02)
        assert collector.confirmed
        assert len(collector.tail)<=8192
        assert win32event.WaitForSingleObject(unrelated,0)==win32event.WAIT_TIMEOUT
        assert job.alive()
        job.close()
        assert not job.alive()
    finally:
        job.close();win32api.CloseHandle(unrelated)


def test_reset_reply_loss_retains_new_real_keys_for_idempotent_next_install():
    import shutil
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    support=module()
    fixture=native.native_folder(0x23)/('EndpointSupportAccessTest-'+uuid.uuid4().hex)
    class Ops(_PayloadTestOps,native.WindowsSupportOps):
        rotations=0
        def dependencies(self,**kwargs):return {}
        def stop_for_update(self,path):pass
        def install_service(self,path):pass
        def rotate_keys(self,root):self.rotations+=1;super().rotate_keys(root)
    class Server:
        calls=0
        registered=None
        def register(self,body):
            self.calls+=1
            if self.calls==1:raise support.SupportHTTPError(409,reset_device_id=DEVICE)
            if self.calls==2:self.registered=dict(body);raise ConnectionError('reply lost after commit')
            assert body==self.registered
            return dict(device_id=DEVICE,credential_id=CREDENTIAL_ID,support_token=TOKEN)
    ops=Ops();server=Server()
    try:
        ops.protect(fixture)
        agent=fixture/'data'/'Agent';agent.mkdir(parents=True)
        (agent/'device-credential').write_text('preserved-core-private-fixture')
        executable=fixture/'signed-fixture.exe';executable.write_bytes(b'fixture')
        def install():return support.install_support_access(agent,fixture/'program'/'Agent',
            origin='https://endpoint.sosnadmin.local',ca_pem='CA',device_id=DEVICE,device_token='c'*43,
            service_executable=executable,_ops=ops,_client=server)
        with pytest.raises(ConnectionError):install()
        root=agent.parent/'Support'
        retained=[(root/name).read_bytes() for name in ('tunnel_ed25519','host_ed25519')]
        assert install()['installed']
        assert retained==[(root/name).read_bytes() for name in ('tunnel_ed25519','host_ed25519')]
        assert ops.rotations==1 and server.calls==3
        assert (agent/'device-credential').read_text()=='preserved-core-private-fixture'
    finally:
        assert fixture.parent==native.native_folder(0x23) and fixture.name.startswith('EndpointSupportAccessTest-')
        if fixture.exists():shutil.rmtree(fixture)

@pytest.mark.parametrize('failure',[None,'signature','start','readiness'])
def test_activation_stages_before_stop_and_restores_owned_image_on_failure(tmp_path,failure):
    import hashlib,contextlib
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    events=[]
    class Ops(native.WindowsSupportOps):
        def activation_lock(self):return contextlib.nullcontext()
        def private(self,path):pass
        def protect(self,path):pass
        def inspect_payload(self,path):
            if failure=='signature' and 'pending' in path.name:raise ValueError('support_signature_invalid')
            return {'version':((1,0,0,0) if 'pending' in path.name else (0,0,0,0)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        def capture_service(self,target):return {'running':True,'config':('old',)}
        def stop_for_update(self,target):events.append('stop')
        def install_service(self,target):
            events.append('start')
            if failure=='start':raise RuntimeError('start failed')
        def prove_service_ready(self,target):
            if failure=='readiness':raise RuntimeError('accepted start crashed')
        def restore_service(self,target,state):events.append('restore')
    source=tmp_path/'offer.exe';source.write_bytes(b'new payload')
    target=tmp_path/'EndpointSupportAccess.exe';target.write_bytes(b'old payload')
    def activate():
        with Ops().prepare_payload(source,target) as activation:
            assert target.read_bytes()==b'old payload' and events==[]
            activation.apply(reload=True)
    if failure:
        with pytest.raises((RuntimeError,ValueError)):activate()
        assert target.read_bytes()==b'old payload'
        assert events==([] if failure=='signature' else ['stop','start','stop','restore'])
    else:
        activate();assert target.read_bytes()==b'new payload' and events==['stop','start']


def test_activation_preserves_orphan_rollback_image(tmp_path):
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    class Ops(_PayloadTestOps):
        def protect(self,path):pass
    target=tmp_path/'EndpointSupportAccess.exe'
    backup=target.with_suffix('.previous.exe');backup.write_bytes(b'only prior image')
    source=tmp_path/'stage.exe';source.write_bytes(b'new')
    with pytest.raises(RuntimeError,match='recovery_required'):
        with Ops().prepare_payload(source,target):pytest.fail('orphan must block activation')
    assert backup.read_bytes()==b'only prior image' and not target.exists()


def test_active_payload_removal_waits_exact_images_before_unlink(monkeypatch,tmp_path):
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    events=[]
    class Processes:
        def __init__(self,target):events.append(('capture',target))
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def wait(self,*,timeout):events.append('wait')
    class Ops(_PayloadTestOps,native.WindowsSupportOps):pass
    monkeypatch.setattr(native,'OwnedImageProcesses',Processes)
    program=tmp_path/'Support';program.mkdir()
    target=program/'EndpointSupportAccess.exe';target.write_bytes(b'owned signed fixture')
    assert Ops().remove_payload(program) is False
    assert events==[('capture',target),'wait'] and not program.exists()


def test_active_payload_removal_preserves_image_on_exit_timeout(monkeypatch,tmp_path):
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    class Processes:
        def __init__(self,target):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def wait(self,*,timeout):raise TimeoutError('still mapped')
    class Ops(_PayloadTestOps,native.WindowsSupportOps):pass
    monkeypatch.setattr(native,'OwnedImageProcesses',Processes)
    target=tmp_path/'EndpointSupportAccess.exe';target.write_bytes(b'owned signed fixture')
    with pytest.raises(TimeoutError):Ops().remove_payload(tmp_path)
    assert target.read_bytes()==b'owned signed fixture'


def test_native_payload_signature_rejects_unsigned_before_activation(tmp_path):
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    unsigned=tmp_path/'unsigned.exe';unsigned.write_bytes(b'not a signed PE image')
    with pytest.raises(ValueError,match='support_signature_invalid'):
        native.WindowsSupportOps().inspect_payload(unsigned)


def test_native_activation_mutex_sdk_boundary():
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    with native.WindowsSupportOps().activation_lock():pass


def test_uninstall_waits_for_activation_mutex(monkeypatch,tmp_path):
    import threading
    native=importlib.import_module('pc_agent.platform.windows.support_access_native')
    entered=threading.Event();errors=[]
    class Ops(_PayloadTestOps):
        def activation_lock(self):return native.WindowsSupportOps().activation_lock()
        def remove_service(self):entered.set()
        def remove_payload(self,program):return False
    monkeypatch.setattr(native,'production_roots',lambda:(tmp_path/'absent',tmp_path/'program'))
    def remove():
        try:module().uninstall_support_access(_ops=Ops())
        except BaseException as error:errors.append(error)
    with native.WindowsSupportOps().activation_lock():
        thread=threading.Thread(target=remove);thread.start()
        assert not entered.wait(.15)
    thread.join(5)
    assert not thread.is_alive() and entered.is_set() and not errors
