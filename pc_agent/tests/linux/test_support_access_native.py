"""Mock only OS lookup/command boundaries; native lifetime harness is separate."""
from types import SimpleNamespace
from pathlib import PurePosixPath
import stat
import pytest
from pc_agent.platform.linux import support_access_native as n
from pc_agent.platform.linux.support_access import SupportError


def test_nss_exact_uid_and_unlocked_admin_required():
    record = SimpleNamespace(pw_name='root', pw_uid=0, pw_shell='/bin/bash')
    shadow = SimpleNamespace(sp_pwdp='$6$opaque', sp_expire=-1, sp_lstchg=20000, sp_max=-1)
    assert n.validate_account('root',0,lookup_name=lambda _:record,lookup_uid=lambda _:record,
        lookup_shadow=lambda _:shadow, admin_probe=lambda _:True, day=20001) == ('root',0)
    for bad in (SimpleNamespace(pw_name='other',pw_uid=0,pw_shell='/bin/bash'),
                SimpleNamespace(pw_name='root',pw_uid=10,pw_shell='/bin/bash')):
        with pytest.raises(SupportError):
            n.validate_account('root',0,lookup_name=lambda _:bad,lookup_uid=lambda _:record,
                lookup_shadow=lambda _:shadow, admin_probe=lambda _:True, day=20001)
    for password in ('!$6$opaque','*',''):
        shadow.sp_pwdp = password
        with pytest.raises(SupportError):
            n.validate_account('root',0,lookup_name=lambda _:record,lookup_uid=lambda _:record,
                lookup_shadow=lambda _:shadow, admin_probe=lambda _:True, day=20001)


def test_unprivileged_wheel_membership_is_not_admin_proof():
    record = SimpleNamespace(pw_name='operator',pw_uid=1000,pw_shell='/bin/bash')
    shadow = SimpleNamespace(sp_pwdp='$6$opaque',sp_expire=-1,sp_lstchg=20000,sp_max=-1)
    with pytest.raises(SupportError):
        n.validate_account('operator',1000,lookup_name=lambda _:record,lookup_uid=lambda _:record,
            lookup_shadow=lambda _:shadow,admin_probe=lambda _:False,day=20001)


def test_cgroup_command_bounds_descendants_and_binds_only_support_parent():
    command = n.child_command('endpoint-support-access-sshd.service', ['/usr/sbin/sshd','-D'], 28)
    assert '--property=KillMode=control-group' in command
    assert '--property=RuntimeMaxSec=28' in command
    assert '--property=BindsTo=endpoint-support-access.service' in command
    assert '--property=KillSignal=SIGKILL' in command
    assert command[-2:] == ['/usr/sbin/sshd','-D']
    with pytest.raises(SupportError):
        n.child_command('sshd.service', ['/usr/sbin/sshd','-D'],28)


def test_native_path_root_is_fixed_and_public_private_are_separate():
    paths = n.SupportPaths()
    assert str(paths.private).replace('\\','/') == '/var/lib/endpoint-support-access'
    assert paths.public != paths.private
    with pytest.raises(SupportError):
        n.support_unit(PurePosixPath('/opt/x\nExecStart=/evil'))


def test_forward_receipt_requires_ack_and_same_master_socket_and_policy(monkeypatch):
    paths=n.SupportPaths(PurePosixPath('/private'),PurePosixPath('/public'))
    child=n.NativeChildren(SimpleNamespace(paths=paths))
    assert not child.connected()
    child.forward_receipt=((100,200),('socket',10),3)
    child.policy_revision=3
    monkeypatch.setattr(child,'alive',lambda:True)
    monkeypatch.setattr(child,'master_identity',lambda:(100,200))
    monkeypatch.setattr(n,'control_socket_identity',lambda *_:('socket',10))
    assert child.connected()
    child.policy_revision=4
    assert not child.connected()
    assert child.forward_receipt is None
    child.forward_receipt=((100,200),('socket',10),4)
    monkeypatch.setattr(child,'master_identity',lambda:(101,201))
    assert not child.connected()
    child.forward_receipt=((101,201),('socket',10),4)
    monkeypatch.setattr(n,'control_socket_identity',lambda *_:('socket',11))
    assert not child.connected()


@pytest.mark.parametrize('failure', [None,'account','keys','configuration'])
def test_readiness_rechecks_local_dependencies_without_starting_children(monkeypatch,failure):
    from pc_agent.tests.linux.test_support_access import parse,policy,key
    writes=[];commands=[];checks=[]
    class Store:
        paths=n.SupportPaths(PurePosixPath('/private'),PurePosixPath('/public'))
        def keys(self):
            checks.append('keys')
            if failure=='keys':raise SupportError('key_mismatch')
            return key(1),key(2)
        def write(self,name,data,**kwargs):writes.append(name)
    def account(*_):
        checks.append('account')
        if failure=='account':raise SupportError('account_not_authorized')
    def command(argv):
        commands.append(argv)
        if failure=='configuration':raise SupportError('native_command_failed')
    monkeypatch.setattr(n,'validate_account',account)
    monkeypatch.setattr(n,'native_command',command)
    child=n.NativeChildren(Store())
    if failure:
        with pytest.raises(SupportError):child.prepare(parse(policy()))
    else:
        assert child.prepare(parse(policy()))=='/private/sshd_config'
        assert checks==['keys','account']
        assert writes==['0','known_hosts','sshd_config']
    assert all(argv==['/usr/sbin/sshd','-t','-f','/private/sshd_config'] for argv in commands)
    assert not child.active and child.forward_receipt is None


@pytest.fixture
def activation_os(monkeypatch):
    """Model only systemd/process/socket boundaries, including a dead first SSH."""
    from pc_agent.tests.linux.test_support_access import parse,policy
    state=SimpleNamespace(now=100.,ready_at=110.,launches=[],stops=[],socket=None,
        units={unit:False for unit in n.CHILD_UNITS},pid=200,acknowledged=False)
    class OwnedPath(PurePosixPath):
        def lstat(self):
            assert str(self)=='/private/mux'
            if state.socket is None:raise FileNotFoundError
            return SimpleNamespace(st_mode=state.socket,st_uid=0,st_gid=0,st_nlink=1)
        def unlink(self):
            assert not state.units[n.CHILD_UNITS[1]]
            state.socket=None
    class Store:
        paths=n.SupportPaths(OwnedPath('/private'),PurePosixPath('/public'))
        def keys(self):pass
        def write(self,*args,**kwargs):pass
    def native(argv,**kwargs):
        if argv[:2]==['/usr/sbin/sshd','-t']:return ''
        if argv[0]=='/usr/bin/systemd-run':
            unit=next(arg.split('=',1)[1] for arg in argv if arg.startswith('--unit='))
            lifetime=int(next(arg.split('=',2)[2] for arg in argv if arg.startswith('--property=RuntimeMaxSec=')))
            assert unit in n.CHILD_UNITS
            state.launches.append((unit,state.now,lifetime))
            if unit==n.CHILD_UNITS[1]:
                assert state.socket is None  # Never silently reuse a stale mux.
                state.pid+=1
                state.units[unit]=state.now>=state.ready_at
                state.socket=stat.S_IFSOCK|0o600
            else:state.units[unit]=True
            return ''
        if argv[1]=='is-active':
            if not all(state.units[unit] for unit in argv[2:]):raise SupportError('native_command_failed')
            return 'active\nactive\n'
        if argv[1]=='show':return str(state.pid if state.units[n.CHILD_UNITS[1]] else 0)
        if argv[0]=='/usr/bin/ssh' and '-O' in argv:
            assert state.units[n.CHILD_UNITS[1]]
            state.acknowledged=True
            return ''
        raise AssertionError(argv)
    def subprocess_run(argv,**kwargs):
        assert argv[0]=='/usr/bin/systemctl'
        if argv[1] in ('kill','stop'):
            units=argv[-1:] if argv[1]=='kill' else argv[2:]
            assert set(units)<=set(n.CHILD_UNITS)
            state.stops.extend(units)
            for unit in units:state.units[unit]=False
            return SimpleNamespace(returncode=0)
        assert argv[1:4]==['show','--property=ActiveState','--value']
        return SimpleNamespace(returncode=0,stdout=b'inactive\n')
    def process(pid):
        if not pid:raise SupportError('master_unavailable')
        return pid,pid*10
    def socket_identity(private,pid):
        assert pid==state.pid and state.units[n.CHILD_UNITS[1]]
        return 1,pid,1
    monkeypatch.setattr(n,'boot_time',lambda:state.now)
    monkeypatch.setattr(n.time,'sleep',lambda seconds:setattr(state,'now',state.now+seconds))
    monkeypatch.setattr(n,'native_command',native)
    monkeypatch.setattr(n.subprocess,'run',subprocess_run)
    monkeypatch.setattr(n,'process_identity',process)
    monkeypatch.setattr(n,'control_socket_identity',socket_identity)
    monkeypatch.setattr(n,'_directory',lambda *args,**kwargs:None)
    monkeypatch.setattr(n,'validate_account',lambda *args:None)
    state.child=n.NativeChildren(Store())
    state.policy=parse(policy())
    return state


def test_gateway_authorization_delay_restarts_dead_master_and_requires_real_ack(activation_os):
    state=activation_os
    state.child.start(state.policy,160)
    assert state.child.active and state.child.connected() and state.acknowledged
    assert state.now>=110
    assert sum(unit==n.CHILD_UNITS[0] for unit,_,_ in state.launches)==1
    assert n.CHILD_UNITS[0] not in state.stops
    tunnels=[(when,lifetime) for unit,when,lifetime in state.launches if unit==n.CHILD_UNITS[1]]
    assert len(tunnels)>1
    assert all(when+lifetime<=157 for when,lifetime in tunnels)
    assert tunnels[-1][1]<tunnels[0][1]  # Original expiry, never a renewed lease.


def test_persistent_gateway_failure_exhausts_activation_budget_and_closes_children(activation_os):
    state=activation_os
    state.ready_at=1000
    with pytest.raises(SupportError,match='child_start_failed'):
        state.child.start(state.policy,1000)
    assert 110<=state.now<=115
    assert not any(state.units.values()) and state.socket is None
    assert not state.child.connected() and not state.child.active


@pytest.mark.parametrize('deadline',[99,106])
def test_expired_or_short_policy_cannot_start_children(activation_os,deadline):
    state=activation_os
    with pytest.raises(SupportError):state.child.start(state.policy,deadline)
    assert state.launches==[]
    assert not state.child.connected()


def test_retry_stops_before_original_policy_deadline(activation_os):
    state=activation_os
    with pytest.raises(SupportError):state.child.start(state.policy,109)
    assert all(when<109 and when+lifetime<109 for _,when,lifetime in state.launches)
    assert state.now<109 and not any(state.units.values())


def test_retry_rejects_foreign_control_node_without_replacing_it(activation_os,monkeypatch):
    state=activation_os
    original=n.native_command
    def native(argv,**kwargs):
        result=original(argv,**kwargs)
        if argv[0]=='/usr/bin/systemd-run' and '--unit='+n.CHILD_UNITS[1] in argv:
            state.socket=stat.S_IFREG|0o600
        return result
    monkeypatch.setattr(n,'native_command',native)
    with pytest.raises(SupportError):state.child.start(state.policy,160)
    assert sum(unit==n.CHILD_UNITS[1] for unit,_,_ in state.launches)==1
    assert state.socket==stat.S_IFREG|0o600
    assert not state.child.connected() and not any(state.units.values())


def test_live_master_with_unverified_mux_fails_closed_without_retry(activation_os,monkeypatch):
    state=activation_os
    state.ready_at=100
    rejected=[]
    def reject_live_socket(private,pid):
        assert pid==state.pid and all(state.units.values())
        rejected.append(pid)
        raise SupportError('unsafe_control_socket')
    monkeypatch.setattr(n,'control_socket_identity',reject_live_socket)
    with pytest.raises(SupportError,match='child_start_failed'):
        state.child.start(state.policy,160)
    tunnels=[(when,lifetime) for unit,when,lifetime in state.launches if unit==n.CHILD_UNITS[1]]
    assert len(tunnels)==1
    assert len(set(rejected))==1
    assert tunnels[0][0]+tunnels[0][1]<=157
    assert not any(state.units.values()) and state.socket is None
    assert not state.acknowledged and state.child.forward_receipt is None
    assert not state.child.active and not state.child.connected()
