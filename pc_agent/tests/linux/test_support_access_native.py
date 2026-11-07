"""Mock only OS lookup/command boundaries; native lifetime harness is separate."""
from types import SimpleNamespace
from pathlib import PurePosixPath
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
