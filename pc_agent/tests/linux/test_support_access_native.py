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
