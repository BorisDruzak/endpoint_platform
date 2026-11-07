"""Explicit root-only disposable ALT harness. Never touches real product units.

Usage: python support_access_native_harness.py /var/tmp/endpoint-linux178-support-harness-<hex>
Creates only its own prefixed systemd parent/children and temporary SSH keys.
Retains all owned harness evidence on failure. Controller owns final cleanup.
"""
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import subprocess
import sys
import time

from pc_agent.platform.linux import support_access as s
from pc_agent.platform.linux import support_access_native as n


def harness_child(unit,argv,seconds,parent):
    """Only rename owned units for the harness; lifetime properties are real."""
    assert re.fullmatch(r'endpoint-linux178-harness-[a-f0-9]+\.service',parent)
    assert unit in [parent.replace('.service','-'+role+'.service') for role in ('sshd','descendant')]
    command=n.child_command(n.CHILD_UNITS[0],argv,seconds)
    return [arg.replace(n.CHILD_UNITS[0],unit).replace(s.SERVICE_NAME,parent) for arg in command]


def run(root):
    assert os.geteuid() == 0
    assert re.fullmatch('/var/tmp/endpoint-linux178-support-harness-[a-f0-9]+',str(root))
    assert root.is_dir() and not root.is_symlink() and stat.S_IMODE(root.stat().st_mode)==0o700
    token = root.name.rsplit('-',1)[-1]
    parent = 'endpoint-linux178-harness-'+token+'.service'
    sshd_unit = parent.replace('.service','-sshd.service')
    child_unit = parent.replace('.service','-descendant.service')
    public=Path('/run/endpoint-linux178-harness-'+token+'-public')
    assert not public.exists() and not public.is_symlink()
    paths = n.SupportPaths(root/'private',public)
    store = n.PrivateStore(paths)
    store.prepare()
    (root/'public-owned.json').write_text(json.dumps({'path':str(public),'uid':0,'mode':'0755'}))
    evidence = {'systemd':n.native_command(['/usr/bin/systemctl','--version'],output=True).splitlines()[0],
        'checks':[],'units':[parent,sshd_unit,child_unit]}
    with store.locked():
        store.write('sentinel',b'preserved')
        assert store.read('sentinel')==b'preserved'
        for name in ('symlink','hardlink','fifo'):
            target=paths.private/name
            if name=='symlink': target.symlink_to(paths.private/'sentinel')
            elif name=='hardlink': os.link(paths.private/'sentinel',target)
            else: os.mkfifo(target,0o600)
            try:
                store.read(name)
            except s.SupportError: pass
            else: raise AssertionError('Unsafe node accepted: '+name)
            try: store.write(name,b'overwrite')
            except s.SupportError: pass
            else: raise AssertionError('Unsafe node overwritten: '+name)
            target.unlink()
        assert store.read('sentinel')==b'preserved'
        unsafe=root/'unsafe'
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        try: n.PrivateStore(n.SupportPaths(unsafe,paths.public)).read('anything',missing=True)
        except s.SupportError: pass
        else: raise AssertionError('Unsafe store accepted')
        evidence['checks'].append('symlink_hardlink_fifo_writable_store_rejected')
        host,tunnel=store.keys(create=True)
        assert host!=tunnel
        assert store.keys()==(host,tunnel)
        evidence['checks'].append('distinct_retained_private_keys')
        try:
            with store.locked():
                raise AssertionError('Concurrent private lock accepted')
        except s.SupportError: pass
        evidence['checks'].append('exclusive_native_lock')
        assert n.validate_account('root',0)==('root',0)
        evidence['checks'].append('native_nss_root_uid_unlocked')
        operator=root/'operator'
        n.native_command(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-C','','-f',str(operator)])
        op=s.public_key(operator.with_suffix('.pub').read_text().strip())
        policy=s.SupportPolicy('e46fc348-c48c-415c-a86a-1dd60ef14e1a',True,1,time.time()+60,
            'endpoint-staging.sosnadmin.local',tunnel,'eps-e46fc348c48c415ca86a1dd6',32001,'root',0,(op,))
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
        assert port!=22222
        store.write('0',(op+'\n').encode(),public=True)
        store.write('sshd_config',s.sshd_config(paths.private,paths.public,policy,port=port).encode())
        config=str(paths.private/'sshd_config')
        n.native_command(['/usr/sbin/sshd','-t','-f',config])
        actual=n.native_command(['/usr/sbin/sshd','-T','-f',config],output=True)
        for value in ('usepam no','passwordauthentication no','disableforwarding yes','allowusers root',f'port {port}'):
            assert value in actual.splitlines(),value
        evidence['checks'].append('actual_sshd_config_test')
        n.native_command(['/usr/bin/systemd-run','--quiet','--collect','--unit='+parent,
            '--property=KillMode=control-group','--property=RuntimeMaxSec=90',
            '--property=TimeoutStopSec=1','--','/usr/bin/sleep','90'])
        try:
            pidfile=root/'detached.pid'
            script="import os,time,pathlib\nif os.fork():\n time.sleep(60); os._exit(0)\nos.setsid(); pathlib.Path("+repr(str(pidfile))+").write_text(str(os.getpid())); time.sleep(60)"
            n.native_command(harness_child(child_unit,['/usr/bin/python3','-c',script],3,parent))
            limit=time.monotonic()+2
            while not pidfile.exists() and time.monotonic()<limit: time.sleep(.05)
            assert pidfile.exists()
            detached=int(pidfile.read_text())
            assert Path(f'/proc/{detached}').exists()
            limit=time.monotonic()+6
            while live(detached) and time.monotonic()<limit: time.sleep(.05)
            assert not live(detached)
            evidence['checks'].append('setsid_descendant_killed_at_cgroup_expiry')
            n.native_command(harness_child(sshd_unit,['/usr/sbin/sshd','-D','-e','-f',config],8,parent))
            known=root/'known_hosts'
            known.write_text('[127.0.0.1]:'+str(port)+' '+host+'\n')
            remote_pid=root/'ssh-detached.pid'
            remote="import os,time,pathlib; p=os.fork(); os._exit(0) if p else None; os.setsid(); pathlib.Path("+repr(str(remote_pid))+").write_text(str(os.getpid())); print('HARNESS_ROOT_OK',flush=True); time.sleep(60)"
            ssh=['/usr/bin/ssh','-F','/dev/null','-p',str(port),'-i',str(operator),'-o','BatchMode=yes',
                '-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),
                '-o','GlobalKnownHostsFile=/dev/null','-o','ConnectTimeout=2','root@127.0.0.1',
                shlex.join(['/usr/bin/python3','-c',remote])]
            # Real key-only SSH with a separately pinned generated host key.
            process=subprocess.Popen(ssh,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            out,err=process.communicate(timeout=13)
            assert b'HARNESS_ROOT_OK' in out,err.decode()
            assert remote_pid.exists()
            assert not live(int(remote_pid.read_text()))
            evidence['checks'].append('actual_root_ssh_and_setsid_session_killed_at_expiry')
            with socket.socket() as sock:
                sock.settimeout(1)
                assert sock.connect_ex(('127.0.0.1',port)) != 0
            evidence['checks'].append('expired_listener_closed')
            evidence['isolated_port']=port
        finally:
            for unit in (sshd_unit,child_unit,parent):
                subprocess.run(['/usr/bin/systemctl','stop',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
        try: n.remove_owned_state(store)
        except s.SupportError: pass
        else: raise AssertionError('Foreign sentinel was purged')
        assert store.read('host_ed25519')
        (paths.private/'sentinel').unlink()
        n.remove_owned_state(store)
        assert sorted(p.name for p in paths.private.iterdir())==['.lock']
        assert list(public.iterdir())==[]
        evidence['checks'].append('owned_cleanup_blocks_foreign_then_removes_private_keys')
    assert public.resolve()==public and public.stat().st_uid==0 and stat.S_IMODE(public.stat().st_mode)==0o755
    assert list(public.iterdir())==[]
    public.rmdir()
    evidence['checks'].append('exact_temporary_public_auth_removed')
    return evidence


def live(pid):
    try: return Path(f'/proc/{pid}/stat').read_text().split()[2] != 'Z'
    except FileNotFoundError: return False


if __name__=='__main__':
    print(json.dumps(run(Path(sys.argv[1]))))
