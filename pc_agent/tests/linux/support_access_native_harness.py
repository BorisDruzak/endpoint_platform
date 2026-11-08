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
import threading
import time
from dataclasses import replace

from pc_agent.platform.linux import support_access as s
from pc_agent.platform.linux import support_access_native as n


def harness_child(unit,argv,seconds,parent):
    """Only rename owned units for the harness; lifetime properties are real."""
    assert re.fullmatch(r'endpoint-linux178-harness-[a-f0-9]+\.service',parent)
    assert unit in [parent.replace('.service','-'+role+'.service') for role in ('sshd','descendant','tunnel')]
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
        verify_forward_ack(root,store,policy,parent,evidence)
        verify_delayed_gateway_authorization(root,store,policy,parent,evidence)
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


def verify_forward_ack(root,store,policy,parent,evidence):
    """Native mux acceptance/rejection against ONLY an ephemeral local gateway.

    Test adapters change production destination/UID/ports to isolated loopback
    values; the actual native ack, kernel socket peer and receipt logic run intact.
    """
    gateway_unit=parent.replace('.service','-sshd.service')
    master_unit=parent.replace('.service','-tunnel.service')
    gateway_key=root/'gateway_ed25519'
    n.native_command(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-C','','-f',str(gateway_key)])
    key=s.public_key(gateway_key.with_suffix('.pub').read_text().strip())
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0));gateway_port=probe.getsockname()[1]
    # Bound remote listener to a distinct unoccupied port; no actual Endpoint
    # listener or gateway is accessed by this harness.
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0));remote_port=probe.getsockname()[1]
    with socket.socket() as target:
        target.bind(('127.0.0.1',0));target.listen(1);target_port=target.getsockname()[1]
        assert 22222 not in (gateway_port,remote_port,target_port)
        tunnel_pub=store.read('tunnel_ed25519.pub').decode().strip()
        store.write('0',(tunnel_pub+'\n').encode(),public=True)
        gateway_config=s.sshd_config(store.paths.private,store.paths.public,policy,port=gateway_port)
        gateway_config=gateway_config.replace('HostKey '+str(store.paths.private/'host_ed25519'),
            'HostKey '+str(gateway_key)).replace('DisableForwarding yes',
            'DisableForwarding no\nAllowTcpForwarding remote\nPermitListen 127.0.0.1:'+str(remote_port))
        config=root/'gateway_sshd_config';config.write_text(gateway_config)
        n.native_command(['/usr/sbin/sshd','-t','-f',str(config)])
        policy=replace(policy,gateway='127.0.0.1',gateway_key=key,tunnel_user='root',remote_port=remote_port)
        store.write('known_hosts',('endpoint-support-gateway '+key+'\n').encode())
        master_command=s.tunnel_command(store.paths.private,policy)
        master_command[master_command.index('-p')+1]=str(gateway_port)
        n.native_command(['/usr/bin/systemd-run','--quiet','--collect','--unit='+parent,
            '--property=KillMode=control-group','--property=RuntimeMaxSec=45',
            '--property=TimeoutStopSec=1','--','/usr/bin/sleep','45'])
        original_forward=n.forward_command
        def isolated_forward(private,p):
            argv=original_forward(private,p)
            index=argv.index('-R')+1
            argv[index]=f'127.0.0.1:{p.remote_port}:127.0.0.1:{target_port}'
            return argv
        class HarnessChildren(n.NativeChildren):
            def master_identity(self):
                return n.process_identity(int(n.native_command(['/usr/bin/systemctl','show',
                    '--property=MainPID','--value',master_unit],output=True).strip()))
            def alive(self):
                try:return n.native_command(['/usr/bin/systemctl','is-active',gateway_unit,master_unit],output=True).splitlines()==['active','active']
                except s.SupportError:return False
        child=HarnessChildren(store)
        n.forward_command=isolated_forward
        try:
            n.native_command(harness_child(gateway_unit,['/usr/sbin/sshd','-D','-e','-f',str(config)],35,parent))
            n.native_command(harness_child(master_unit,master_command,30,parent))
            assert not child.connected()
            child.acknowledge_forward(policy,n.boot_time()+20)
            assert child.connected()
            # A successful native -O forward really allocated the remote port
            # and forwards bytes to our own isolated target, not just exit0.
            with socket.create_connection(('127.0.0.1',remote_port),timeout=2) as forwarded:
                forwarded.sendall(b'OWNED_FORWARD_ACK')
                target.settimeout(2)
                connection,_=target.accept()
                with connection:
                    connection.settimeout(2)
                    assert connection.recv(100)==b'OWNED_FORWARD_ACK'
            evidence['checks'].append('native_mux_ack_and_actual_forwarded_bytes')
            # The same live SSH master cannot assert an explicitly denied port.
            denied=remote_port+1 if remote_port<65535 else remote_port-1
            try:child.acknowledge_forward(replace(policy,remote_port=denied),n.boot_time()+10)
            except s.SupportError:pass
            else:raise AssertionError('Denied remote forwarding acknowledged')
            assert child.forward_receipt is None and not child.connected()
            evidence['checks'].append('native_mux_rejection_clears_readiness')
            child.acknowledge_forward(policy,n.boot_time()+10)
            assert child.connected()
            subprocess.run(['/usr/bin/systemctl','stop',master_unit],check=True,timeout=5)
            assert not child.connected() and child.forward_receipt is None
            evidence['checks'].append('master_death_clears_forward_receipt')
            # -O never falls back to a direct network login when socket is gone.
            try:n.native_command(isolated_forward(store.paths.private,policy),timeout=2)
            except s.SupportError:pass
            else:raise AssertionError('Missing master accepted forward')
            evidence['checks'].append('missing_mux_has_no_direct_fallback')
            evidence['forward_ports']={'gateway':gateway_port,'remote':remote_port,'target':target_port}
        finally:
            n.forward_command=original_forward
            for unit in (master_unit,gateway_unit,parent):
                subprocess.run(['/usr/bin/systemctl','stop',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            control=store.paths.private/'mux'
            if control.exists():
                info=control.lstat()
                assert stat.S_ISSOCK(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600
                control.unlink()
        evidence['units'].append(master_unit)


def verify_delayed_gateway_authorization(root,store,policy,parent,evidence):
    """Run the real start/retry/cleanup/ACK path against an isolated late key."""
    sshd_unit=parent.replace('.service','-sshd.service')
    tunnel_unit=parent.replace('.service','-tunnel.service')
    gateway_unit=parent.replace('.service','-descendant.service')
    gateway_key=root/'gateway_ed25519'
    key=s.public_key(gateway_key.with_suffix('.pub').read_text().strip())
    ports=[]
    # Reserve all ports together so gateway/sshd/forward/target cannot collide.
    probes=[socket.socket() for _ in range(4)]
    try:
        for probe in probes:
            probe.bind(('127.0.0.1',0));ports.append(probe.getsockname()[1])
    finally:
        for probe in probes:probe.close()
    gateway_port,sshd_port,remote_port,target_port=ports
    assert 22222 not in ports
    policy=replace(policy,gateway='127.0.0.1',gateway_key=key,tunnel_user='root',remote_port=remote_port)
    auth_name='gateway-authorized'
    store.write(auth_name,b'',public=True)
    store.write('known_hosts',('endpoint-support-gateway '+key+'\n').encode())
    gateway_config=s.sshd_config(store.paths.private,store.paths.public,policy,port=gateway_port)
    gateway_config=gateway_config.replace('HostKey '+str(store.paths.private/'host_ed25519'),
        'HostKey '+str(gateway_key)).replace('AuthorizedKeysFile '+str(store.paths.public)+'/%U',
        'AuthorizedKeysFile '+str(store.paths.public/auth_name)).replace('DisableForwarding yes',
        'DisableForwarding no\nAllowTcpForwarding remote\nPermitListen 127.0.0.1:'+str(remote_port))
    config=root/'gateway_delayed_sshd_config';config.write_text(gateway_config)
    n.native_command(['/usr/sbin/sshd','-t','-f',str(config)])
    originals=(n.CHILD_UNITS,n.SERVICE_NAME,n.sshd_config,n.tunnel_command,n.forward_command,n.native_command)
    original_sshd,original_tunnel,original_forward,original_native=originals[2:]
    started=threading.Event();cancelled=threading.Event()
    authorized=[];launches=[];writer_errors=[]
    def late_key():
        try:
            if started.wait(10) and not cancelled.wait(6):
                store.write(auth_name,store.read('tunnel_ed25519.pub')+b'\n',public=True)
                authorized.append(n.boot_time())
        except Exception as exc:writer_errors.append(type(exc).__name__)
    def isolated_tunnel(private,p):
        argv=original_tunnel(private,p)
        argv[argv.index('-p')+1]=str(gateway_port)
        return argv
    def isolated_forward(private,p):
        argv=original_forward(private,p)
        argv[argv.index('-R')+1]=f'127.0.0.1:{p.remote_port}:127.0.0.1:{target_port}'
        return argv
    def record_launch(argv,**kwargs):
        if '--unit='+tunnel_unit in argv:
            lifetime=int(next(arg.split('=',2)[2] for arg in argv if arg.startswith('--property=RuntimeMaxSec=')))
            launches.append((n.boot_time(),lifetime))
            started.set()
        return original_native(argv,**kwargs)
    child=None;writer=None
    try:
        original_native(['/usr/bin/systemd-run','--quiet','--collect','--unit='+parent,
            '--property=KillMode=control-group','--property=RuntimeMaxSec=45',
            '--property=TimeoutStopSec=1','--','/usr/bin/sleep','45'])
        original_native(harness_child(gateway_unit,['/usr/sbin/sshd','-D','-e','-f',str(config)],40,parent))
        ready_limit=time.monotonic()+2
        while True:
            with socket.socket() as probe:
                probe.settimeout(.2)
                if probe.connect_ex(('127.0.0.1',gateway_port))==0:break
            assert time.monotonic()<ready_limit,'Isolated gateway listener did not start'
            time.sleep(.05)
        # The same pinned master command really fails publickey before keyready.
        rejected=subprocess.run(isolated_tunnel(store.paths.private,policy),stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
        assert rejected.returncode==255 and b'Permission denied (publickey)' in rejected.stderr
        assert not (store.paths.private/'mux').exists()
        n.CHILD_UNITS=(sshd_unit,tunnel_unit)
        n.SERVICE_NAME=parent
        n.sshd_config=lambda private,public,p:original_sshd(private,public,p,port=sshd_port)
        n.tunnel_command=isolated_tunnel
        n.forward_command=isolated_forward
        n.native_command=record_launch
        child=n.NativeChildren(store)
        writer=threading.Thread(target=late_key,daemon=True)
        with socket.socket() as target:
            target.bind(('127.0.0.1',target_port));target.listen(1)
            writer.start()
            deadline=n.boot_time()+30
            child.start(policy,deadline)
            writer.join(timeout=1)
            assert not writer.is_alive() and not writer_errors and authorized
            assert len(launches)>1 and launches[0][0]<authorized[0]<=launches[-1][0]
            assert all(when+lifetime<=deadline-3 for when,lifetime in launches)
            assert launches[-1][1]<launches[0][1]
            assert child.active and child.connected()
            with socket.create_connection(('127.0.0.1',remote_port),timeout=2) as forwarded:
                forwarded.sendall(b'LATE_GATEWAY_AUTH_ACK')
                target.settimeout(2)
                connection,_=target.accept()
                with connection:
                    connection.settimeout(2)
                    assert connection.recv(100)==b'LATE_GATEWAY_AUTH_ACK'
            evidence['checks'].append('native_start_retries_late_gateway_key_and_forwards_bytes')
            evidence['delayed_gateway_authorization']={'delay_seconds':6,'attempts':len(launches),
                'first_rejected_exit':rejected.returncode,'activation_seconds':n.boot_time()-(deadline-30),
                'original_deadline':deadline,'launch_lifetimes':launches}
    finally:
        cancelled.set();started.set()
        if writer is not None and writer.ident is not None:writer.join(timeout=2)
        try:
            if child is not None:child.stop()
        finally:
            n.CHILD_UNITS,n.SERVICE_NAME,n.sshd_config,n.tunnel_command,n.forward_command,n.native_command=originals
            for unit in (tunnel_unit,sshd_unit,gateway_unit,parent):
                subprocess.run(['/usr/bin/systemctl','stop',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            (store.paths.public/auth_name).unlink()


def live(pid):
    try: return Path(f'/proc/{pid}/stat').read_text().split()[2] != 'Z'
    except FileNotFoundError: return False


if __name__=='__main__':
    print(json.dumps(run(Path(sys.argv[1]))))
