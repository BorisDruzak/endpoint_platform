"""Root-owned Support filesystem and native child cgroups; no global SSH edits."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import time

from pc_agent.platform.linux.support_access import (SupportError, SERVICE_NAME,
    public_key, safe_path, sshd_config, tunnel_command, forward_command, integer)


@dataclass(frozen=True)
class SupportPaths:
    private: Path = Path('/var/lib/endpoint-support-access')
    public: Path = Path('/var/lib/endpoint-support-access-public')


def boot_time():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def native_command(argv, *, timeout=8, output=False):
    """No shell and no inherited input; fixed callers never pass private bytes."""
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if output else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=timeout, check=True,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})
        if output:
            if len(result.stdout) > 65536:
                raise SupportError('native_output_bound')
            return result.stdout.decode('utf-8')
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise SupportError('native_command_failed') from None


def _admin_probe(username):
    # Validate actual noninteractive unrestricted root authorization, not groups.
    listing = native_command(['/sbin/runuser','-u',username,'--','/usr/bin/sudo','-n','-l'],output=True)
    unrestricted = re.search(r'^\s*\((?:ALL|root)(?:\s*:\s*ALL)?\)\s+NOPASSWD:\s+ALL\s*$',listing,re.M)
    return bool(unrestricted) and native_command(['/sbin/runuser','-u',username,'--',
        '/usr/bin/sudo','-n','--','/usr/bin/id','-u'],output=True).strip() == '0'


def validate_account(username, uid, *, lookup_name=None, lookup_uid=None,
                     lookup_shadow=None, admin_probe=None, day=None):
    try:
        if not isinstance(username,str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',username):
            raise ValueError
        integer(uid,0,2147483647)
        if lookup_name is None:
            import pwd
            import spwd
            lookup_name,lookup_uid,lookup_shadow = pwd.getpwnam,pwd.getpwuid,spwd.getspnam
        named,numbered = lookup_name(username),lookup_uid(uid)
        if any(item.pw_name != username or item.pw_uid != uid for item in (named,numbered)):
            raise ValueError
        if named.pw_shell not in ('/bin/bash','/bin/sh','/usr/bin/bash','/usr/bin/sh','/bin/zsh','/usr/bin/zsh'):
            raise ValueError
        shadow = lookup_shadow(username)
        day = int(time.time()/86400) if day is None else day
        if (not shadow.sp_pwdp or shadow.sp_pwdp.startswith(('!','*')) or shadow.sp_lstchg == 0
            or (shadow.sp_expire >= 0 and day >= shadow.sp_expire)
            or (shadow.sp_max >= 0 and shadow.sp_lstchg >= 0 and day >= shadow.sp_lstchg+shadow.sp_max)):
            raise ValueError
        if uid != 0 and not (admin_probe or _admin_probe)(username):
            raise ValueError
        return username,uid
    except Exception:
        raise SupportError('account_not_authorized') from None


def _directory(path, mode, *, create=False):
    safe_path(path)
    if os.name != 'posix' or os.geteuid() != 0:
        raise SupportError('native_root_required')
    # Only root can mutate a checked subtree. Root-owned sticky ancestors are
    # safe for the explicitly bounded /var/tmp native harness, never leaf stores.
    chain = list(reversed(path.parents)) + [path]
    for item in chain:
        try:
            info = item.lstat()
        except FileNotFoundError:
            if item != path or not create:
                raise SupportError('unsafe_path') from None
            item.mkdir(mode=mode)
            # Creation alone is filtered by the service's restrictive0077 umask.
            # Only our newly created leaf may have its exact intended mode set.
            item.chmod(mode)
            info = item.lstat()
        writable = info.st_mode & 0o022
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or (writable and not (item != path and info.st_mode & stat.S_ISVTX))):
            raise SupportError('unsafe_path')
    if stat.S_IMODE(path.stat().st_mode) != mode:
        raise SupportError('unsafe_path')


class PrivateStore:
    def __init__(self, paths=SupportPaths()):
        self.paths = paths

    def prepare(self):
        _directory(self.paths.private,0o700,create=True)
        _directory(self.paths.public,0o755,create=True)

    @contextmanager
    def locked(self):
        import fcntl
        _directory(self.paths.private,0o700)
        fd = os.open(self.paths.private/'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            self._check(os.fstat(fd),0o600)
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            yield self
        except (OSError,ValueError):
            raise SupportError('store_busy_or_unsafe') from None
        finally:
            os.close(fd)

    @staticmethod
    def _check(info,mode):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode or info.st_size > 65536):
            raise SupportError('unsafe_file')

    def read(self,name,*,public=False,missing=False):
        directory,mode = (self.paths.public,0o644) if public else (self.paths.private,0o600)
        if not re.fullmatch(r'[A-Za-z0-9_.-]+',name) or name in ('.','..'):
            raise SupportError('unsafe_path')
        _directory(directory,0o755 if public else 0o700)
        try:
            fd = os.open(directory/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        except FileNotFoundError:
            if missing:
                return None
            raise SupportError('missing_file') from None
        except OSError:
            raise SupportError('unsafe_file') from None
        try:
            self._check(os.fstat(fd),mode)
            raw = os.read(fd,65537)
            if len(raw)>65536:
                raise SupportError('unsafe_file')
            return raw
        finally:
            os.close(fd)

    def write(self,name,raw,*,public=False):
        if not isinstance(raw,bytes) or len(raw)>65536:
            raise SupportError('invalid_file')
        self.read(name,public=public,missing=True)
        directory,mode = (self.paths.public,0o644) if public else (self.paths.private,0o600)
        temp = directory/('.new-'+secrets.token_hex(12))
        fd = os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,mode)
        try:
            os.fchmod(fd,mode)
            with os.fdopen(fd,'wb',closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(fd)
            os.replace(temp,directory/name)
            directory_fd = os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            os.close(fd)
            temp.unlink(missing_ok=True)

    def json(self,name,*,missing=False):
        raw = self.read(name,missing=missing)
        try:
            return None if raw is None else json.loads(raw)
        except (ValueError,UnicodeError):
            raise SupportError('invalid_store') from None

    def save(self,name,value):
        self.write(name,json.dumps(value,separators=(',',':'),allow_nan=False).encode())

    def keys(self,*,create=False):
        result = []
        for name in ('host_ed25519','tunnel_ed25519'):
            raw = self.read(name,missing=True)
            if raw is None:
                if not create:
                    raise SupportError('missing_key')
                # Generate directly in our exclusively locked0700 root. Existing
                # partial material is retained; no implicit key rotation/rebind.
                if (self.paths.private/(name+'.pub')).exists():
                    raise SupportError('partial_key_state')
                native_command(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-C','',
                    '-f',str(self.paths.private/name)])
                os.chmod(self.paths.private/(name+'.pub'),0o600)
            self.read(name)
            derived = public_key(native_command(['/usr/bin/ssh-keygen','-y','-f',str(self.paths.private/name)],output=True).strip())
            retained = self.read(name+'.pub').decode().strip()
            if derived != retained:
                raise SupportError('key_mismatch')
            result.append(derived)
        if result[0] == result[1]:
            raise SupportError('key_role_conflict')
        return tuple(result)


CHILD_UNITS = ('endpoint-support-access-sshd.service','endpoint-support-access-tunnel.service')


def process_identity(pid):
    integer(pid,1,2**31-1)
    try:
        raw = Path(f'/proc/{pid}/stat').read_text()
        fields=raw[raw.rfind(')')+2:].split()
        if fields[0] in ('Z','X'):
            raise ValueError
        return pid,int(fields[19])
    except (OSError,IndexError,ValueError):
        raise SupportError('master_unavailable') from None


def control_socket_identity(private,expected_pid):
    """Kernel peer credentials bind the root-only socket to the owned master."""
    _directory(private,0o700)
    path=private/'mux'
    try:
        info=path.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or
            info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600):
            raise ValueError
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:
            stream.settimeout(1)
            stream.connect(str(path))
            pid,uid,gid=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if (pid,uid,gid)!=(expected_pid,0,0):
                raise ValueError
        after=path.lstat()
        identity=(info.st_dev,info.st_ino,info.st_ctime_ns)
        if identity!=(after.st_dev,after.st_ino,after.st_ctime_ns):
            raise ValueError
        return identity
    except (OSError,ValueError):
        raise SupportError('unsafe_control_socket') from None


def child_command(unit, argv, seconds):
    if unit not in CHILD_UNITS or not argv or not str(argv[0]).startswith('/'):
        raise SupportError('invalid_child_unit')
    integer(seconds,1,8*3600)
    return ['/usr/bin/systemd-run','--quiet','--collect','--unit='+unit,
        '--property=Type=exec','--property=KillMode=control-group',
        '--property=KillSignal=SIGKILL','--property=SendSIGKILL=yes',
        '--property=TimeoutStartSec=3','--property=TimeoutStopSec=1',
        '--property=RuntimeMaxSec='+str(seconds),'--property=BindsTo='+SERVICE_NAME,
        '--property=PartOf='+SERVICE_NAME,'--property=After='+SERVICE_NAME,
        '--property=Restart=no','--property=StandardOutput=null','--property=StandardError=null',
        '--',*argv]


class NativeChildren:
    def __init__(self,store):
        self.store = store
        self.active = False
        self.forward_receipt = None
        self.policy_revision = None

    def stop(self):
        self.forward_receipt = None
        self.policy_revision = None
        # Kill immediately instead of waiting on systemctl stop jobs/network.
        for unit in CHILD_UNITS:
            subprocess.run(['/usr/bin/systemctl','kill','--kill-whom=all','--signal=KILL',unit],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
        # Unknown/not-loaded owned units are already stopped. Do not broaden the
        # selector or accidentally operate the machine's global sshd service.
        subprocess.run(['/usr/bin/systemctl','stop',*CHILD_UNITS],stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
        for unit in CHILD_UNITS:
            result = subprocess.run(['/usr/bin/systemctl','show','--property=ActiveState','--value',unit],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3)
            if result.returncode != 0 or result.stdout.strip() not in (b'inactive',b'failed'):
                raise SupportError('child_stop_unconfirmed')
        self.active = False
        _directory(self.store.paths.private,0o700)
        control=self.store.paths.private/'mux'
        try:
            info=control.lstat()
        except FileNotFoundError:
            return
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or
            info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600):
            raise SupportError('unsafe_control_socket')
        control.unlink()  # Exact owned stale socket, only after both units stopped.

    def prepare(self,policy):
        """Validate local account/configuration without opening any listener/tunnel."""
        self.store.keys()  # Revalidate owned key files and public/private binding.
        validate_account(policy.username,policy.uid)
        self.store.write(str(policy.uid),('\n'.join(policy.operator_keys)+'\n').encode(),public=True)
        self.store.write('known_hosts',('endpoint-support-gateway '+policy.gateway_key+'\n').encode())
        self.store.write('sshd_config',sshd_config(self.store.paths.private,self.store.paths.public,policy).encode())
        config = str(self.store.paths.private/'sshd_config')
        native_command(['/usr/sbin/sshd','-t','-f',config])
        return config

    def start(self,policy,deadline):
        self.forward_receipt = None
        self.policy_revision = policy.revision
        config = self.prepare(policy)
        # Hard cgroup bound survives dead/hung parent and detached ssh sessions.
        # Reserve activation budget so delayed starts cannot extend the lease.
        seconds = int(deadline-boot_time())-6
        if seconds < 1:
            raise SupportError('expired_policy')
        try:
            native_command(child_command(CHILD_UNITS[0],['/usr/sbin/sshd','-D','-e','-f',config],seconds))
            seconds = int(deadline-boot_time())-3
            native_command(child_command(CHILD_UNITS[1],tunnel_command(self.store.paths.private,policy),seconds))
            self.acknowledge_forward(policy,deadline)
            self.active = True
        except Exception:
            self.stop()
            raise SupportError('child_start_failed') from None

    def alive(self):
        try:
            return native_command(['/usr/bin/systemctl','is-active',*CHILD_UNITS],output=True).splitlines() == ['active','active']
        except SupportError:
            return False

    def master_identity(self):
        value=native_command(['/usr/bin/systemctl','show','--property=MainPID','--value',CHILD_UNITS[1]],output=True,timeout=3)
        try:
            return process_identity(int(value.strip()))
        except (ValueError,SupportError):
            raise SupportError('master_unavailable') from None

    def acknowledge_forward(self,policy,deadline):
        """OpenSSH mux waits for remote tcpip-forward success before exit0."""
        self.forward_receipt=None
        self.policy_revision=policy.revision
        limit=min(boot_time()+8,deadline-1)
        identity=None
        while boot_time()<limit:
            try:
                master=self.master_identity()
                identity=control_socket_identity(self.store.paths.private,master[0])
                break
            except SupportError:
                time.sleep(.05)
        if identity is None:
            raise SupportError('master_unavailable')
        remaining=min(3,limit-boot_time())
        if remaining<=0:
            raise SupportError('expired_policy')
        native_command(forward_command(self.store.paths.private,policy),timeout=remaining)
        if (master!=self.master_identity() or
            identity!=control_socket_identity(self.store.paths.private,master[0])):
            raise SupportError('master_changed')
        self.forward_receipt=(master,identity,policy.revision)

    def connected(self):
        if self.forward_receipt is None:
            return False
        try:
            master,identity,revision=self.forward_receipt
            if (revision!=self.policy_revision or not self.alive() or master!=self.master_identity()
                or identity!=control_socket_identity(self.store.paths.private,master[0])):
                raise SupportError('master_changed')
            return True
        except Exception:
            self.forward_receipt=None
            return False


def support_unit(executable):
    executable = safe_path(executable)
    return ('[Unit]\nDescription=Independent Endpoint Linux Support\nAfter=network.target\n'
        '[Service]\nType=simple\nUser=root\nGroup=root\nUMask=0077\n'
        f'ExecStart={executable} run\nRestart=on-failure\nRestartSec=5\n'
        'KillMode=control-group\nTimeoutStopSec=10\nSendSIGKILL=yes\n'
        '[Install]\nWantedBy=multi-user.target\n')


def remove_owned_state(store):
    """Caller holds native/Support locks and proved parent/children stopped.

    Validate the entire removal set before unlinking any node. Do not recursively
    delete; foreign/symlink/hardlink state blocks cleanup and preserves evidence.
    Empty0700/0755 roots and the lock inode remain safe for later installation.
    """
    private = {'config.json','ca.crt','host_ed25519','host_ed25519.pub','tunnel_ed25519',
        'tunnel_ed25519.pub','known_hosts','sshd_config','lease.json','.lock'}
    nodes = []
    for directory,public in ((store.paths.private,False),(store.paths.public,True)):
        _directory(directory,0o755 if public else 0o700)
        for path in directory.iterdir():
            if (public and not re.fullmatch(r'(?:0|[1-9][0-9]{0,9})',path.name)) or (not public and path.name not in private):
                raise SupportError('foreign_support_state')
            store.read(path.name,public=public)
            if path.name != '.lock':
                nodes.append(path)
    for path in nodes:
        path.unlink()
