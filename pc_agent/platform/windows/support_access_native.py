"""Native Windows boundary for the independent Support component.

Installer PowerShell is a fixed Microsoft capability/signature query only.
The service never invokes PowerShell, Core, observer, updater, or command source.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
from ctypes import wintypes
from threading import Event,Thread

from .support_bootstrap import (
    TRUSTED_SIDS, BOOTSTRAP_SERVICE_SIDS, reject_links, assert_bootstrap_file,
)


def atomic_write(path: Path, text: str):
    reject_links(path)
    temporary = path.with_suffix(path.suffix+'.new')
    reject_links(temporary)
    with temporary.open('w', encoding='utf-8', newline='\n') as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary,path)


def native_folder(identifier: int) -> Path:
    buffer = ctypes.create_unicode_buffer(260)
    if ctypes.windll.shell32.SHGetFolderPathW(None,identifier,None,0,buffer):
        raise OSError('support_native_folder_unavailable')
    return Path(buffer.value)


def production_roots():
    return (native_folder(0x23)/'Endpoint Platform'/'Support',
            native_folder(0x26)/'Endpoint Platform'/'Support')


def windows_root() -> Path:
    buffer = ctypes.create_unicode_buffer(260)
    if not ctypes.windll.kernel32.GetWindowsDirectoryW(buffer,260):
        raise OSError('support_windows_root_unavailable')
    return Path(buffer.value)


def assert_private(path: Path):
    reject_links(path)
    if os.name != 'nt':
        if path.stat().st_mode & 0o077:
            raise ValueError('unsafe_support_acl')
        return
    import win32security as security
    assert_namespace(path)
    descriptor = security.GetNamedSecurityInfo(str(path),security.SE_FILE_OBJECT,
        security.OWNER_SECURITY_INFORMATION|security.DACL_SECURITY_INFORMATION)
    owner = security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
    dacl = descriptor.GetSecurityDescriptorDacl()
    if owner != 'S-1-5-18' or dacl is None or not descriptor.GetSecurityDescriptorControl()[0]&security.SE_DACL_PROTECTED:
        raise ValueError('unsafe_support_acl')
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        if ace[0][0] != security.ACCESS_ALLOWED_ACE_TYPE or security.ConvertSidToStringSid(ace[2]) not in TRUSTED_SIDS:
            raise ValueError('unsafe_support_acl')


def assert_namespace(path: Path):
    """A leaf ACL cannot defend against parent DELETE_CHILD or ACL authority."""
    reject_links(path)
    import win32security as security
    trusted = TRUSTED_SIDS|{'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'}
    for parent in path.parents:
        if not parent.exists():
            continue
        descriptor = security.GetNamedSecurityInfo(str(parent),security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION|security.DACL_SECURITY_INFORMATION)
        owner = descriptor.GetSecurityDescriptorOwner()
        acl = descriptor.GetSecurityDescriptorDacl()
        if owner is None or security.ConvertSidToStringSid(owner) not in trusted or acl is None:
            raise ValueError('unsafe_support_namespace')
        for index in range(acl.GetAceCount()):
            ace = acl.GetAce(index)
            if len(ace)!=3 or ace[0][0]!=security.ACCESS_ALLOWED_ACE_TYPE:
                raise ValueError('unsafe_support_namespace')
            if ace[0][1]&security.INHERIT_ONLY_ACE:
                continue
            if security.ConvertSidToStringSid(ace[2]) not in trusted and ace[1]&0x500D0040:
                raise ValueError('unsafe_support_namespace')


def administrators_name():
    import win32security
    return win32security.LookupAccountSid(None,win32security.ConvertStringSidToSid('S-1-5-32-544'))[0]


def validate_windows_admin(username: str):
    import win32api
    import win32net
    import win32netcon
    import win32security as security
    from .support_access import windows_ssh_principal
    try:
        windows_ssh_principal(username) # Reject ambiguous/pattern/config syntax.
        computer=win32api.GetComputerName()
        supplied_domain,sam=(username.split('\\') if '\\' in username else (computer,username))
        # Bare names are explicitly local: never inherit Windows' search order.
        sid,domain,kind=security.LookupAccountName(None,supplied_domain+'\\'+sam)
        name,reverse_domain,reverse_kind=security.LookupAccountSid(None,sid)
        if (kind!=security.SidTypeUser or reverse_kind!=security.SidTypeUser
                or domain.casefold()!=supplied_domain.casefold()
                or reverse_domain.casefold()!=domain.casefold() or name.casefold()!=sam.casefold()):
            raise ValueError()
        local=domain.casefold()==computer.casefold()
        server=None if local else win32net.NetGetDCName(None,domain)
        if not local and (not isinstance(server,str) or not server.startswith('\\\\')):
            raise ValueError()
        # USER_INFO_4 binds enabled flags and the resolved SID in one response.
        info=win32net.NetUserGetInfo(server,name,4)
        if (info['name'].casefold()!=name.casefold()
                or security.ConvertSidToStringSid(info['user_sid'])!=security.ConvertSidToStringSid(sid)
                or info['flags']&win32netcon.UF_ACCOUNTDISABLE
                or not info['flags']&win32netcon.UF_NORMAL_ACCOUNT):
            raise ValueError()
        qualified=domain+'\\'+name
        groups=win32net.NetUserGetLocalGroups(None,qualified,win32netcon.LG_INCLUDE_INDIRECT)
        if administrators_name().casefold() not in {g.casefold() for g in groups}:
            raise ValueError()
        return windows_ssh_principal(name if local else qualified)
    except Exception:
        # Unavailable DCs, unknown/disabled users and non-user SIDs all fail closed.
        raise ValueError('support_existing_admin_required') from None


def verify_dependencies(dependencies: dict):
    if dependencies.get('profile') == 'windows-openssh-fod-v1':
        from .support_access_os import verify_os_snapshot
        verify_os_snapshot(dependencies)
        return
    if 'profile' in dependencies:
        from .support_access_bundle import verify_profile
        verify_profile(dependencies)
        return
    root = windows_root()/'System32'/'OpenSSH'
    for role, filename in [('ssh','ssh.exe'),('sshd','sshd.exe'),('keygen','ssh-keygen.exe')]:
        path = Path(dependencies.get(role,''))
        if path != root/filename or not path.is_file():
            raise ValueError('support_dependency_changed')
        if hashlib.sha256(path.read_bytes()).hexdigest() != dependencies.get('hashes',{}).get(role):
            raise ValueError('support_dependency_changed')


def validate_service_config(config, executable: Path):
    expected = '"'+str(executable).replace('/','\\')+'"'
    binary = config[3].replace('/','\\')
    if config[0] != 16 or binary.casefold() != expected.casefold() or config[7].casefold() not in {'localsystem','nt authority\\system'}:
        raise ValueError('support_service_conflict')


def _current_elevated_creator(owner_sid: str) -> bool:
    """Authorize only this elevated installer token's own newly written leaf.

    OpenSSH keygen/atomic writes use TokenUser ownership even inside the private
    SYSTEM-owned namespace. This is installation normalization, never a relaxed
    runtime file-security policy or acceptance of another user's existing file.
    """
    import win32api
    import win32security as security
    token=security.OpenProcessToken(win32api.GetCurrentProcess(),security.TOKEN_QUERY)
    try:
        caller=security.ConvertSidToStringSid(security.GetTokenInformation(token,security.TokenUser)[0])
        return (owner_sid==caller and bool(security.GetTokenInformation(token,security.TokenElevation))
                and security.CheckTokenMembership(None,security.ConvertStringSidToSid('S-1-5-32-544')))
    finally:
        token.Close()


class PayloadActivation:
    """Prepare authenticated bytes before stopping; compensate only image and SCM."""
    def __init__(self,ops,source,target):
        self.ops,self.source,self.target=ops,source,target
        self.pending=target.with_suffix('.pending.exe')
        self.previous=target.with_suffix('.previous.exe')
        self.applied=False
        self.stopped=False
        self.compensated=False
        self.backup_created=False
        self.configuration=None
        self.configuration_compensation=True

    def snapshot_configuration(self,path):
        self.config_path=Path(path)
        if self.config_path.exists():
            self.ops.private(self.config_path)
            self.configuration=self.config_path.read_bytes()
            credential=self.config_path.parent/'credential'
            self.authority=hashlib.sha256(credential.read_bytes()).hexdigest() if credential.exists() else None

    def invalidate_configuration_compensation(self):
        # An authenticated central reset/new key generation cannot be undone.
        self.configuration_compensation=False

    def _restore_configuration(self):
        if self.configuration is None:
            return
        credential=self.config_path.parent/'credential'
        current=hashlib.sha256(credential.read_bytes()).hexdigest() if credential.exists() else None
        if current!=self.authority and self.configuration_compensation:
            raise RuntimeError('support_payload_recovery_required')
        self.ops.private(self.config_path)
        old=json.loads(self.configuration)
        new=json.loads(self.config_path.read_bytes())
        if any(old.get(k)!=new.get(k) for k in ('device_id','origin')):
            raise RuntimeError('support_payload_recovery_required')
        if not self.configuration_compensation:
            # Authorized reset keeps every NEW key, token and credential binding.
            # Only restore the old image's compatible dependency selection.
            if 'dependencies' not in old:return
            new['dependencies']=old['dependencies']
            restored=json.dumps(new)
        else:
            if old.get('credential_id')!=new.get('credential_id'):
                raise RuntimeError('support_payload_recovery_required')
            restored=self.configuration.decode('utf-8')
        atomic_write(self.config_path,restored)
        self.ops.protect(self.config_path)

    def require_initialized_readiness(self):
        self.ops.prepare_readiness(self.target,self.candidate,self.config_path)

    def __enter__(self):
        import shutil
        self.lock=self.ops.activation_lock();self.lock.__enter__()
        try:
            self.state=self.ops.capture_service(self.target)
            self.old=None
            if self.target.exists():
                self.ops.private(self.target)
                self.old=self.ops.inspect_payload(self.target)
            if self.previous.exists():
                self.ops.private(self.previous)
                raise RuntimeError('support_payload_recovery_required')
            for path in (self.pending,):
                if path.exists():
                    self.ops.private(path);self.ops.inspect_payload(path);path.unlink()
            # Sharing excludes concurrent writers/deletion while copying the source.
            import win32file,win32con
            handle=win32file.CreateFile(str(self.source),win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ,None,win32con.OPEN_EXISTING,
                0x00200000,None)
            try:
                reject_links(self.source)
                with self.pending.open('xb') as output:
                    while True:
                        _,chunk=win32file.ReadFile(handle,1024*1024)
                        if not chunk:break
                        output.write(chunk)
                    output.flush();os.fsync(output.fileno())
            finally:handle.Close()
            self.ops.protect(self.pending)
            self.candidate=self.ops.inspect_payload(self.pending)
            if self.old:
                shutil.copyfile(self.target,self.previous);self.ops.protect(self.previous)
                self.backup_created=True
                if self.ops.inspect_payload(self.previous)['sha256']!=self.old['sha256']:
                    raise ValueError('support_payload_changed')
            self.changed=bool(not self.old or self.old['sha256']!=self.candidate['sha256'])
            return self
        except BaseException:
            self.__exit__(None,None,None);raise

    def apply(self,*,reload):
        if not self.changed and not reload:return
        self.stop()
        moved=False
        try:
            if self.changed:
                os.replace(self.pending,self.target);moved=True
            self.ops.install_service(self.target)
            self.ops.prove_service_ready(self.target)
            self.applied=True
            if self.previous.exists():self.previous.unlink()
        except BaseException:
            try:self.ops.stop_for_update(self.target)
            except BaseException:
                # Keep the authenticated rollback image if exact process exit
                # cannot be proved. Never overwrite a possibly mapped image.
                self.compensated=True
                raise
            try:self._restore_configuration()
            except BaseException:
                # Preserve both signed images and unknown authority ownership.
                self.compensated=True
                raise
            if moved:
                if self.old:os.replace(self.previous,self.target)
                elif self.target.exists():self.target.unlink()
            elif self.previous.exists():os.replace(self.previous,self.target)
            self.ops.restore_service(self.target,self.state)
            self.compensated=True
            raise

    def stop(self):
        self.ops.stop_for_update(self.target)
        self.stopped=True

    def __exit__(self,*exc):
        if self.pending.exists():self.pending.unlink()
        try:
            if exc[0] is not None and not self.compensated:
                self._restore_configuration()
            if exc[0] is not None and self.stopped and not self.compensated:
                self.ops.restore_service(self.target,self.state)
            if self.backup_created and not self.applied and self.previous.exists() and not self.compensated:
                self.previous.unlink()
        finally:self.lock.__exit__(*exc)


class WindowsSupportOps:
    def private(self, path):
        assert_private(path)

    def activation_lock(self):
        from contextlib import contextmanager
        @contextmanager
        def locked():
            import win32event, win32api, win32security, pywintypes
            attributes=pywintypes.SECURITY_ATTRIBUTES()
            attributes.SECURITY_DESCRIPTOR=win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                'D:P(A;;GA;;;SY)(A;;GA;;;BA)',1)
            handle=win32event.CreateMutex(attributes,False,'Global\\EndpointPlatform.SupportAccess.Install')
            acquired=False
            try:
                result=win32event.WaitForSingleObject(handle,30000)
                if result not in (0,128):raise RuntimeError('support_install_busy')
                acquired=True
                yield
            finally:
                if acquired:win32event.ReleaseMutex(handle)
                win32api.CloseHandle(handle)
        return locked()

    def inspect_payload(self,path):
        reject_links(path)
        script=r'''
$ErrorActionPreference='Stop'
$p=$env:ENDPOINT_SUPPORT_VERIFY_FILE
$s=Get-AuthenticodeSignature -LiteralPath $p
if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne '4D4C23389F5FF77BC4EB32044761019EAE8FB776' -or !$s.TimeStamperCertificate){throw 'support_signature_invalid'}
$v=(Get-Item -LiteralPath $p).VersionInfo
@{version=@($v.FileMajorPart,$v.FileMinorPart,$v.FileBuildPart,$v.FilePrivatePart);sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}|ConvertTo-Json -Compress
'''
        environment=dict(os.environ,ENDPOINT_SUPPORT_VERIFY_FILE=str(path),
            PSModulePath=str(windows_root()/'System32/WindowsPowerShell/v1.0/Modules'))
        result=subprocess.run([str(windows_root()/'System32/WindowsPowerShell/v1.0/powershell.exe'),
            '-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16-le')).decode()],
            env=environment,capture_output=True,text=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:raise ValueError('support_signature_invalid')
        record=json.loads(result.stdout.strip().splitlines()[-1]);record['version']=tuple(record['version'])
        return record

    def prepare_payload(self,source,target):
        return PayloadActivation(self,Path(source),Path(target))

    def capture_service(self,target):
        import win32service,win32serviceutil
        from .support_access import SERVICE_NAME
        if not self.assert_owned_service(target):return None
        manager=win32service.OpenSCManager(None,None,win32service.SC_MANAGER_CONNECT)
        service=win32service.OpenService(manager,SERVICE_NAME,win32service.SERVICE_QUERY_CONFIG)
        try:return {'config':win32service.QueryServiceConfig(service),
            'running':win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1]==win32service.SERVICE_RUNNING}
        finally:win32service.CloseServiceHandle(service);win32service.CloseServiceHandle(manager)

    def prepare_readiness(self,target,candidate,config_path):
        from uuid import uuid4
        assert_private(config_path)
        self._ready_root=config_path.parent
        self._ready_request={'nonce':uuid4().hex,'image_sha256':candidate['sha256']}
        path=self._ready_root/'readiness-request.json'
        atomic_write(path,json.dumps(self._ready_request,sort_keys=True));self.protect(path)

    def prove_service_ready(self,target):
        import win32service,win32serviceutil,win32process
        from .support_access import SERVICE_NAME
        if not self.assert_owned_service(target):raise RuntimeError('support_service_not_ready')
        win32serviceutil.WaitForServiceStatus(SERVICE_NAME,win32service.SERVICE_RUNNING,30)
        with OwnedImageProcesses(target) as processes:
            if not processes.handles:raise RuntimeError('support_service_not_ready')
            request=getattr(self,'_ready_request',None)
            deadline=time.monotonic()+(90 if request is not None else 3)
            while True:
                if (win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1]!=win32service.SERVICE_RUNNING
                    or any(win32process.GetExitCodeProcess(handle)!=259 for handle in processes.handles)):
                    raise RuntimeError('support_service_not_ready')
                if request is not None:
                    from .support_access_readiness import matches,dependency_digest
                    root=self._ready_root
                    try:
                        for name in ('readiness.json','support.json','credential'):assert_private(root/name)
                        if (root/'readiness.json').stat().st_size>2048:raise ValueError()
                        record=json.loads((root/'readiness.json').read_bytes())
                        config=json.loads((root/'support.json').read_bytes())
                        verify_dependencies(config['dependencies'])
                        pids={win32process.GetProcessId(handle) for handle in processes.handles}
                        if matches(record,request,device_id=config['device_id'],
                            credential_sha256=hashlib.sha256((root/'credential').read_bytes()).hexdigest(),
                            dependency_sha256=dependency_digest(config['dependencies']),active_pids=pids):return
                    except (OSError,ValueError,KeyError,TypeError):pass
                elif time.monotonic()>=deadline:return
                if time.monotonic()>=deadline:raise RuntimeError('support_service_not_ready')
                time.sleep(.25)

    def restore_service(self,target,state):
        import win32service,win32serviceutil
        from .support_access import SERVICE_NAME
        if state is None:
            self.remove_service();return
        self.install_service(target)
        manager=win32service.OpenSCManager(None,None,win32service.SC_MANAGER_CONNECT)
        service=win32service.OpenService(manager,SERVICE_NAME,win32service.SERVICE_CHANGE_CONFIG)
        try:
            config=state['config']
            win32service.ChangeServiceConfig(service,config[0],config[1],config[2],config[3],
                config[4],0,config[6],config[7],None,config[8])
        finally:win32service.CloseServiceHandle(service);win32service.CloseServiceHandle(manager)
        if not state['running']:self.stop_for_update(target)

    def rotate_keys(self, root: Path):
        assert_private(root)
        for name in ('tunnel_ed25519','tunnel_ed25519.pub','host_ed25519','host_ed25519.pub'):
            path=root/name
            if path.exists():
                assert_private(path)
                path.unlink()

    def assert_owned_service(self, executable: Path) -> bool:
        import win32service
        from .support_access import SERVICE_NAME
        manager=win32service.OpenSCManager(None,None,win32service.SC_MANAGER_CONNECT)
        service=None
        try:
            try:
                service=win32service.OpenService(manager,SERVICE_NAME,win32service.SERVICE_QUERY_CONFIG)
            except Exception as error:
                if getattr(error,'winerror',None)==1060:
                    return False
                raise
            validate_service_config(win32service.QueryServiceConfig(service),executable)
            return True
        finally:
            if service is not None: win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(manager)

    def stop_for_update(self, executable: Path):
        import win32service
        import win32serviceutil
        from .support_access import SERVICE_NAME
        if not self.assert_owned_service(executable):
            return
        # SCM STOPPED can precede the onefile bootloader parent's final exit.
        # Retain exact image handles before stop; never guess by PID afterward.
        with OwnedImageProcesses(executable) as processes:
            try:
                win32serviceutil.StopService(SERVICE_NAME)
                win32serviceutil.WaitForServiceStatus(SERVICE_NAME,win32service.SERVICE_STOPPED,30)
            except Exception as error:
                if getattr(error,'winerror',None)!=1062:
                    raise
            processes.wait(timeout=15)

    def remove_service(self):
        import win32service
        import win32serviceutil
        from .support_access import SERVICE_NAME
        _,program=production_roots()
        if not self.assert_owned_service(program/'EndpointSupportAccess.exe'):
            return
        self.stop_for_update(program/'EndpointSupportAccess.exe')
        try:
            win32serviceutil.RemoveService(SERVICE_NAME)
        except Exception as error:
            if getattr(error,'winerror',None) != 1060:
                raise

    def remove_payload(self,program):
        import sys
        target=program/'EndpointSupportAccess.exe'
        if target.exists():
            self.private(target);self.inspect_payload(target)
            if Path(sys.executable).resolve()==target.resolve():return True
            with OwnedImageProcesses(target) as processes:processes.wait(timeout=15)
            target.unlink()
        try:program.rmdir()
        except OSError:pass
        return False

    def protect(self, path: Path):
        reject_links(path)
        existed = path.exists()
        if not path.exists():
            path.mkdir(parents=True)
        if os.name != 'nt':
            path.chmod(0o700 if path.is_dir() else 0o600)
            return
        import win32api
        import win32security as security
        assert_namespace(path)
        if existed:
            current = security.GetNamedSecurityInfo(str(path),security.SE_FILE_OBJECT,security.OWNER_SECURITY_INFORMATION)
            owner_sid=security.ConvertSidToStringSid(current.GetSecurityDescriptorOwner())
            if owner_sid not in TRUSTED_SIDS and not _current_elevated_creator(owner_sid):
                raise ValueError('unsafe_support_acl')
        token = security.OpenProcessToken(win32api.GetCurrentProcess(),security.TOKEN_ADJUST_PRIVILEGES|security.TOKEN_QUERY)
        for privilege in ('SeRestorePrivilege','SeTakeOwnershipPrivilege'):
            security.AdjustTokenPrivileges(token,False,[(security.LookupPrivilegeValue(None,privilege),security.SE_PRIVILEGE_ENABLED)])
        inherited = 'OICI' if path.is_dir() else ''
        descriptor = security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            f'O:SYG:SYD:P(A;{inherited};FA;;;SY)(A;{inherited};FA;;;BA)',1)
        security.SetNamedSecurityInfo(str(path),security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION|security.DACL_SECURITY_INFORMATION|security.PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.GetSecurityDescriptorOwner(),None,descriptor.GetSecurityDescriptorDacl(),None)
        assert_private(path)

    def dependencies(self, *, previous=None, existing=False):
        from .support_access_os import PROFILE,WindowsFOD,ensure_inbox_openssh
        if previous and previous.get('profile') not in {None,PROFILE,'bundled-openssh-v1'}:
            raise ValueError('support_dependency_migration_unsupported')
        if previous and previous.get('profile')=='bundled-openssh-v1':
            from .support_access_bundle import verify_profile
            verify_profile(previous) # Retain the exact old compensation input.
        root=production_roots()[0]
        result=ensure_inbox_openssh(WindowsFOD(root))
        self._keygen=result['keygen']
        return result

    def os_dependencies(self):
        root=windows_root()/'System32'/'OpenSSH'
        if not all((root/name).is_file() for name in ('ssh.exe','sshd.exe','ssh-keygen.exe')):
            raise ValueError('support_dependency_unavailable')
        script=r'''
$ErrorActionPreference='Stop'
$items=@()
foreach($name in @('ssh.exe','sshd.exe','ssh-keygen.exe')) {
 $path=Join-Path ([Environment]::GetFolderPath('System')) ('OpenSSH\'+$name)
 $sig=Get-AuthenticodeSignature -LiteralPath $path
 if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation'){throw 'signature'}
 $items+=@{name=$name;version=(Get-Item -LiteralPath $path).VersionInfo.FileVersion;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
}
ConvertTo-Json -InputObject @($items) -Compress
'''
        response=subprocess.run([str(windows_root()/'System32/WindowsPowerShell/v1.0/powershell.exe'),
            '-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16-le')).decode()],
            env=dict(os.environ,PSModulePath=str(windows_root()/'System32/WindowsPowerShell/v1.0/Modules')),
            capture_output=True,text=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        if response.returncode:raise ValueError('support_dependency_signature_invalid')
        records={row['name']:row for row in json.loads(response.stdout)}
        result={'capability_version':'0.0.1.0','automatic_inbound_rule_removed':False,'hashes':{},'versions':{}}
        for role,name in [('ssh','ssh.exe'),('sshd','sshd.exe'),('keygen','ssh-keygen.exe')]:
            result[role]=str(root/name);result['hashes'][role]=records[name]['sha256'];result['versions'][role]=records[name]['version']
        verify_dependencies(result)
        return result

    def remove_runtime(self):
        from .support_access_bundle import remove
        remove()

    def key(self, root: Path, name: str):
        from .support_access import public_key
        if name not in {'host_ed25519','tunnel_ed25519'}:
            raise ValueError('invalid_support_key_role')
        path = root/name
        reject_links(path)
        if not path.exists():
            keygen = Path(getattr(self,'_keygen',windows_root()/'System32'/'OpenSSH'/'ssh-keygen.exe'))
            result = subprocess.run([str(keygen),'-q','-t','ed25519','-N','','-C','endpoint-support','-f',str(path)],
                capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode:
                raise RuntimeError('support_key_generation_failed')
        self.protect(path)
        # Derive public bytes from the retained private key, not a stale .pub file.
        keygen = Path(getattr(self,'_keygen',windows_root()/'System32'/'OpenSSH'/'ssh-keygen.exe'))
        result = subprocess.run([str(keygen),'-y','-f',str(path)],capture_output=True,text=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:
            raise RuntimeError('support_key_read_failed')
        canonical = ' '.join(result.stdout.strip().split()[:2])
        public_key(canonical)
        atomic_write(root/(name+'.pub'),canonical+'\n')
        self.protect(root/(name+'.pub'))
        return canonical

    def install_service(self, executable: Path):
        import win32service
        import win32serviceutil
        from .support_access import SERVICE_NAME
        assert_private(executable)
        manager = win32service.OpenSCManager(None,None,win32service.SC_MANAGER_CONNECT|win32service.SC_MANAGER_CREATE_SERVICE)
        service = None
        try:
            try:
                service = win32service.OpenService(manager,SERVICE_NAME,win32service.SERVICE_ALL_ACCESS)
            except Exception as error:
                if getattr(error,'winerror',None) != 1060:
                    raise
                service = win32service.CreateService(manager,SERVICE_NAME,'Endpoint Support Access',
                    win32service.SERVICE_ALL_ACCESS,win32service.SERVICE_WIN32_OWN_PROCESS,
                    win32service.SERVICE_AUTO_START,win32service.SERVICE_ERROR_NORMAL,
                    '"'+str(executable)+'"',None,0,None,'LocalSystem',None)
            else:
                validate_service_config(win32service.QueryServiceConfig(service),executable)
                win32service.ChangeServiceConfig(service,win32service.SERVICE_WIN32_OWN_PROCESS,
                    win32service.SERVICE_AUTO_START,win32service.SERVICE_ERROR_NORMAL,
                    '"'+str(executable)+'"',None,0,[], 'LocalSystem',None,'Endpoint Support Access')
            # No Core/observer/updater dependencies. SCM crash recovery owns restart.
            win32service.ChangeServiceConfig2(service,win32service.SERVICE_CONFIG_FAILURE_ACTIONS,
                {'ResetPeriod':86400,'RebootMsg':'','Command':'','Actions':[(win32service.SC_ACTION_RESTART,5000),(win32service.SC_ACTION_RESTART,30000)]})
            try:
                win32service.StartService(service,None)
            except Exception as error:
                if getattr(error,'winerror',None) != 1056:
                    raise
        finally:
            if service is not None:
                win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(manager)


class _ProcessEntry(ctypes.Structure):
    _fields_=[('dwSize',wintypes.DWORD),('cntUsage',wintypes.DWORD),
              ('pid',wintypes.DWORD),('heap',ctypes.c_size_t),('module',wintypes.DWORD),
              ('threads',wintypes.DWORD),('parent',wintypes.DWORD),('priority',wintypes.LONG),
              ('flags',wintypes.DWORD),('name',wintypes.WCHAR*260)]


class OwnedImageProcesses:
    """Retained handles to exact installed image instances, including onefile parent."""
    def __init__(self, executable: Path, *, only_pids=None):
        self.handles=[]
        self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.kernel.CreateToolhelp32Snapshot.argtypes=[wintypes.DWORD,wintypes.DWORD]
        self.kernel.CreateToolhelp32Snapshot.restype=wintypes.HANDLE
        self.kernel.Process32FirstW.argtypes=[wintypes.HANDLE,ctypes.POINTER(_ProcessEntry)]
        self.kernel.Process32NextW.argtypes=[wintypes.HANDLE,ctypes.POINTER(_ProcessEntry)]
        self.kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
        self.kernel.OpenProcess.restype=wintypes.HANDLE
        self.kernel.QueryFullProcessImageNameW.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)]
        self.kernel.CloseHandle.argtypes=[wintypes.HANDLE]
        self.kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
        snapshot=self.kernel.CreateToolhelp32Snapshot(2,0)
        if snapshot==wintypes.HANDLE(-1).value:raise ctypes.WinError(ctypes.get_last_error())
        expected=str(executable).replace('/','\\').casefold()
        try:
            entry=_ProcessEntry();entry.dwSize=ctypes.sizeof(entry)
            more=self.kernel.Process32FirstW(snapshot,ctypes.byref(entry))
            while more:
                if (entry.name.casefold()==executable.name.casefold() and entry.pid not in {os.getpid(),os.getppid()}
                        and (only_pids is None or entry.pid in only_pids)):
                    handle=self.kernel.OpenProcess(0x1000|0x100000,False,entry.pid)
                    if handle:
                        path=ctypes.create_unicode_buffer(32768);length=wintypes.DWORD(len(path))
                        queried=self.kernel.QueryFullProcessImageNameW(handle,0,path,ctypes.byref(length))
                        error=ctypes.get_last_error() if not queried else 0
                        if queried and path.value.casefold()==expected:
                            self.handles.append(handle)
                        else:
                            self.kernel.CloseHandle(handle)
                            if not queried and error not in {6,87}:raise RuntimeError('support_process_identity_unavailable')
                    elif ctypes.get_last_error()!=87:
                        raise RuntimeError('support_process_identity_unavailable')
                more=self.kernel.Process32NextW(snapshot,ctypes.byref(entry))
        except BaseException:
            self.close();raise
        finally:self.kernel.CloseHandle(snapshot)

    def wait(self, *, timeout: float):
        deadline=time.monotonic()+timeout
        for handle in self.handles:
            result=self.kernel.WaitForSingleObject(handle,max(0,int((deadline-time.monotonic())*1000)))
            if result!=0:raise RuntimeError('support_process_exit_timeout')

    def close(self):
        for handle in self.handles:self.kernel.CloseHandle(handle)
        self.handles.clear()

    def __enter__(self):return self
    def __exit__(self,*args):self.close()


class ForwardConfirmation:
    """Bounded diagnostic matcher belonging to one exact current SSH child."""
    def __init__(self, remote_port: int):
        self.marker=f'remote forward success for: listen 127.0.0.1:{remote_port}, connect 127.0.0.1:22222'.encode()
        self.tail=b''
        self.confirmed=False

    def feed(self, data: bytes):
        combined=self.tail+data
        if self.marker in combined:self.confirmed=True
        self.tail=combined[-8192:]


class _SecurityAttributes(ctypes.Structure):
    _fields_=[('length',wintypes.DWORD),('descriptor',wintypes.LPVOID),('inherit',wintypes.BOOL)]


class _StartupInfo(ctypes.Structure):
    _fields_=[('cb',wintypes.DWORD),('reserved',wintypes.LPWSTR),('desktop',wintypes.LPWSTR),
              ('title',wintypes.LPWSTR),('x',wintypes.DWORD),('y',wintypes.DWORD),
              ('width',wintypes.DWORD),('height',wintypes.DWORD),('chars_x',wintypes.DWORD),
              ('chars_y',wintypes.DWORD),('fill',wintypes.DWORD),('flags',wintypes.DWORD),
              ('show',wintypes.WORD),('reserved_size',wintypes.WORD),('reserved_bytes',ctypes.POINTER(ctypes.c_ubyte)),
              ('stdin',wintypes.HANDLE),('stdout',wintypes.HANDLE),('stderr',wintypes.HANDLE)]


class _StartupInfoEx(ctypes.Structure):
    _fields_=[('startup',_StartupInfo),('attributes',wintypes.LPVOID)]


class _ProcessInfo(ctypes.Structure):
    _fields_=[('process',wintypes.HANDLE),('thread',wintypes.HANDLE),('pid',wintypes.DWORD),('tid',wintypes.DWORD)]


def _captured_suspended_process(arguments):
    """Create suspended child with exactly stderr/NUL inherited, no other handles."""
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreatePipe.argtypes=[ctypes.POINTER(wintypes.HANDLE),ctypes.POINTER(wintypes.HANDLE),ctypes.POINTER(_SecurityAttributes),wintypes.DWORD]
    kernel.SetHandleInformation.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.DWORD]
    kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(_SecurityAttributes),wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype=wintypes.HANDLE
    kernel.InitializeProcThreadAttributeList.argtypes=[wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(ctypes.c_size_t)]
    kernel.UpdateProcThreadAttribute.argtypes=[wintypes.LPVOID,wintypes.DWORD,ctypes.c_size_t,wintypes.LPVOID,ctypes.c_size_t,wintypes.LPVOID,wintypes.LPVOID]
    kernel.DeleteProcThreadAttributeList.argtypes=[wintypes.LPVOID]
    kernel.CreateProcessW.argtypes=[wintypes.LPCWSTR,wintypes.LPWSTR,wintypes.LPVOID,wintypes.LPVOID,wintypes.BOOL,wintypes.DWORD,wintypes.LPVOID,wintypes.LPCWSTR,ctypes.POINTER(_StartupInfoEx),ctypes.POINTER(_ProcessInfo)]
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    security=_SecurityAttributes(ctypes.sizeof(_SecurityAttributes),None,True)
    read=wintypes.HANDLE();write=wintypes.HANDLE();nul=None;attribute=None
    success=False;attribute_initialized=False
    try:
        if not kernel.CreatePipe(ctypes.byref(read),ctypes.byref(write),ctypes.byref(security),65536):raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.SetHandleInformation(read,1,0):raise ctypes.WinError(ctypes.get_last_error())
        nul=kernel.CreateFileW('NUL',0x80000000|0x40000000,3,ctypes.byref(security),3,0x80,None)
        if nul==wintypes.HANDLE(-1).value:raise ctypes.WinError(ctypes.get_last_error())
        size=ctypes.c_size_t()
        kernel.InitializeProcThreadAttributeList(None,1,0,ctypes.byref(size))
        attribute=ctypes.create_string_buffer(size.value)
        if not kernel.InitializeProcThreadAttributeList(attribute,1,0,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
        attribute_initialized=True
        handles=(wintypes.HANDLE*2)(write.value,nul)
        if not kernel.UpdateProcThreadAttribute(attribute,0,0x20002,ctypes.cast(handles,wintypes.LPVOID),ctypes.sizeof(handles),None,None):raise ctypes.WinError(ctypes.get_last_error())
        startup=_StartupInfoEx();startup.startup.cb=ctypes.sizeof(startup)
        startup.startup.flags=0x100;startup.startup.stdin=nul;startup.startup.stdout=nul;startup.startup.stderr=write.value
        startup.attributes=ctypes.cast(attribute,wintypes.LPVOID)
        process=_ProcessInfo()
        command=ctypes.create_unicode_buffer(subprocess.list2cmdline(arguments))
        if not kernel.CreateProcessW(arguments[0],command,None,None,True,0x4|0x08000000|0x00080000,
            None,str(Path(arguments[0]).parent),ctypes.byref(startup),ctypes.byref(process)):
            raise ctypes.WinError(ctypes.get_last_error())
        success=True
        return process.process,process.thread,read.value
    finally:
        if attribute_initialized:kernel.DeleteProcThreadAttributeList(attribute)
        if write.value:kernel.CloseHandle(write)
        if nul and nul!=wintypes.HANDLE(-1).value:kernel.CloseHandle(nul)
        if read.value and not success:kernel.CloseHandle(read)


class _PipeReader:
    def __init__(self, handle, collector):
        self.handle=handle;self.collector=collector;self.stop=Event()
        self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.kernel.PeekNamedPipe.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.DWORD,wintypes.LPVOID,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID]
        self.kernel.ReadFile.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID]
        self.kernel.CloseHandle.argtypes=[wintypes.HANDLE]
        self.thread=Thread(target=self.run,name='support-ssh-stderr',daemon=True);self.thread.start()

    def run(self):
        while not self.stop.is_set():
            available=wintypes.DWORD()
            if not self.kernel.PeekNamedPipe(self.handle,None,0,None,ctypes.byref(available),None):return
            if available.value:
                buffer=ctypes.create_string_buffer(min(4096,available.value));read=wintypes.DWORD()
                if not self.kernel.ReadFile(self.handle,buffer,len(buffer),ctypes.byref(read),None):return
                self.collector.feed(buffer.raw[:read.value])
            else:self.stop.wait(.02)

    def close(self):
        self.stop.set();self.thread.join(timeout=2)
        self.kernel.CloseHandle(self.handle)


class NativeProcessJob:
    """Own all sshd/ssh descendants; handle closure/SCM crash kills the whole tree."""
    def __init__(self):
        import win32job
        self.job = win32job.CreateJobObject(None,'')
        limits = win32job.QueryInformationJobObject(self.job,win32job.JobObjectExtendedLimitInformation)
        limits['BasicLimitInformation']['LimitFlags'] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(self.job,win32job.JobObjectExtendedLimitInformation,limits)
        self.processes = []
        self.readers=[]

    def launch(self, arguments: list[str], *, stderr=None):
        import win32api
        import win32job
        import win32process
        # Suspend before assignment: no sshd/shell descendant can escape its job.
        startup = win32process.STARTUPINFO()
        pipe=None
        if stderr is None:
            process, thread, _, _ = win32process.CreateProcess(arguments[0],subprocess.list2cmdline(arguments),
                None,None,False,win32process.CREATE_SUSPENDED|win32process.CREATE_NO_WINDOW,
                None,str(Path(arguments[0]).parent),startup)
        else:process,thread,pipe=_captured_suspended_process(arguments)
        try:
            win32job.AssignProcessToJobObject(self.job,process)
            self.processes.append(process)
            if pipe is not None:
                self.readers.append(_PipeReader(pipe,stderr));pipe=None
            win32process.ResumeThread(thread)
        except BaseException:
            win32process.TerminateProcess(process,1)
            if process not in self.processes:
                win32api.CloseHandle(process)
            raise
        finally:
            win32api.CloseHandle(thread)
            if pipe is not None:win32api.CloseHandle(pipe)

    def alive(self):
        import win32process
        return bool(self.job and self.processes) and all(win32process.GetExitCodeProcess(p)==259 for p in self.processes)

    def close(self):
        import win32api
        import win32job
        if self.job:
            win32job.TerminateJobObject(self.job,0)
            win32api.CloseHandle(self.job)
            self.job = None
        for process in self.processes:
            win32api.CloseHandle(process)
        self.processes.clear()
        for reader in self.readers:reader.close()
        self.readers.clear()


class SupportChildren:
    def __init__(self, root: Path, dependencies: dict):
        self.root = root
        self.dependencies = dependencies
        self.job = None
        self.remote_port = None
        self.confirmation=None
        self.dependencies_validated=False

    def select_dependencies(self,dependencies):
        verify_dependencies(dependencies)
        if dependencies!=self.dependencies:
            self.stop()
            self.dependencies=dependencies
        self.dependencies_validated=True

    def start(self, policy):
        from .support_access import sshd_config, tunnel_command, _ssh_path
        self.stop()
        self.remote_port = policy.remote_port
        self.confirmation=ForwardConfirmation(policy.remote_port)
        verify_dependencies(self.dependencies)
        self.dependencies_validated=True
        from dataclasses import replace
        policy=replace(policy,windows_admin_username=validate_windows_admin(policy.windows_admin_username))
        assert_private(self.root)
        for name in ('host_ed25519','tunnel_ed25519'):
            assert_private(self.root/name)
        config=sshd_config(self.root,policy)
        if self.dependencies.get('profile')=='bundled-openssh-v1':
            config+='ModuliFile '+_ssh_path(Path(self.dependencies['sshd']).parent/'moduli')+'\n'
        elif self.dependencies.get('profile')=='windows-openssh-fod-v1' and self.dependencies.get('moduli_sha256'):
            config+='ModuliFile '+_ssh_path(Path(self.dependencies['sshd']).parent/'moduli')+'\n'
        for name, data in [
            ('authorized_keys','\n'.join(policy.operator_public_keys)+'\n'),
            ('sshd_config',config),
            ('known_hosts','endpoint-support-gateway '+policy.gateway_host_public_key+'\n'),
            ('sshd.pid',''),
        ]:
            atomic_write(self.root/name,data)
            WindowsSupportOps().protect(self.root/name)
        daemon = [self.dependencies['sshd'],'-D','-e','-f',str(self.root/'sshd_config')]
        checked = subprocess.run([self.dependencies['sshd'],'-t','-f',str(self.root/'sshd_config')],
            capture_output=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
        if checked.returncode:
            raise RuntimeError('support_sshd_config_invalid')
        self.job = NativeProcessJob()
        try:
            self.job.launch(daemon)
            self.job.launch(tunnel_command(self.dependencies['ssh'],self.root,policy),stderr=self.confirmation)
        except BaseException:
            self.stop()
            raise

    def alive(self):
        return self.job is not None and self.job.alive()

    def connected(self):
        return bool(self.alive() and self.confirmation and self.confirmation.confirmed)

    def stop(self):
        self.confirmation=None
        if self.job is not None:
            self.job.close()
            self.job = None
