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

TRUSTED_SIDS = {'S-1-5-18', 'S-1-5-32-544'}
# Exact identities already present in the canonical Agent172 data ACL policy.
# They are bootstrap readers/writers only, never principals in Support ACLs.
BOOTSTRAP_SERVICE_SIDS = (
    'S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691',
    'S-1-5-80-327494974-20047353-929432329-1920152597-707704661',
)


def reject_links(path: Path):
    for item in [*reversed(path.parents), path]:
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise ValueError('unsafe_support_path')
        if not stat.S_ISDIR(info.st_mode) and info.st_nlink != 1:
            raise ValueError('unsafe_support_path')


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


def assert_bootstrap_file(path: Path):
    reject_links(path)
    if not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('support_enrollment_unavailable')
    import win32security as security
    descriptor = security.GetNamedSecurityInfo(str(path),security.SE_FILE_OBJECT,
        security.OWNER_SECURITY_INFORMATION|security.DACL_SECURITY_INFORMATION)
    trusted = TRUSTED_SIDS|{'S-1-5-19'}
    if security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in trusted:
        raise ValueError('support_enrollment_unavailable')
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None:
        raise ValueError('support_enrollment_unavailable')
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        if len(ace)!=3 or ace[0][0]!=security.ACCESS_ALLOWED_ACE_TYPE:
            raise ValueError('support_enrollment_unavailable')
        sid=security.ConvertSidToStringSid(ace[2])
        if sid in trusted:
            continue
        import ntsecuritycon
        credential=path.name in {'device-credential','endpoint-ca.crt'}
        allowed={BOOTSTRAP_SERVICE_SIDS[0]:ntsecuritycon.FILE_GENERIC_READ,
                 BOOTSTRAP_SERVICE_SIDS[1]:ntsecuritycon.FILE_GENERIC_WRITE}
        if not credential:
            allowed=dict.fromkeys(BOOTSTRAP_SERVICE_SIDS,
                ntsecuritycon.FILE_GENERIC_READ|ntsecuritycon.FILE_GENERIC_WRITE|ntsecuritycon.DELETE)
        if sid not in allowed or ace[1]&~allowed[sid]:
            raise ValueError('support_enrollment_unavailable')


def validate_windows_admin(username: str):
    import win32net
    import win32netcon
    info = win32net.NetUserGetInfo(None,username,1)
    # pywin32311 exposes (server, user, flags); native level0 is implicit.
    groups = win32net.NetUserGetLocalGroups(None,username,win32netcon.LG_INCLUDE_INDIRECT)
    if info['flags'] & 2 or administrators_name().casefold() not in {g.casefold() for g in groups}:
        raise ValueError('support_existing_admin_required')


def verify_dependencies(dependencies: dict):
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


class WindowsSupportOps:
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
        try:
            win32serviceutil.StopService(SERVICE_NAME)
            win32serviceutil.WaitForServiceStatus(SERVICE_NAME,win32service.SERVICE_STOPPED,30)
        except Exception as error:
            if getattr(error,'winerror',None)!=1062:
                raise

    def remove_service(self):
        import win32service
        import win32serviceutil
        from .support_access import SERVICE_NAME
        _,program=production_roots()
        if not self.assert_owned_service(program/'EndpointSupportAccess.exe'):
            return
        try:
            win32serviceutil.StopService(SERVICE_NAME)
            win32serviceutil.WaitForServiceStatus(SERVICE_NAME,win32service.SERVICE_STOPPED,30)
        except Exception as error:
            if getattr(error,'winerror',None) not in {1060,1062}:
                raise
        try:
            win32serviceutil.RemoveService(SERVICE_NAME)
        except Exception as error:
            if getattr(error,'winerror',None) != 1060:
                raise

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

    def dependencies(self):
        # This method is invoked exclusively by native installer, never service boot.
        powershell = windows_root()/'System32'/'WindowsPowerShell'/'v1.0'/'powershell.exe'
        script = r'''
$ErrorActionPreference='Stop'
$restart=$false
$removedInboundRule=$false
$existingInboundRule=@(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
foreach($name in @('OpenSSH.Client~~~~0.0.1.0','OpenSSH.Server~~~~0.0.1.0')) {
  $cap=Get-WindowsCapability -Online -Name $name
  if($cap.State -ne 'Installed') {
    try {
      $added=Add-WindowsCapability -Online -Name $name
      if($added.RestartNeeded){$restart=$true}
    } finally {
      if($name -eq 'OpenSSH.Server~~~~0.0.1.0' -and $existingInboundRule.Count -eq 0) {
        $newRule=@(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
        foreach($rule in $newRule){Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop}
        if(@(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue).Count -ne 0) {throw 'support_dependency_firewall_conflict'}
        $removedInboundRule=$newRule.Count -gt 0
      }
    }
  }
}
$items=@()
foreach($name in @('ssh.exe','sshd.exe','ssh-keygen.exe')) {
  $path=Join-Path ([Environment]::GetFolderPath('System')) ('OpenSSH\'+$name)
  $sig=Get-AuthenticodeSignature -LiteralPath $path
  if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {throw 'support_dependency_signature_invalid'}
  $items+=@{name=$name;version=(Get-Item -LiteralPath $path).VersionInfo.FileVersion;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
}
@{restart_needed=$restart;automatic_inbound_rule_removed=$removedInboundRule;capability_version='0.0.1.0';items=$items}|ConvertTo-Json -Depth 4 -Compress
'''
        encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
        result = subprocess.run([str(powershell),'-NoProfile','-NonInteractive','-EncodedCommand',encoded],
            capture_output=True,text=True,timeout=600,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:
            if 'support_dependency_firewall_conflict' in result.stderr:
                raise RuntimeError('support_dependency_firewall_conflict')
            if 'support_dependency_signature_invalid' in result.stderr:
                raise RuntimeError('support_dependency_signature_invalid')
            raise RuntimeError('support_dependency_install_failed')
        response = json.loads(result.stdout.strip().splitlines()[-1])
        if response.get('restart_needed'):
            raise RuntimeError('support_dependency_reboot_required')
        records = {item['name']:item for item in response['items']}
        root = windows_root()/'System32'/'OpenSSH'
        output = {'capability_version':'0.0.1.0','hashes':{},'versions':{},
                  'automatic_inbound_rule_removed':response.get('automatic_inbound_rule_removed') is True}
        for role, filename in [('ssh','ssh.exe'),('sshd','sshd.exe'),('keygen','ssh-keygen.exe')]:
            output[role] = str(root/filename)
            output['hashes'][role] = records[filename]['sha256']
            output['versions'][role] = records[filename]['version']
        verify_dependencies(output)
        return output

    def key(self, root: Path, name: str):
        from .support_access import public_key
        if name not in {'host_ed25519','tunnel_ed25519'}:
            raise ValueError('invalid_support_key_role')
        path = root/name
        reject_links(path)
        if not path.exists():
            keygen = windows_root()/'System32'/'OpenSSH'/'ssh-keygen.exe'
            result = subprocess.run([str(keygen),'-q','-t','ed25519','-N','','-C','endpoint-support','-f',str(path)],
                capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode:
                raise RuntimeError('support_key_generation_failed')
        self.protect(path)
        # Derive public bytes from the retained private key, not a stale .pub file.
        keygen = windows_root()/'System32'/'OpenSSH'/'ssh-keygen.exe'
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


class NativeProcessJob:
    """Own all sshd/ssh descendants; handle closure/SCM crash kills the whole tree."""
    def __init__(self):
        import win32job
        self.job = win32job.CreateJobObject(None,'')
        limits = win32job.QueryInformationJobObject(self.job,win32job.JobObjectExtendedLimitInformation)
        limits['BasicLimitInformation']['LimitFlags'] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(self.job,win32job.JobObjectExtendedLimitInformation,limits)
        self.processes = []

    def launch(self, arguments: list[str]):
        import win32api
        import win32job
        import win32process
        # Suspend before assignment: no sshd/shell descendant can escape its job.
        startup = win32process.STARTUPINFO()
        process, thread, _, _ = win32process.CreateProcess(arguments[0],subprocess.list2cmdline(arguments),
            None,None,False,win32process.CREATE_SUSPENDED|win32process.CREATE_NO_WINDOW,
            None,str(Path(arguments[0]).parent),startup)
        try:
            win32job.AssignProcessToJobObject(self.job,process)
            self.processes.append(process)
            win32process.ResumeThread(thread)
        except BaseException:
            win32process.TerminateProcess(process,1)
            if process not in self.processes:
                win32api.CloseHandle(process)
            raise
        finally:
            win32api.CloseHandle(thread)

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


class SupportChildren:
    def __init__(self, root: Path, dependencies: dict):
        self.root = root
        self.dependencies = dependencies
        self.job = None
        self.remote_port = None

    def start(self, policy):
        from .support_access import sshd_config, tunnel_command
        self.stop()
        self.remote_port = policy.remote_port
        verify_dependencies(self.dependencies)
        validate_windows_admin(policy.windows_admin_username)
        assert_private(self.root)
        for name in ('host_ed25519','tunnel_ed25519'):
            assert_private(self.root/name)
        for name, data in [
            ('authorized_keys','\n'.join(policy.operator_public_keys)+'\n'),
            ('sshd_config',sshd_config(self.root,policy)),
            ('known_hosts','endpoint-support-gateway '+policy.gateway_host_public_key+'\n'),
            ('tunnel.log',''),
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
            self.job.launch(tunnel_command(self.dependencies['ssh'],self.root,policy))
        except BaseException:
            self.stop()
            raise

    def alive(self):
        return self.job is not None and self.job.alive()

    def connected(self):
        if not self.alive() or self.remote_port is None:
            return False
        try:
            log = self.root/'tunnel.log'
            reject_links(log)
            with log.open('rb') as stream:
                stream.seek(max(0,log.stat().st_size-65536))
                data = stream.read(65536).decode('utf-8',errors='replace')
        except OSError:
            return False
        marker = f'remote forward success for: listen 127.0.0.1:{self.remote_port}, connect 127.0.0.1:22222'
        return marker in data

    def stop(self):
        if self.job is not None:
            self.job.close()
            self.job = None
