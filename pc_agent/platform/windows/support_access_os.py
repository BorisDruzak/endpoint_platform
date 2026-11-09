"""Fixed Windows FoD preparation and independently validated OpenSSH snapshots.

No request can select a capability, executable, script, source or firewall rule.
An uncertain servicing operation is retained separately from the native MSI owner.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

PROFILE = 'windows-openssh-fod-v1'
CAPABILITIES = ('OpenSSH.Client~~~~0.0.1.0', 'OpenSSH.Server~~~~0.0.1.0')
ROLES = {'ssh': 'ssh.exe', 'sshd': 'sshd.exe', 'keygen': 'ssh-keygen.exe'}


def _capabilities(value):
    if not isinstance(value, dict) or set(value) != set(CAPABILITIES):
        raise ValueError('support_dependency_install_failed')
    if any(state not in {'Installed', 'NotPresent'} for state in value.values()):
        raise ValueError('support_dependency_reboot_required')
    return tuple(name for name in CAPABILITIES if value[name] == 'NotPresent')


def ensure_inbox_openssh(ops):
    missing = _capabilities(ops.capabilities())
    previous = ops.read_receipt()
    if previous and previous.get('state')=='installed_unverified':
        if missing:raise ValueError('support_dependency_recovery_required')
        dependencies=ops.verify()
        ops.write_receipt(dict(previous,state='complete'))
        return dependencies
    if (previous and previous.get('state')=='reboot_required' and not missing
            and getattr(ops,'reboot_completed',lambda old:False)(previous)):
        dependencies=ops.verify()
        ops.write_receipt(dict(previous,state='complete'))
        return dependencies
    if previous and previous.get('state') not in {'complete', 'failed'}:
        # File presence cannot settle a killed DISM/TrustedInstaller operation.
        raise ValueError('support_dependency_recovery_required')
    if not missing:
        return ops.verify()
    receipt = {'schema_version': 1, 'state': 'servicing', 'capabilities': list(missing)}
    ops.write_receipt(receipt)
    try:
        result = ops.install(missing)
    except Exception:
        # Do not guess whether Windows servicing continued after caller loss.
        raise ValueError('support_dependency_recovery_required') from None
    if (not isinstance(result, dict) or set(result) !=
            {'completed', 'restart_needed', 'boundary_preserved'} or
            any(type(value) is not bool for value in result.values())):
        raise ValueError('support_dependency_recovery_required')
    if not result['boundary_preserved']:
        state, error = 'conflict', 'support_dependency_firewall_conflict'
    elif result['restart_needed']:
        state, error = 'reboot_required', 'support_dependency_reboot_required'
    elif not result['completed']:
        state, error = 'failed', 'support_dependency_install_failed'
    else:
        state, error = 'complete', None
    if error:
        ops.write_receipt(dict(receipt, state=state))
        raise ValueError(error)
    receipt=dict(receipt,state='installed_unverified')
    ops.write_receipt(receipt) # Known servicing completion is not lost on verifier failure.
    if _capabilities(ops.capabilities()):
        raise ValueError('support_dependency_recovery_required')
    dependencies = ops.verify()
    ops.write_receipt(dict(receipt, state='complete'))
    return dependencies


class OSDependencyMonitor:
    """The policy worker owns slow validation; the lease loop never waits on it."""
    def __init__(self, dependencies, *, unchanged, validate, persist=lambda old, new: None):
        if dependencies.get('profile') != PROFILE:
            raise ValueError('support_dependency_migration_unsupported')
        self.dependencies = deepcopy(dependencies)
        self.unchanged, self.validate, self.persist = unchanged, validate, persist

    def refresh(self):
        if self.unchanged(self.dependencies):
            return deepcopy(self.dependencies)
        verified = self.validate()
        if not isinstance(verified, dict) or verified.get('profile') != PROFILE:
            raise ValueError('support_dependency_signature_invalid')
        self.persist(self.dependencies, verified)
        self.dependencies = deepcopy(verified)
        return deepcopy(verified)


def run_fixed_powershell(script, *, variables=None, timeout=60):
    from .support_access_native import windows_root
    system = windows_root() / 'System32'
    environment = dict(os.environ, PSModulePath=str(system/'WindowsPowerShell/v1.0/Modules'))
    environment.update(variables or {})
    prefix = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
    result = subprocess.run([str(system/'WindowsPowerShell/v1.0/powershell.exe'),
        '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
        base64.b64encode((prefix+script).encode('utf-16-le')).decode()],
        env=environment, capture_output=True, text=True, timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode or len(result.stdout.encode('utf-8')) > 65536:
        raise ValueError('support_dependency_signature_invalid')
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        raise ValueError('support_dependency_signature_invalid') from None


def _hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def assert_os_path(path):
    """Windows servicing owners may write code; ordinary users may only read it."""
    from .support_access_native import windows_root, reject_links, TRUSTED_SIDS
    import win32security as security
    root = windows_root()/'System32'/'OpenSSH'
    if path != root and path.parent != root:
        raise ValueError('support_dependency_changed')
    installer = security.ConvertSidToStringSid(security.LookupAccountName(None, r'NT SERVICE\TrustedInstaller')[0])
    trusted = set(TRUSTED_SIDS) | {installer}
    # Include parents: replacing a protected leaf through a writable parent is unsafe.
    for current in (windows_root(), windows_root()/'System32', root, path):
        reject_links(current)
        info = security.GetNamedSecurityInfo(str(current), security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION)
        if security.ConvertSidToStringSid(info.GetSecurityDescriptorOwner()) not in trusted:
            raise ValueError('support_dependency_signature_invalid')
        acl = info.GetSecurityDescriptorDacl()
        if acl is None:
            raise ValueError('support_dependency_signature_invalid')
        for i in range(acl.GetAceCount()):
            ace = acl.GetAce(i)
            if ace[0][1] & security.INHERIT_ONLY_ACE:
                continue
            if ace[0][0] == security.ACCESS_DENIED_ACE_TYPE:
                continue
            if (ace[0][0] != security.ACCESS_ALLOWED_ACE_TYPE or
                    (ace[1] & 0x500D0156 and security.ConvertSidToStringSid(ace[2]) not in trusted)):
                raise ValueError('support_dependency_signature_invalid')


def verify_os_snapshot(value):
    """Fast checks for a previously authenticated full OpenSSH helper closure."""
    from .support_access_native import windows_root
    root = windows_root()/'System32'/'OpenSSH'
    if not isinstance(value, dict) or set(value) != {
            'profile', 'capability_version', 'ssh', 'sshd', 'keygen',
            'hashes', 'versions', 'files', 'moduli_sha256'} or value['profile'] != PROFILE:
        raise ValueError('support_dependency_changed')
    if value['capability_version'] != '0.0.1.0' or not isinstance(value['files'], list) or not 3 <= len(value['files']) <= 64:
        raise ValueError('support_dependency_changed')
    assert_os_path(root)
    names = set()
    versions = set()
    for row in value['files']:
        if (not isinstance(row, dict) or set(row) != {'name', 'size', 'sha256', 'version', 'publisher_thumbprint'}
                or not re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:exe|dll)', row['name'])
                or row['name'].casefold() in names or not re.fullmatch('[0-9a-f]{64}', row['sha256'])
                or not isinstance(row['version'],str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',row['version'])
                or not isinstance(row['publisher_thumbprint'],str) or not re.fullmatch('[0-9A-Fa-f]{40}',row['publisher_thumbprint'])
                or type(row['size']) is not int or not 0 < row['size'] <= 100*1024*1024):
            raise ValueError('support_dependency_changed')
        names.add(row['name'].casefold())
        versions.add(row['version'])
        path = root/row['name']
        assert_os_path(path)
        if path.stat().st_nlink < 1 or path.stat().st_size != row['size'] or _hash(path) != row['sha256']:
            raise ValueError('support_dependency_changed')
    actual = {p.name.casefold() for p in root.iterdir() if p.suffix.lower() in {'.exe', '.dll'}}
    if actual != names or len(versions)!=1:
        raise ValueError('support_dependency_changed')
    rows = {r['name']: r for r in value['files']}
    if set(value['hashes']) != set(ROLES) or set(value['versions']) != set(ROLES):
        raise ValueError('support_dependency_changed')
    for role, name in ROLES.items():
        if (value[role] != str(root/name) or name not in rows or value['hashes'][role] != rows[name]['sha256']
                or value['versions'][role] != rows[name]['version']):
            raise ValueError('support_dependency_changed')
    if value['moduli_sha256'] is not None:
        assert_os_path(root/'moduli')
        if not re.fullmatch('[0-9a-f]{64}', value['moduli_sha256']) or _hash(root/'moduli') != value['moduli_sha256']:
            raise ValueError('support_dependency_changed')
    elif (root/'moduli').exists():
        raise ValueError('support_dependency_changed')


def snapshot_unchanged(value):
    try:
        verify_os_snapshot(value)
        return True
    except (ValueError, OSError, TypeError, KeyError):
        return False


def signed_os_dependencies():
    from .support_access_native import windows_root
    root = windows_root()/'System32'/'OpenSSH'
    assert_os_path(root)
    value = run_fixed_powershell(r'''
$root=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH'
$files=@(Get-ChildItem -LiteralPath $root -File | Where-Object {$_.Extension -in @('.exe','.dll')} | Sort-Object Name)
if($files.Count -lt 3 -or $files.Count -gt 64){throw 'closure'}
$out=@();$handles=@()
try {
 foreach($file in $files){$handles+=,[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)}
 foreach($file in $files){
  $s=Get-AuthenticodeSignature -LiteralPath $file.FullName
  if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'){throw 'signature'}
  $out+=@{name=$file.Name;size=$file.Length;version=$file.VersionInfo.FileVersion;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant();publisher_thumbprint=$s.SignerCertificate.Thumbprint}
 }
 ConvertTo-Json -InputObject @($out) -Compress
} finally {foreach($handle in $handles){$handle.Dispose()}}
''')
    if not isinstance(value, list):
        raise ValueError('support_dependency_signature_invalid')
    rows = {row['name']: row for row in value}
    if not set(ROLES.values()) <= set(rows) or len(rows) != len(value):
        raise ValueError('support_dependency_signature_invalid')
    result = {'profile': PROFILE, 'capability_version': '0.0.1.0',
        **{role: str(root/name) for role, name in ROLES.items()},
        'hashes': {role: rows[name]['sha256'] for role, name in ROLES.items()},
        'versions': {role: rows[name]['version'] for role, name in ROLES.items()},
        'files': value, 'moduli_sha256': _hash(root/'moduli') if (root/'moduli').is_file() else None}
    verify_os_snapshot(result)
    return result


class WindowsFOD:
    def __init__(self, root):
        from .support_access_native import assert_private
        self.root = Path(root)
        assert_private(self.root)
        self.path = self.root/'os-servicing.json'
        self._metadata=None

    def boot_state(self):
        return run_fixed_powershell(r'''
$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
$pending=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
@{boot_id=$boot;pending=[bool]$pending}|ConvertTo-Json -Compress
''')

    def reboot_completed(self,previous):
        if not isinstance(previous.get('boot_id'),str):return False
        current=self.boot_state()
        if (not current.get('pending') and isinstance(current.get('boot_id'),str)
                and current['boot_id']!=previous['boot_id']):
            self._metadata=dict(previous,recovered_boot_id=current['boot_id'])
            return True
        return False

    def capabilities(self):
        rows = run_fixed_powershell(r'''
$out=@();foreach($name in @('OpenSSH.Client~~~~0.0.1.0','OpenSSH.Server~~~~0.0.1.0')){
 $c=Get-WindowsCapability -Online -Name $name
 $out+=@{name=$c.Name;state=[string]$c.State}
};ConvertTo-Json -InputObject @($out) -Compress
''')
        if not isinstance(rows, list) or len(rows) != 2:
            raise ValueError('support_dependency_install_failed')
        return {r['name']: r['state'] for r in rows}

    def read_receipt(self):
        from .support_access_native import assert_private, reject_links
        reject_links(self.path)
        if not self.path.exists():
            return None
        assert_private(self.path)
        if self.path.stat().st_size > 8192:
            raise ValueError('support_dependency_recovery_required')
        value = json.loads(self.path.read_text(encoding='utf-8'))
        if not isinstance(value, dict) or value.get('schema_version') != 1:
            raise ValueError('support_dependency_recovery_required')
        if not isinstance(value.get('operation_id'),str) or not re.fullmatch('[0-9a-f]{32}',value['operation_id']):
            raise ValueError('support_dependency_recovery_required')
        self._metadata=value
        return value

    def write_receipt(self, value):
        from .support_access_native import atomic_write, WindowsSupportOps
        if value['state']=='servicing':
            from uuid import uuid4
            boot=self.boot_state()
            if boot.get('pending') or not isinstance(boot.get('boot_id'),str):
                raise ValueError('support_dependency_reboot_required')
            operation=uuid4().hex
            self._metadata={'operation_id':operation,'boot_id':boot['boot_id'],
                'firewall_reservation_name':'OpenSSH-Server-In-TCP',
                'firewall_reservation_description':'Endpoint Support OpenSSH preparation '+operation}
        if self._metadata is None:raise ValueError('support_dependency_recovery_required')
        result=dict(self._metadata,**value)
        atomic_write(self.path, json.dumps(result, sort_keys=True))
        self._metadata=result
        WindowsSupportOps().protect(self.path)

    def install(self, names):
        if not names or any(name not in CAPABILITIES for name in names):
            raise ValueError('support_dependency_install_failed')
        # PowerShell owns the entire fixed servicing interval. No timeout-based
        # success inference, uninstall, WSUS/GPO change or alternate download.
        return run_fixed_powershell(r'''
$names=@($env:ENDPOINT_SUPPORT_FOD_NAMES|ConvertFrom-Json)
if(!$names.Count -or @($names|Where-Object {$_ -notin @('OpenSSH.Client~~~~0.0.1.0','OpenSSH.Server~~~~0.0.1.0')}).Count){throw 'names'}
if($env:ENDPOINT_SUPPORT_FOD_OPERATION -cnotmatch '^[0-9a-f]{32}$'){throw 'operation'}
function ServiceState {Get-CimInstance Win32_Service -Filter "Name='sshd'" | Select-Object Name,State,StartMode,PathName,StartName,ProcessId | ConvertTo-Json -Compress}
function Properties {param($object);$out=[ordered]@{};foreach($p in ($object.CimInstanceProperties|Sort-Object Name)){$out[$p.Name]=$p.Value};return $out}
function RuleState {param($rules);if(!$rules){return $null};if(@($rules).Count -ne 1){throw 'multiple rules'};$rule=@($rules)[0];@{rule=(Properties $rule);port=(Properties ($rule|Get-NetFirewallPortFilter));address=(Properties ($rule|Get-NetFirewallAddressFilter));app=(Properties ($rule|Get-NetFirewallApplicationFilter));service=(Properties ($rule|Get-NetFirewallServiceFilter));security=(Properties ($rule|Get-NetFirewallSecurityFilter));interface=(Properties ($rule|Get-NetFirewallInterfaceFilter));interface_type=(Properties ($rule|Get-NetFirewallInterfaceTypeFilter))}|ConvertTo-Json -Depth 12 -Compress}
$service=ServiceState;$rule=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
if($rule.Count -gt 1){throw 'rule'}
$before=RuleState $rule;$owned=$null;$ok=$true;$restart=$false;$preserved=$true
if(!$rule.Count){
 # Reserve the default name with our durable operation nonce BEFORE servicing.
 # Absence followed by a default-shaped rule never establishes ownership.
 $description='Endpoint Support OpenSSH preparation '+$env:ENDPOINT_SUPPORT_FOD_OPERATION
 try {
  $created=New-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -DisplayName 'Endpoint Support OpenSSH preparation' -Description $description -Enabled False -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort 22 -Program (Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\sshd.exe') -ErrorAction Stop
  $reserved=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP')
  if($reserved.Count -ne 1 -or $reserved[0].Description -cne $description -or (RuleState $reserved) -cne (RuleState @($created))){throw 'reservation conflict'}
  $owned=RuleState $reserved
 } catch {@{completed=$false;restart_needed=$false;boundary_preserved=$false}|ConvertTo-Json -Compress;exit 0}
}
try {foreach($name in $names){$r=Add-WindowsCapability -Online -Name $name -ErrorAction Stop;$restart=$restart -or [bool]$r.RestartNeeded}}
catch {$ok=$false}
$after=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
if($owned){
 if($after.Count -ne 1 -or $after[0].Description -cne $description -or (RuleState $after) -cne $owned){$preserved=$false}
 else {
  $again=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP')
  if((RuleState $again) -cne $owned){$preserved=$false}
  else {try {$again|Remove-NetFirewallRule -ErrorAction Stop;if(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue){$preserved=$false}}catch {$preserved=$false}}
 }
} elseif((RuleState $after) -cne $before){$preserved=$false}
$now=ServiceState
if($service){if($now -cne $service){$preserved=$false}}
elseif($now){$created=$now|ConvertFrom-Json;if($created.State -ne 'Stopped' -or $created.StartMode -ne 'Manual'){$preserved=$false}}
@{completed=[bool]$ok;restart_needed=[bool]$restart;boundary_preserved=[bool]$preserved}|ConvertTo-Json -Compress
''', variables={'ENDPOINT_SUPPORT_FOD_NAMES': json.dumps(list(names)),
               'ENDPOINT_SUPPORT_FOD_OPERATION': self._metadata['operation_id']}, timeout=540)

    def verify(self):
        return signed_os_dependencies()
