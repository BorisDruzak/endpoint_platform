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
import stat
import subprocess

PROFILE = 'windows-openssh-fod-v1'
CAPABILITIES = ('OpenSSH.Client~~~~0.0.1.0', 'OpenSSH.Server~~~~0.0.1.0')
ROLES = {'ssh': 'ssh.exe', 'sshd': 'sshd.exe', 'keygen': 'ssh-keygen.exe'}

# Exact local PersistentStore snapshots observed after OpenSSH Server FoD Add.
# Unknown fields and alternate defaults fail closed. Only localized Status text
# may differ from the captured template. The independent fixture is
# the captured stock rule, including every associated CIM filter.
_STOCK_RULE_ID = 'OpenSSH-Server-In-TCP'
_STOCK_CIM_KEYS = {
    'CreationClassName': 'MSFT|FW|FirewallRule|' + _STOCK_RULE_ID,
    'InstanceID': _STOCK_RULE_ID, 'SystemCreationClassName': '', 'SystemName': '',
}
_STOCK_FILTER_KEYS = dict.fromkeys((
    'Caption', 'CommunicationStatus', 'Description', 'DetailedStatus', 'HealthState',
    'InstallDate', 'IsNegated', 'OperatingStatus', 'OperationalStatus',
    'PrimaryStatus', 'Status', 'StatusDescriptions',
)) | _STOCK_CIM_KEYS | {'ElementName': '', 'Name': ''}
_STOCK_RULE = {
    'rule': _STOCK_CIM_KEYS | {
        'Action': 2, 'Caption': None, 'CommonName': None, 'ConditionListType': 3,
        'Description': 'Inbound rule for OpenSSH SSH Server (sshd)', 'Direction': 1,
        'DisplayGroup': 'OpenSSH Server', 'DisplayName': 'OpenSSH SSH Server (sshd)',
        'EdgeTraversalPolicy': 0, 'ElementName': 'OpenSSH SSH Server (sshd)', 'Enabled': 1,
        'EnforcementStatus': [0], 'ExecutionStrategy': 2, 'LocalOnlyMapping': False,
        'LooseSourceMapping': False, 'Mandatory': None, 'Owner': None,
        'PackageFamilyName': None, 'Platforms': [], 'PolicyAppId': None,
        'PolicyDecisionStrategy': 2, 'PolicyKeywords': None, 'PolicyRoles': None,
        'PolicyRuleName': '', 'PolicyStoreSource': 'PersistentStore', 'PolicyStoreSourceType': 1,
        'PrimaryStatus': 1, 'Priority': None, 'Profiles': 2, 'RemoteDynamicKeywordAddresses': [],
        'RuleGroup': 'OpenSSH Server', 'RuleUsage': None, 'SequencedActions': 3,
        'Status': 'The rule was parsed successfully from the store.', 'StatusCode': 65536,
    },
    'port': _STOCK_FILTER_KEYS | {
        'DynamicTransport': 0, 'IcmpType': None, 'LocalPort': ['22'], 'Protocol': 'TCP', 'RemotePort': None,
    },
    'address': _STOCK_FILTER_KEYS | {'LocalAddress': None, 'RemoteAddress': None},
    'app': _STOCK_FILTER_KEYS | {'AppPath': r'%SystemRoot%\system32\OpenSSH\sshd.exe', 'Package': None},
    'service': _STOCK_FILTER_KEYS | {'ServiceName': None},
    'security': _STOCK_FILTER_KEYS | {
        'Authentication': 0, 'Encryption': 0, 'LocalUsers': None, 'OverrideBlockRules': False,
        'RemoteMachines': None, 'RemoteUsers': None,
    },
    'interface': _STOCK_FILTER_KEYS | {'InterfaceAlias': None},
    'interface_type': _STOCK_FILTER_KEYS | {'InterfaceType': 0},
}

# Windows 10 build 19045 returns this combination as a single stock shape.
_STOCK_RULE_WIN10 = _STOCK_RULE | {'rule': {
    key: value for key, value in _STOCK_RULE['rule'].items() if key != 'PackageFamilyName'
} | {'Profiles': 0, 'RemoteDynamicKeywordAddresses': None}}
_STOCK_RULES = (_STOCK_RULE, _STOCK_RULE_WIN10)



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
    adopting = bool(previous and previous.get('schema_version') == 2 and previous.get('state') == 'servicing')
    if previous and previous.get('state') not in {'complete', 'failed'} and not adopting:
        # File presence cannot settle a killed DISM/TrustedInstaller operation.
        raise ValueError('support_dependency_recovery_required')
    if not missing and not adopting:
        return ops.verify()
    receipt = previous if adopting else {'schema_version': 2, 'state': 'servicing', 'capabilities': list(missing)}
    if not adopting:
        ops.write_receipt(receipt)
    try:
        result = ops.completed_operation(previous) if adopting else ops.install(missing)
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


def run_fixed_powershell(script, *, variables=None, timeout=60, durable=False):
    from .support_access_native import windows_root
    system = windows_root() / 'System32'
    environment = {k:v for k,v in os.environ.items() if k.casefold() != 'psmodulepath'}
    environment['PSModulePath'] = str(system/'WindowsPowerShell/v1.0/Modules')
    environment.update(variables or {})
    prefix = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
    command = [str(system/'WindowsPowerShell/v1.0/powershell.exe'),
        '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
        base64.b64encode((prefix+script).encode('utf-16-le')).decode()]
    if durable:
        # No inherited pipes, console or caller-owned kill-on-close Job. If the
        # containing Job forbids breakaway CreateProcess fails before servicing.
        import win32api, win32con, win32event, win32job, win32process
        process, thread, _, _ = win32process.CreateProcess(None, subprocess.list2cmdline(command),
            None, None, False, win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW |
            subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_BREAKAWAY_FROM_JOB,
            environment, None, win32process.STARTUPINFO())
        started = False
        try:
            # Nested Jobs can leave a child in a restrictive inner Job even
            # when the outer Job allowed breakaway. Check before ANY code runs.
            if win32job.IsProcessInJob(process, None):
                raise ValueError('support_dependency_recovery_required')
            win32process.ResumeThread(thread)
            started = True
            win32event.WaitForSingleObject(process, win32event.INFINITE)
            if win32process.GetExitCodeProcess(process) != 0:
                raise ValueError('support_dependency_recovery_required')
        finally:
            if not started:
                win32process.TerminateProcess(process, 1)
            win32api.CloseHandle(thread)
            win32api.CloseHandle(process)
        return None
    result = subprocess.run(command,
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
    from .support_access_native import windows_root, TRUSTED_SIDS
    import win32security as security
    root = windows_root()/'System32'/'OpenSSH'
    if path != root and path.parent != root:
        raise ValueError('support_dependency_changed')
    installer = security.ConvertSidToStringSid(security.LookupAccountName(None, r'NT SERVICE\TrustedInstaller')[0])
    trusted = set(TRUSTED_SIDS) | {installer}
    # Include parents: replacing a protected leaf through a writable parent is unsafe.
    for current in (windows_root(), windows_root()/'System32', root, path):
        # Serviced Windows files are hardlinked to WinSxS. Their shared inode
        # has the same protected owner/DACL; only redirection is forbidden here.
        # Private Endpoint identity files retain their stricter single-link rule.
        for item in (*reversed(current.parents), current):
            info=item.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
                raise ValueError('support_dependency_signature_invalid')
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
        if not isinstance(value, dict) or value.get('schema_version') not in (1, 2):
            raise ValueError('support_dependency_recovery_required')
        if not isinstance(value.get('operation_id'),str) or not re.fullmatch('[0-9a-f]{32}',value['operation_id']):
            raise ValueError('support_dependency_recovery_required')
        self._metadata=value
        return value

    def write_receipt(self, value):
        from .support_access_native import atomic_write, WindowsSupportOps
        if value['state']=='servicing' and 'operation_id' not in value:
            from uuid import uuid4
            boot=self.boot_state()
            if boot.get('pending') or not isinstance(boot.get('boot_id'),str):
                raise ValueError('support_dependency_reboot_required')
            operation=uuid4().hex
            self._metadata={'operation_id':operation,'nonce':uuid4().hex,'boot_id':boot['boot_id'],
                'firewall_reservation_name':'OpenSSH-Server-In-TCP',
                'firewall_reservation_description':'Endpoint Support OpenSSH preparation '+operation}
        if self._metadata is None:raise ValueError('support_dependency_recovery_required')
        result=dict(self._metadata,**value)
        atomic_write(self.path, json.dumps(result, sort_keys=True))
        self._metadata=result
        WindowsSupportOps().protect(self.path)

    def operation_root(self, receipt):
        from .support_access_native import assert_private
        if (receipt.get('schema_version') != 2 or
                any(not isinstance(receipt.get(k), str) or not re.fullmatch('[0-9a-f]{32}', receipt[k])
                    for k in ('operation_id', 'nonce')) or
                not isinstance(receipt.get('boot_id'), str) or
                not isinstance(receipt.get('capabilities'), list) or
                not receipt['capabilities'] or
                receipt['capabilities'] != [n for n in CAPABILITIES if n in receipt['capabilities']]):
            raise ValueError('support_dependency_recovery_required')
        assert_private(self.root)
        return self.root/('os-servicing-'+receipt['operation_id'])

    def completed_operation(self, receipt):
        """Only the exact protected worker proof can settle a lost caller."""
        from .support_access_native import assert_private
        import win32file, win32con
        try:
            root = self.operation_root(receipt)
            assert_private(root)
            lock = root/'worker.lock'
            assert_private(lock)
            # An orphan may publish then still own its cleanup interval.
            handle = win32file.CreateFile(str(lock), win32con.GENERIC_READ, 0, None,
                win32con.OPEN_EXISTING, 0x00200000, None)
            try:
                def read_record(name):
                    path = root/name
                    assert_private(path)
                    if path.stat().st_size > 65536:raise ValueError()
                    return path.read_bytes()
                baseline_raw = read_record('baseline.json')
                proof_raw = read_record('completion.json')
                baseline, proof = json.loads(baseline_raw), json.loads(proof_raw)
                request = {k:receipt[k] for k in ('schema_version','operation_id','nonce','boot_id','capabilities')}
                proof_fields = {'request','baseline_sha256','result'}
                if (set(baseline) != {'request','service','rule'} or baseline['request'] != request or
                        set(proof) not in (proof_fields, proof_fields | {'normalization_sha256'}) or
                        proof['request'] != request or
                        proof['baseline_sha256'] != hashlib.sha256(baseline_raw).hexdigest() or
                        not isinstance(proof['result'],dict) or set(proof['result']) !=
                        {'completed','restart_needed','boundary_preserved'} or
                        any(type(v) is not bool for v in proof['result'].values())):
                    raise ValueError()
                if 'normalization_sha256' in proof:
                    intent_raw = read_record('normalization-intent.json')
                    normalized_raw = read_record('normalization-proof.json')
                    self._verify_normalization(baseline, proof, intent_raw, normalized_raw)
                elif proof['result']['boundary_preserved'] and (root/'normalization-intent.json').exists():
                    raise ValueError()
                return proof['result']
            finally:handle.Close()
        except Exception:
            raise ValueError('support_dependency_recovery_required') from None

    @staticmethod
    def _verify_normalization(baseline, completion, intent_raw, normalized_raw):
        from .support_access_native import windows_root
        intent, normalized = json.loads(intent_raw), json.loads(normalized_raw)
        binding = {key:completion[key] for key in ('request','baseline_sha256')}
        original = json.loads(intent['rule'])
        status = original['rule']['Status']
        original_json = json.dumps(original, sort_keys=True)
        stock_match = any(
            original_json == json.dumps(stock | {'rule': stock['rule'] | {'Status': status}}, sort_keys=True)
            for stock in _STOCK_RULES
        )
        disabled = original | {'rule': original['rule'] | {'Enabled': 2}}
        service = json.loads(intent['service'])
        native_service = {'Name':'sshd','State':'Stopped','StartMode':'Manual','StartName':'LocalSystem',
            'ProcessId':0,'PathName':str(windows_root()/'System32'/'OpenSSH'/'sshd.exe').casefold()}
        service['PathName'] = service['PathName'].casefold()
        if (baseline['service'] is not None or baseline['rule'] is not None or
                CAPABILITIES[1] not in binding['request']['capabilities'] or
                not completion['result']['completed'] or completion['result']['restart_needed'] or
                set(intent) != set(binding) | {'service','rule'} or
                set(normalized) != set(binding) | {'service','rule','intent_sha256'} or
                any(record.get(key) != value for record in (intent,normalized) for key,value in binding.items()) or
                service != native_service or normalized['service'] != intent['service'] or
                not isinstance(status, str) or not status or not stock_match or
                json.dumps(json.loads(normalized['rule']), sort_keys=True) != json.dumps(disabled, sort_keys=True) or
                normalized['intent_sha256'] != hashlib.sha256(intent_raw).hexdigest() or
                completion['normalization_sha256'] != hashlib.sha256(normalized_raw).hexdigest()):
            raise ValueError('support_dependency_recovery_required')

    def install(self, names):
        if not names or any(name not in CAPABILITIES for name in names):
            raise ValueError('support_dependency_install_failed')
        # PowerShell owns the entire fixed servicing interval. No timeout-based
        # success inference, uninstall, WSUS/GPO change or alternate download.
        from .support_access_native import WindowsSupportOps
        root = self.operation_root(self._metadata)
        if list(names) != self._metadata['capabilities'] or root.exists():
            raise ValueError('support_dependency_recovery_required')
        WindowsSupportOps().protect(root)
        run_fixed_powershell(r'''
$names=ConvertFrom-Json -InputObject $env:ENDPOINT_SUPPORT_FOD_NAMES
if(!$names.Count -or @($names|Where-Object {$_ -notin @('OpenSSH.Client~~~~0.0.1.0','OpenSSH.Server~~~~0.0.1.0')}).Count){throw 'names'}
if($env:ENDPOINT_SUPPORT_FOD_OPERATION -cnotmatch '^[0-9a-f]{32}$'){throw 'operation'}
$root=$env:ENDPOINT_SUPPORT_FOD_ROOT
$request=ConvertFrom-Json -InputObject $env:ENDPOINT_SUPPORT_FOD_REQUEST
function ProtectFile {param($path);$acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)');[IO.File]::SetAccessControl($path,$acl)}
function Persist {param($name,$value)
 $path=Join-Path $root $name;$temporary=$path+'.new'
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $value -Depth 16 -Compress))
 $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 ProtectFile $temporary;[IO.File]::Move($temporary,$path)
}
$lock=[IO.File]::Open((Join-Path $root 'worker.lock'),[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
 ProtectFile (Join-Path $root 'worker.lock')
function ServiceState {
 $services=@(Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop)
 if(!$services.Count){return $null}
 if($services.Count -ne 1){throw 'multiple services'}
 $services[0] | Select-Object Name,State,StartMode,PathName,StartName,ProcessId | ConvertTo-Json -Compress
}
function ReadDefaultRule {
 try {Get-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop}
 catch {if($_.FullyQualifiedErrorId -cne 'CmdletizationQuery_NotFound_InstanceID,Get-NetFirewallRule'){throw}}
}
function Properties {
 param($object)
 if(@($object).Count -ne 1){throw 'unexpected firewall filter count'}
 $out=[ordered]@{}
 foreach($p in ($object.CimInstanceProperties|Sort-Object Name)){$out[$p.Name]=$p.Value}
 return $out
}
function RuleState {param($rules);if(!$rules){return $null};if(@($rules).Count -ne 1){throw 'multiple rules'};$rule=@($rules)[0];@{rule=(Properties $rule);port=(Properties ($rule|Get-NetFirewallPortFilter));address=(Properties ($rule|Get-NetFirewallAddressFilter));app=(Properties ($rule|Get-NetFirewallApplicationFilter));service=(Properties ($rule|Get-NetFirewallServiceFilter));security=(Properties ($rule|Get-NetFirewallSecurityFilter));interface=(Properties ($rule|Get-NetFirewallInterfaceFilter));interface_type=(Properties ($rule|Get-NetFirewallInterfaceTypeFilter))}|ConvertTo-Json -Depth 12 -Compress}
$service=ServiceState;$rule=@(ReadDefaultRule)
if($rule.Count -gt 1){throw 'rule'}
$before=RuleState $rule;$owned=$null;$ok=$true;$restart=$false;$preserved=$true
Persist 'baseline.json' @{request=$request;service=$service;rule=$before}
$baseline=(Get-FileHash -LiteralPath (Join-Path $root 'baseline.json') -Algorithm SHA256).Hash.ToLowerInvariant()
function Complete {param($result,$normalization)
 $record=@{request=$request;baseline_sha256=$baseline;result=$result}
 if($normalization){$record.normalization_sha256=$normalization}
 Persist 'completion.json' $record
}
function MatchesStockRule {param($actual,$stock)
 foreach($section in $stock.PSObject.Properties){
  $fields=@($actual.($section.Name).PSObject.Properties)
  if($fields.Count -ne @($section.Value.PSObject.Properties).Count){return $false}
  foreach($field in $section.Value.PSObject.Properties){
   $observed=$actual.($section.Name).PSObject.Properties[$field.Name]
   if(!$observed -or $observed.Name -cne $field.Name){return $false}
   if($section.Name -ceq 'rule' -and $field.Name -ceq 'Status'){
    if($observed.Value -isnot [string] -or !$observed.Value){return $false}
    continue
   }
   if((ConvertTo-Json -InputObject $observed.Value -Compress) -cne
      (ConvertTo-Json -InputObject $field.Value -Compress)){return $false}
  }
 }
 return $true
}
function IsStockRule {param($snapshot)
 $actual=ConvertFrom-Json -InputObject $snapshot
 foreach($stock in (ConvertFrom-Json -InputObject $env:ENDPOINT_SUPPORT_FOD_STOCK_RULES)){
  if(MatchesStockRule $actual $stock){return $true}
 }
 return $false
}
function RestartPending {
 (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
 (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
}
$serverName='OpenSSH.Server~~~~0.0.1.0'
function ServerIs {param($state)
 $cap=@(Get-WindowsCapability -Online -Name $serverName -ErrorAction Stop)
 $cap.Count -eq 1 -and $cap[0].Name -ceq $serverName -and [string]$cap[0].State -ceq $state
}
function NormalizeStockRule {param($snapshot,$nativeService)
 if(!$nativeService -or !(IsStockRule $snapshot) -or !(ServerIs 'Installed') -or (RestartPending)){return}
 $sshd=ConvertFrom-Json -InputObject $nativeService
 $expectedPath=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\sshd.exe'
 if($sshd.Name -cne 'sshd' -or $sshd.State -cne 'Stopped' -or $sshd.StartMode -cne 'Manual' -or
    $sshd.PathName -ine $expectedPath -or $sshd.StartName -cne 'LocalSystem' -or $sshd.ProcessId -ne 0){return}
 Persist 'normalization-intent.json' @{request=$request;baseline_sha256=$baseline;service=$nativeService;rule=$snapshot}
 $intent=(Get-FileHash -LiteralPath (Join-Path $root 'normalization-intent.json') -Algorithm SHA256).Hash.ToLowerInvariant()
 if((RestartPending) -or (ServiceState) -cne $nativeService){return}
 $fresh=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop)
 if($fresh.Count -ne 1 -or (RuleState $fresh) -cne $snapshot){return}
 Disable-NetFirewallRule -InputObject $fresh[0] -Confirm:$false -ErrorAction Stop
 $afterDisable=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop)
 if($afterDisable.Count -ne 1){return}
 $disabled=RuleState $afterDisable
 $expected=ConvertFrom-Json -InputObject $snapshot
 $expected.rule.Enabled=2
 if($disabled -cne (ConvertTo-Json -InputObject $expected -Depth 12 -Compress) -or (ServiceState) -cne $nativeService){return}
 Persist 'normalization-proof.json' @{request=$request;baseline_sha256=$baseline;intent_sha256=$intent;service=$nativeService;rule=$disabled}
 (Get-FileHash -LiteralPath (Join-Path $root 'normalization-proof.json') -Algorithm SHA256).Hash.ToLowerInvariant()
}
if($service -and 'OpenSSH.Server~~~~0.0.1.0' -in $names){
 $existing=$service|ConvertFrom-Json
 $expected=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\sshd.exe'
 if($existing.PathName -ine $expected -and $existing.PathName -ine ('"'+$expected+'"')){
  # A missing OS Server capability cannot authorize replacing a foreign global
  # sshd service. Keep its process/configuration and the old Support untouched.
  Complete @{completed=$false;restart_needed=$false;boundary_preserved=$true};return
 }
}
if(!$rule.Count){
 # Reserve the default name with our durable operation nonce BEFORE servicing.
 # Absence followed by a default-shaped rule never establishes ownership.
 $description='Endpoint Support OpenSSH preparation '+$env:ENDPOINT_SUPPORT_FOD_OPERATION
 try {
  $created=New-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -DisplayName 'Endpoint Support OpenSSH preparation' -Description $description -Enabled False -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort 22 -Program (Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\sshd.exe') -ErrorAction Stop
  $reserved=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP')
  if($reserved.Count -ne 1 -or $reserved[0].Description -cne $description -or (RuleState $reserved) -cne (RuleState @($created))){throw 'reservation conflict'}
  $owned=RuleState $reserved
  Persist 'reservation.json' @{request=$request;baseline_sha256=$baseline;rule=$owned}
 } catch {Complete @{completed=$false;restart_needed=$false;boundary_preserved=$false};return}
}
$serverAdded=$false
try {
 foreach($name in $names){
  $stockCandidate=$name -ceq $serverName -and !$service -and !$before
  if($stockCandidate -and !(ServerIs 'NotPresent')){throw 'Server capability source changed'}
  $r=@(Add-WindowsCapability -Online -Name $name -ErrorAction Stop)
  $restart=$restart -or [bool]$r.RestartNeeded
  if($stockCandidate){$serverAdded=$r.Count -eq 1 -and $r[0].RestartNeeded -is [bool] -and !$r[0].RestartNeeded}
 }
} catch {$ok=$false}
$after=@(ReadDefaultRule)
$normalization=$null
if($owned){
 if($after.Count -ne 1 -or $after[0].Description -cne $description -or (RuleState $after) -cne $owned){
  $preserved=$false
  if($ok -and !$restart -and $serverAdded -and $after.Count -eq 1){
   try {
    $normalization=NormalizeStockRule (RuleState $after) (ServiceState)
    $preserved=[bool]$normalization
   } catch {$preserved=$false}
  }
 }
 else {
  $again=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP')
  if((RuleState $again) -cne $owned){$preserved=$false}
  else {try {$again|Remove-NetFirewallRule -ErrorAction Stop;if(ReadDefaultRule){$preserved=$false}}catch {$preserved=$false}}
 }
} elseif((RuleState $after) -cne $before){$preserved=$false}
$now=ServiceState
if($service){if($now -cne $service){$preserved=$false}}
elseif($now){$created=$now|ConvertFrom-Json;if($created.State -ne 'Stopped' -or $created.StartMode -ne 'Manual'){$preserved=$false}}
Complete @{completed=[bool]$ok;restart_needed=[bool]$restart;boundary_preserved=[bool]$preserved} $normalization
} finally {$lock.Dispose()}
''', variables={'ENDPOINT_SUPPORT_FOD_NAMES': json.dumps(list(names)),
               'ENDPOINT_SUPPORT_FOD_OPERATION': self._metadata['operation_id'],
               'ENDPOINT_SUPPORT_FOD_ROOT': str(root),
               'ENDPOINT_SUPPORT_FOD_STOCK_RULES': json.dumps(_STOCK_RULES),
               'ENDPOINT_SUPPORT_FOD_REQUEST': json.dumps({k:self._metadata[k] for k in
                   ('schema_version','operation_id','nonce','boot_id','capabilities')})}, timeout=None, durable=True)
        return self.completed_operation(self._metadata)

    def verify(self):
        return signed_os_dependencies()
