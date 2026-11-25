"""Provision and retire the source-bound signed observer for native Setup.

Provisioning stays in the authenticated accepted-native continuation. Final
uninstall cleanup holds the installer exclusion and probes the fixed Observer
mutex without waiting. Neither path invokes the Observer.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import subprocess
import stat
import sys

from endpoint_contracts.runtime_payload import read_json
from . import durable_state, installer_fence as fence
from .authenticode_timestamp import has_verified_timestamp
from .setup_update_bootstrap import system_powershell
from .scheduled_task import find_task

_LIMIT = 2 * 1024 * 1024
_TASK_NAME = 'EndpointSetupUpdater'
_MUTEX_NAME = r'Global\EndpointSetupUpdater-v1'
_MUTEX_FULL_CONTROL = 0x1F0001
_MUTEX_SDDL = 'O:BAG:BAD:P(A;;0x1f0001;;;SY)(A;;0x1f0001;;;BA)'
_SDDL = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
_PUBLISHER = '4D4C23389F5FF77BC4EB32044761019EAE8FB776'
_POWERSHELL_TIMESTAMP_UNAVAILABLE = 22


def _fail():
    raise ValueError('RECOVERY_REQUIRED')


def read_packaged_observer(root):
    root = Path(root)
    asset = root / 'EndpointSetupUpdater.ps1'
    manifest = read_json((root / 'EndpointSetupUpdater.payload.json').read_bytes(), 4096)
    if (not isinstance(manifest, dict) or set(manifest) != {'schema_version', 'client_version', 'script_sha256', 'source_sha256'}
            or type(manifest['schema_version']) is not int or manifest['schema_version'] != 1
            or not isinstance(manifest['client_version'], str)
            or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', manifest['client_version'])
            or any(not isinstance(manifest[key], str) or not re.fullmatch('[0-9a-f]{64}', manifest[key])
                   for key in ('script_sha256', 'source_sha256'))):
        _fail()
    if asset.stat().st_size > _LIMIT:
        _fail()
    raw = asset.read_bytes()
    signed = raw.decode('utf-8-sig').replace('\r\n', '\n')
    source, marker, signature = signed.partition('# SIG # Begin signature block')
    if (hashlib.sha256(raw).hexdigest() != manifest['script_sha256'] or not marker
            or '# SIG # End signature block' not in signature
            or hashlib.sha256(source.rstrip().encode('utf-8')).hexdigest() != manifest['source_sha256']
            or "\n$script:ClientVersion='" + manifest['client_version'] + "'\n" not in '\n' + source):
        _fail()
    return asset, raw, manifest


def _verify_signature(asset):
    result = _check_signature_and_trust_publisher(asset)
    if result == _POWERSHELL_TIMESTAMP_UNAVAILABLE and has_verified_timestamp(asset, _PUBLISHER):
        result = _check_signature_and_trust_publisher(asset, native_timestamp=True)
    if result != 0:
        _fail()


def _check_signature_and_trust_publisher(asset, *, native_timestamp=False):
    literal = str(asset).replace("'", "''")
    require_powershell_timestamp = '$false' if native_timestamp else '$true'
    code = f"""$ErrorActionPreference='Stop'
$s=Get-AuthenticodeSignature -LiteralPath '{literal}'
if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -cne '{_PUBLISHER}'){{exit 21}}
if({require_powershell_timestamp} -and !$s.TimeStamperCertificate){{exit {_POWERSHELL_TIMESTAMP_UNAVAILABLE}}}
$store=[Security.Cryptography.X509Certificates.X509Store]::new('TrustedPublisher','LocalMachine')
try{{$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);if(!$store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$s.SignerCertificate.Thumbprint,$false).Count){{$store.Add($s.SignerCertificate)}}}}finally{{$store.Close()}}
"""
    result = subprocess.run([str(system_powershell()), '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden',
        '-ExecutionPolicy', 'AllSigned', '-EncodedCommand', base64.b64encode(code.encode('utf-16-le')).decode('ascii')],
        shell=False, timeout=30, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=0x08000000)
    return result.returncode


def _administrative_directory(parent, name):
    path = parent / name
    fence.assert_namespace_security(parent, include_self=True)
    if not path.exists():
        durable_state.installer_mutation_checkpoint(required=True)
        path.mkdir()
        fence.protect_state(path, secret=True)
    fence.assert_state_security(path, secret=True)
    fence.assert_namespace_security(path, include_self=True)
    if not path.is_dir():
        _fail()
    return path


def _assert_administrative_file(path):
    """Existing Core-installed clients inherit their protected directory ACL.

    Their immutable signed file need not have a protected leaf DACL. Require
    the same administrative writers and secure containing namespace instead.
    """
    import win32security
    fence.assert_namespace_security(path)
    details = path.lstat()
    if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
            or getattr(details, 'st_file_attributes', 0) & 0x400 or details.st_size > _LIMIT):
        _fail()
    security = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
    owner, acl = security.GetSecurityDescriptorOwner(), security.GetSecurityDescriptorDacl()
    admins = {'S-1-5-18', 'S-1-5-32-544'}
    if owner is None or acl is None or win32security.ConvertSidToStringSid(owner) not in admins:
        _fail()
    for index in range(acl.GetAceCount()):
        kind, mask, sid = acl.GetAce(index)
        if kind[0] != 0 or win32security.ConvertSidToStringSid(sid) not in admins:
            _fail()


def _verify_task(task, target, powershell, *, allow_disabled=False):
    import win32security
    definition = task.Definition
    principal = definition.Principal
    sid = (win32security.ConvertStringSidToSid(principal.UserId) if principal.UserId.startswith('S-1-')
           else win32security.LookupAccountName(None, principal.UserId)[0])
    if (win32security.ConvertSidToStringSid(sid) != 'S-1-5-18' or principal.LogonType != 5
            or principal.RunLevel != 1 or definition.Actions.Count != 1 or definition.Triggers.Count != 2):
        _fail()
    settings = definition.Settings
    if ((not allow_disabled and not settings.Enabled)
            or settings.MultipleInstances != 2 or settings.ExecutionTimeLimit != 'PT0S'
            or not settings.StartWhenAvailable or settings.DisallowStartIfOnBatteries or settings.StopIfGoingOnBatteries):
        _fail()
    for index in (1, 2):
        trigger = definition.Triggers.Item(index)
        if not trigger.Enabled or (trigger.Type == 1 and trigger.Repetition.Interval != 'PT1M'):
            _fail()
    action = definition.Actions.Item(1)
    if (action.Type != 0 or action.Path != str(powershell) or action.Arguments != _arguments(target)
            or action.WorkingDirectory or sorted(definition.Triggers.Item(i).Type for i in (1, 2)) != [1, 9]):
        _fail()
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(task.GetSecurityDescriptor(7), 1)
    dacl = descriptor.GetSecurityDescriptorDacl()
    owner = descriptor.GetSecurityDescriptorOwner()
    if dacl is None or owner is None or win32security.ConvertSidToStringSid(owner) not in {'S-1-5-18', 'S-1-5-32-544'}:
        _fail()
    for index in range(dacl.GetAceCount()):
        kind, mask, sid = dacl.GetAce(index)
        if kind[0] != 0 or win32security.ConvertSidToStringSid(sid) not in {'S-1-5-18', 'S-1-5-32-544'}:
            _fail()


def _arguments(target):
    return '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy AllSigned -File "' + str(target) + '" -Mode Run'


def _register_observer(target):
    import win32com.client
    scheduler = win32com.client.Dispatch('Schedule.Service'); scheduler.Connect()
    folder = scheduler.GetFolder('\\')
    definition = scheduler.NewTask(0)
    definition.Principal.UserId = 'SYSTEM'
    definition.Principal.LogonType = 5
    definition.Principal.RunLevel = 1
    definition.RegistrationInfo.Description = 'Endpoint Platform authenticated full Setup updates and user-session continuity'
    settings = definition.Settings
    settings.Enabled = True
    settings.ExecutionTimeLimit = 'PT0S'
    settings.MultipleInstances = 2  # IgnoreNew
    settings.StartWhenAvailable = True
    settings.DisallowStartIfOnBatteries = False
    settings.StopIfGoingOnBatteries = False
    trigger = definition.Triggers.Create(1)
    trigger.StartBoundary = (datetime.now().astimezone() + timedelta(seconds=15)).isoformat(timespec='seconds')
    trigger.Repetition.Interval = 'PT1M'
    definition.Triggers.Create(9)
    powershell = system_powershell()
    action = definition.Actions.Create(0)
    action.Path = str(powershell)
    action.Arguments = _arguments(target)
    durable_state.installer_mutation_checkpoint(required=True)
    task = folder.RegisterTaskDefinition(_TASK_NAME, definition, 6, 'SYSTEM', None, 5, _SDDL)
    _verify_task(task, target, powershell)


def provision_packaged_observer(paths):
    from .update_paths import WindowsUpdatePaths
    if not getattr(sys, 'frozen', False) or paths != WindowsUpdatePaths.production():
        _fail()
    root = Path(sys._MEIPASS) / 'setup-updater'
    asset = root / 'EndpointSetupUpdater.ps1'
    with durable_state._pinned_copy_source(asset):
        asset, raw, metadata = read_packaged_observer(root)
        durable_state.installer_mutation_checkpoint(required=True)
        _verify_signature(asset)
        client_root = _administrative_directory(paths.install_root.parent.parent, 'EndpointPlatformSetupUpdater')
        state_root = _administrative_directory(paths.updates_root.parent.parent.parent, 'EndpointPlatformSetupUpdates')
        version_root = _administrative_directory(client_root, metadata['client_version'])
        target = version_root / 'EndpointSetupUpdater.ps1'
        if target.exists():
            _assert_administrative_file(target)
            if target.read_bytes() != raw:
                _fail()
        else:
            durable_state.write_bytes_atomic(target, raw, trusted_root=version_root, max_bytes=_LIMIT,
                protect=lambda path: fence.protect_state(path, secret=True))
        with durable_state._pinned_copy_source(target):
            _verify_signature(target)
            _register_observer(target)
            durable_state.write_json_atomic(state_root / 'client.json',
                {'client_version': metadata['client_version'], 'script_sha256': metadata['script_sha256'],
                 'installed_at': datetime.now(timezone.utc).isoformat()},
                trusted_root=state_root, max_bytes=4096, protect=lambda path: fence.protect_state(path, secret=True))
    return 'provisioned'

def _scheduler_folder():
    from win32com.client import Dispatch

    scheduler = Dispatch('Schedule.Service')
    scheduler.Connect()
    return scheduler.GetFolder('\\')


@contextmanager
def _observer_mutex():
    import pywintypes
    import win32event
    import win32security

    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(_MUTEX_SDDL, 1)
    handle = win32event.CreateMutex(attributes, False, _MUTEX_NAME)
    acquired = False
    try:
        descriptor = win32security.GetSecurityInfo(
            handle, win32security.SE_KERNEL_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
        owner, acl = descriptor.GetSecurityDescriptorOwner(), descriptor.GetSecurityDescriptorDacl()
        owners = {'S-1-5-18', 'S-1-5-32-544'}
        if (owner is None or win32security.ConvertSidToStringSid(owner) not in owners
                or not descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED
                or acl is None or acl.GetAceCount() != len(owners)):
            _fail()
        actual = set()
        for index in range(acl.GetAceCount()):
            kind, mask, sid = acl.GetAce(index)
            if kind != (win32security.ACCESS_ALLOWED_ACE_TYPE, 0) or mask != _MUTEX_FULL_CONTROL:
                _fail()
            actual.add(win32security.ConvertSidToStringSid(sid))
        if actual != owners:
            _fail()
        result = win32event.WaitForSingleObject(handle, 0)
        acquired = result in (win32event.WAIT_OBJECT_0, win32event.WAIT_ABANDONED)
        if not acquired:
            _fail()
        yield
    finally:
        try:
            if acquired:
                win32event.ReleaseMutex(handle)
        finally:
            handle.Close()


@contextmanager
def _pinned_observer_action(paths, task):
    incoming = paths.updates_root.parent.parent.parent / 'EndpointPlatformSetupUpdates' / 'client.json'
    _assert_administrative_file(incoming)
    with durable_state._pinned_copy_source(incoming):
        _assert_administrative_file(incoming)
        with incoming.open('rb') as stream:
            record = read_json(stream.read(4097), 4096)
        version, digest = record['client_version'], record['script_sha256']
        if (set(record) != {'client_version', 'script_sha256', 'installed_at'}
                or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version)
                or not re.fullmatch('[0-9a-fA-F]{64}', digest)):
            _fail()
        target = paths.install_root.parent.parent / 'EndpointPlatformSetupUpdater' / version / 'EndpointSetupUpdater.ps1'
        _assert_administrative_file(target)
        with durable_state._pinned_copy_source(target):
            _assert_administrative_file(target)
            with target.open('rb') as stream:
                raw = stream.read(_LIMIT + 1)
            if (len(raw) > _LIMIT or hashlib.sha256(raw).hexdigest() != digest.lower()
                    or f"$script:ClientVersion='{version}'" not in raw.decode('utf-8-sig').splitlines()
                    or not has_verified_timestamp(target, _PUBLISHER, cache_only=True)):
                _fail()
            _verify_task(task, target, system_powershell(), allow_disabled=True)
            yield


def retire_packaged_observer(paths) -> str:
    """Remove only the fixed owned idle task. Caller owns installer exclusion."""
    try:
        folder = _scheduler_folder()
        if find_task(folder, _TASK_NAME) is None:
            return 'removed'
        with _observer_mutex():
            task = find_task(folder, _TASK_NAME)
            if task is None:
                return 'removed'
            if task.Path != '\\' + _TASK_NAME or task.State not in (1, 3) or task.GetInstances(0).Count:
                return 'incomplete'
            definition = task.Xml, task.GetSecurityDescriptor(7)
            with _pinned_observer_action(paths, task):
                durable_state.installer_mutation_checkpoint(required=True)
                current = find_task(folder, _TASK_NAME)
                if current is None:
                    return 'removed'
                if (current.Path != task.Path or (current.Xml, current.GetSecurityDescriptor(7)) != definition
                        or current.State not in (1, 3) or current.GetInstances(0).Count):
                    return 'incomplete'
                folder.DeleteTask(_TASK_NAME, 0)
                return 'removed' if find_task(folder, _TASK_NAME) is None else 'incomplete'
    except Exception:
        return 'incomplete'


def write_observer_cleanup_receipt(archive, transaction_id, package_sha256, observer_cleanup):
    if observer_cleanup not in {'removed', 'incomplete'}:
        raise ValueError('Invalid Observer cleanup outcome')
    durable_state.write_json_atomic(
        archive / 'observer-cleanup.json',
        {'schema_version': 1, 'transaction_id': transaction_id, 'package_sha256': package_sha256,
         'native_result': 0, 'native_uninstalled': True, 'observer_cleanup': observer_cleanup},
        trusted_root=archive, max_bytes=4096, protect=fence.protect_state)
