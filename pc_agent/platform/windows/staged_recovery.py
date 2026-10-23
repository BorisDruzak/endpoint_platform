"""Protected recovery inputs and fresh owner admission for staged updates.

Read-only inspection is never native settlement or mutation authority. All
writers are called from a fresh authenticated installer checkpoint scope.
"""
from __future__ import annotations

from dataclasses import replace
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
from uuid import UUID

from endpoint_contracts.runtime_payload import read_json
from . import durable_state, installer_fence as fence, staged_update_state as state
from . import installation_provenance as provenance

_LIMIT = 32768


def _fail():
    raise ValueError('RECOVERY_REQUIRED')


def _root(paths, operation_id, create=False):
    if not isinstance(operation_id, str) or str(UUID(operation_id)) != operation_id:
        _fail()
    parent = fence.state_root(paths)
    if create:
        parent = provenance._archive_directory(parent, 'staged-recovery')
        return provenance._archive_directory(parent, operation_id)
    return parent / 'staged-recovery' / operation_id


def _read(path):
    fence.assert_state_security(path, secret=True)
    return read_json(provenance._read(path, _LIMIT), _LIMIT)


def _write(root, name, value):
    durable_state.installer_mutation_checkpoint(required=True)
    durable_state.write_json_atomic(root / name, value, trusted_root=root, max_bytes=_LIMIT,
                                    protect=lambda leaf: fence.protect_state(leaf, secret=True))


def _binding_hash(record):
    return hashlib.sha256(state._canonical(state._binding_value(record.binding))).hexdigest()


def _assert_owner_dead(owner):
    """Use a real retained process handle; access failure is not death proof."""
    if os.name != 'nt':
        _fail()
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(ctypes.c_uint64)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x00101000, False, owner['pid'])
    if not handle:
        if ctypes.get_last_error() == 87:  # nonexistent PID, not access denied
            return
        _fail()
    try:
        times = [ctypes.c_uint64() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *[ctypes.byref(value) for value in times]):
            _fail()
        if times[0].value != owner['created']:
            return  # PID reuse is a different process; never terminate it.
        if kernel.WaitForSingleObject(handle, 0) != 0:
            _fail()
    finally:
        kernel.CloseHandle(handle)


def owner_authorized(paths, record, owner):
    if owner == record.owner:
        return True
    try:
        receipt = _read(_root(paths, record.binding.operation_id) / 'owner.json')
        return receipt == {'schema_version': 1, 'operation_id': record.binding.operation_id,
            'binding_sha256': _binding_hash(record), 'original_owner': record.owner, 'owner': owner}
    except (OSError, ValueError, TypeError):
        return False


def _validate_task(paths, operation_id, executable, expected_digest):
    import win32com.client
    from xml.etree import ElementTree as ET
    service = win32com.client.Dispatch('Schedule.Service'); service.Connect()
    task = service.GetFolder('\\').GetTask('EndpointStagedRecovery-' + operation_id)
    if hashlib.sha256(str(task.Xml).encode('utf-8')).hexdigest() != expected_digest:
        _fail()
    _validate_task_definition(task.Xml, operation_id, executable, task.Definition.Principal.LogonType)
    # Scheduler's protected DACL must grant no write authority to another user.
    import win32security
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(task.GetSecurityDescriptor(7), 1)
    dacl = descriptor.GetSecurityDescriptorDacl()
    if (descriptor.GetSecurityDescriptorOwner() is None or dacl is None
            or win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in {'S-1-5-18','S-1-5-32-544'}):
        _fail()
    for index in range(dacl.GetAceCount()):
        kind, mask, sid = dacl.GetAce(index)
        if (kind[0] != 0 or win32security.ConvertSidToStringSid(sid) not in {'S-1-5-18','S-1-5-32-544'}):
            _fail()


def _validate_task_definition(xml, operation_id, executable, logon_type):
    from xml.etree import ElementTree as ET
    root = ET.fromstring(xml)
    ns = {'t': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
    actions = root.findall('t:Actions/t:Exec', ns)
    principals = root.findall('t:Principals/t:Principal', ns)
    restarts = root.findall('t:Settings/t:RestartOnFailure', ns)
    if len(root.findall('t:Settings', ns)) > 1 or len(restarts) > 1:
        _fail()
    # Historical captured tasks have no retry block. New tasks bind exactly
    # three one-minute retries in their protected XML digest; never widen it.
    if restarts and (len(restarts[0]) != 2
            or restarts[0].findtext('t:Interval', namespaces=ns) != 'PT1M'
            or restarts[0].findtext('t:Count', namespaces=ns) != '3'):
        _fail()
    if (len(actions) != 1 or len(root.findall('t:Actions/*', ns)) != 1
            or len(root.findall('t:Triggers/*', ns)) != 1 or len(principals) != 1
            or actions[0].findtext('t:Command', namespaces=ns) != str(executable)
            or actions[0].findtext('t:Arguments', namespaces=ns) != '--recover-staged-update ' + operation_id
            or principals[0].findtext('t:UserId', namespaces=ns) != 'S-1-5-18'
            or principals[0].findtext('t:RunLevel', namespaces=ns) != 'HighestAvailable'
            or logon_type != 5
            or principals[0].findtext('t:LogonType', namespaces=ns) not in (None, 'ServiceAccount')
            or len(root.findall('t:Triggers/t:BootTrigger', ns)) != 1):
        _fail()


def _validate_recovery_inputs(paths, record):
    value = _read(_root(paths, record.binding.operation_id) / 'inputs.json')
    fields = {'schema_version','operation_id','owner','package_sha256','files','service_states','task_sha256','boot'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['operation_id'] != record.binding.operation_id
            or value['owner'] != record.owner or value['package_sha256'] != record.binding.new_release['package_sha256']
            or not isinstance(value['boot'], str) or not 0 < len(value['boot']) <= 128
            or not isinstance(value['files'], dict) or set(value['files']) != {
                'EndpointAgentSetup.exe','EndpointAgent.msi','EndpointAgent.release.json','Install-EndpointAgentCanary.ps1'}
            or not isinstance(value['service_states'], dict) or set(value['service_states']) != {
                'EndpointAgent','EndpointAgentUpdater','EndpointBrowserPolicy'}
            or any(item not in {'Running','Stopped','Absent'} for item in value['service_states'].values())):
        _fail()
    cache = paths.install_root.parent / 'installer-cache' / ('msi-' + value['package_sha256'])
    fence.assert_namespace_security(cache, include_self=True)
    for name, digest in value['files'].items():
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            _fail()
        leaf = cache / name
        fence.assert_state_security(leaf, secret=True)
        if hashlib.sha256(provenance._read(leaf, 768 * 1024 * 1024)).hexdigest() != digest:
            _fail()
    if value['files']['EndpointAgent.msi'] != value['package_sha256']:
        _fail()
    if not isinstance(value['task_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', value['task_sha256']):
        _fail()
    _validate_task(paths, record.binding.operation_id, cache / 'EndpointAgentSetup.exe', value['task_sha256'])
    return value


def _native_settled(paths):
    # The owner additionally performs a real empty MsiBegin/End barrier before
    # granting recover-staged-owner. An idle PID or absent fence is insufficient.
    from .compound_upgrade_plan import has_active_upgrade
    return fence.read_fence(paths) is None and not has_active_upgrade(paths)


def _verify_original_state(paths, record):
    from .staged_foundation_rollback import _verify_original_data, _verify_original_core
    if (provenance.verified_foundation_release(paths) != record.binding.old_release
            or paths.current_path.read_bytes() != record.binding.selected_before
            or (paths.previous_path.read_bytes() if paths.previous_path.exists() else None) != record.binding.previous_before):
        _fail()
    _verify_original_data(paths, record)
    _verify_original_core(paths, record)


class _BootEnvironment(ctypes.Structure):
    _fields_ = [('identifier', ctypes.c_ubyte * 16), ('firmware', ctypes.c_uint32),
                ('flags', ctypes.c_uint64)]


def _kernel_boot(value):
    return (isinstance(value, str) and re.fullmatch(
        r'kernel-boot-v1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value)
        is not None and value != 'kernel-boot-v1:00000000-0000-0000-0000-000000000000')


def _boot_identity():
    # LastBootUpTime is a WMI provider's wall-clock value, not boot identity:
    # a provider refresh after clock correction can change it without reboot.
    # Match the signed owner's SYSTEM_BOOT_ENVIRONMENT_INFORMATION ABI. No
    # timestamp fallback may authorize a trial on unsupported/query failure.
    value = _BootEnvironment()
    length = ctypes.c_uint32()
    try:
        query = ctypes.WinDLL('ntdll').NtQuerySystemInformation
        query.argtypes = [ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32,
                          ctypes.POINTER(ctypes.c_uint32)]
        query.restype = ctypes.c_int32
        status = query(90, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(length))
    except (AttributeError, OSError):
        _fail()
    if status != 0 or length.value != ctypes.sizeof(value):
        _fail()
    result = 'kernel-boot-v1:' + str(UUID(bytes_le=bytes(value.identifier)))
    if not _kernel_boot(result):
        _fail()
    return result


def record_reboot_required(paths, operation_id, native_exit):
    durable_state.installer_mutation_checkpoint(required=True)
    record = state.read_staged_update(paths)
    if (record is None or record.binding.operation_id != operation_id or native_exit not in (3010, 1641)
            or record.phase not in {'switching','native-settled','trial'}):
        _fail()
    root = _root(paths, operation_id, create=True)
    value = {'schema_version': 1, 'binding_sha256': _binding_hash(record),
             'native_exit': native_exit, 'boot': _boot_identity()}
    leaf = root / 'reboot.json'
    if leaf.exists():
        if _read(leaf) != value: _fail()
    else:
        _write(root, 'reboot.json', value)


def reboot_pending(paths, record):
    leaf = _root(paths, record.binding.operation_id) / 'reboot.json'
    if not leaf.exists():
        return False
    value = _read(leaf)
    if (not isinstance(value, dict) or set(value) != {'schema_version','binding_sha256','native_exit','boot'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['binding_sha256'] != _binding_hash(record) or value['native_exit'] not in (3010,1641)
            or not isinstance(value['boot'], str)):
        _fail()
    # Historical wall-clock markers never prove a new boot. Retain the reboot
    # gate rather than releasing it on a timestamp/provider change.
    return not _kernel_boot(value['boot']) or value['boot'] == _boot_identity()


def recover_staged_update(paths, operation_id, *, capability=None):
    """Admit a fresh owner; return an action, never pretend native work occurred."""
    durable_state.installer_mutation_checkpoint(required=True)
    record = state.read_staged_update(paths)
    if (record is None or record.binding.operation_id != operation_id or capability is None
            or capability['transaction_id'] != operation_id or capability['package'] != record.binding.new_release
            or capability['operation'] != 'install' or capability['recovery'] or capability['uninstall_finalization']):
        _fail()
    inputs = _validate_recovery_inputs(paths, record)
    _assert_owner_dead(record.owner)
    if not _native_settled(paths):
        _fail()
    root = _root(paths, operation_id, create=True)
    prior = root / 'owner.json'
    if prior.exists():
        saved = _read(prior)
        if saved.get('owner') != capability['owner']:
            _assert_owner_dead(saved['owner'])
    receipt = {'schema_version': 1, 'operation_id': operation_id, 'binding_sha256': _binding_hash(record),
               'original_owner': record.owner, 'owner': capability['owner']}
    if prior.exists():
        saved = _read(prior)
        if (not isinstance(saved, dict) or set(saved) != set(receipt)
                or any(saved[key] != receipt[key] for key in receipt if key != 'owner')):
            _fail()
        history = provenance._archive_directory(root, 'owners')
        name = hashlib.sha256(state._canonical(saved)).hexdigest() + '.json'
        leaf = history / name
        if leaf.exists():
            if _read(leaf) != saved:
                _fail()
        else:
            _write(history, name, saved)
    _write(root, 'owner.json', receipt)
    if record.phase in {'accepted', 'rolled-back'}:
        return record.phase
    if record.phase in {'preparing', 'prepared'}:
        _verify_original_state(paths, record)
        from .staged_candidate_payload import cancel_prepared_candidate
        cancel_prepared_candidate(paths, record)
        state.advance_staged_update(paths, operation_id, record.phase, 'rolled-back', safe_code='preparation_cancelled')
        return 'preparation-cancelled'
    if reboot_pending(paths, record):
        return 'reboot-required'
    captured_boot = inputs.get('boot')
    current_boot = _boot_identity() if _kernel_boot(captured_boot) else None
    post_boot = _kernel_boot(captured_boot) and _kernel_boot(current_boot) and captured_boot != current_boot
    if record.phase in {'switching','native-settled','trial'} and not post_boot:
        return 'rollback-required'
    if record.phase == 'trial':
        # A confirmed new boot gets a new request/attempt and a fresh handshake.
        record = state._write(paths, replace(record, phase='native-settled', sequence=record.sequence + 1, attempt_id=None))
    if record.phase in {'switching','native-settled'}:
        return 'trial-required'
    return 'recovery-required'


def companion_restore_decisions(before, sessions):
    if not isinstance(before, list) or len(before) > 64 or not isinstance(sessions, list):
        _fail()
    result = []
    for item in before:
        if (not isinstance(item, dict) or set(item) != {'role','session_id','sid'}
                or item['role'] not in {'sensor','tray'} or type(item['session_id']) is not int
                or item['session_id'] <= 0 or not isinstance(item['sid'], str)):
            _fail()
        if any(session.get('session_id') == item['session_id'] and session.get('sid') == item['sid'] for session in sessions):
            result.append(item)
    return result


def wait_for_original_owner(owner, *, timeout_seconds):
    """The hidden watchdog retains one exact original handle until signalled."""
    import win32api, win32event, win32process
    try:
        handle = win32api.OpenProcess(0x00101000, False, owner['pid'])
    except win32api.error as error:
        if error.winerror == 87:
            return
        raise
    try:
        # GetProcessTimes returns a datetime through pywin32; use the same raw
        # FILETIME representation as the authenticated capability instead.
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(ctypes.c_uint64)] * 4
        kernel.GetProcessTimes.restype = wintypes.BOOL
        times = [ctypes.c_uint64() for _ in range(4)]
        if not kernel.GetProcessTimes(int(handle), *[ctypes.byref(value) for value in times]):
            _fail()
        if times[0].value != owner['created']:
            return
        if win32event.WaitForSingleObject(handle, int(timeout_seconds * 1000)) != win32event.WAIT_OBJECT_0:
            _fail()
    finally:
        handle.Close()


def execute_staged_recovery_phase(client, paths):
    cap = client.capability
    record = state.read_staged_update(paths)
    if (record is None or cap['transaction_id'] != record.binding.operation_id
            or cap['package'] != record.binding.new_release or cap['operation'] != 'install'
            or cap['recovery'] or cap['uninstall_finalization'] or 'compound' in cap
            or 'staged_rollback' in cap or 'recovery_parent' in cap):
        _fail()
    if client.phase == 'inspect-staged-recovery':
        inputs = _validate_recovery_inputs(paths, record)
        _assert_owner_dead(record.owner)
        result = {'operation_id': record.binding.operation_id, 'phase': record.phase,
                  'old_release': record.binding.old_release, 'service_states': inputs['service_states']}
    else:
        with durable_state.installer_mutation_checkpoints(client.checkpoint):
            if client.phase == 'recover-staged-owner':
                action = recover_staged_update(paths, record.binding.operation_id, capability=cap)
                result = {'operation_id': record.binding.operation_id, 'action': action}
            elif client.phase == 'restore-staged-companions':
                if not owner_authorized(paths, record, cap['owner']):
                    _fail()
                result = {'operation_id': record.binding.operation_id, **restore_staged_companions(paths, record.binding.operation_id)}
            elif client.phase in {'record-staged-reboot-3010','record-staged-reboot-1641'}:
                if not owner_authorized(paths, record, cap['owner']):
                    _fail()
                record_reboot_required(paths, record.binding.operation_id, int(client.phase.rsplit('-', 1)[1]))
                result = {'operation_id': record.binding.operation_id, 'result': 'reboot-required'}
            else:
                _fail()
    client.request('complete', result)
    return result


_COMPANIONS = {'sensor': 'EndpointUserSensor.exe', 'tray': 'EndpointAgentTray.exe'}


def _probe_companions(paths):
    import win32com.client
    service = win32com.client.GetObject('winmgmts:root\\cimv2')
    rows = service.ExecQuery("SELECT * FROM Win32_Process WHERE Name='EndpointUserSensor.exe' OR Name='EndpointAgentTray.exe'")
    expected = {os.path.normcase(str(paths.install_root / filename)): role for role, filename in _COMPANIONS.items()}
    result = []
    for process in rows:
        if not process.ExecutablePath or os.path.normcase(process.ExecutablePath) not in expected:
            continue
        session = int(process.SessionId)
        if session <= 0:
            continue
        output = process.ExecMethod_('GetOwnerSid')
        if int(output.Properties_('ReturnValue').Value) != 0:
            _fail()
        sid = str(output.Properties_('Sid').Value)
        item = {'role': expected[os.path.normcase(process.ExecutablePath)], 'session_id': session, 'sid': sid}
        if item not in result:
            result.append(item)
    companion_restore_decisions(result, [])  # validate strict bounded records
    return result


def prepare_staged_companions(paths, binding):
    """Persist cancellation evidence before publishing the reservation."""
    durable_state.installer_mutation_checkpoint(required=True)
    binding_sha256 = hashlib.sha256(state._canonical(state._binding_value(binding))).hexdigest()
    root = _root(paths, binding.operation_id, create=True)
    path = root / 'companions.json'
    if path.exists():
        value = _read(path)
        if value['binding_sha256'] != binding_sha256:
            _fail()
        return
    value = {'schema_version': 1, 'binding_sha256': binding_sha256, 'before': _probe_companions(paths)}
    _write(root, 'companions.json', value)


def capture_staged_companions(paths, operation_id):
    record = state.read_staged_update(paths)
    if record is None or record.binding.operation_id != operation_id or record.phase != 'preparing':
        _fail()
    prepare_staged_companions(paths, record.binding)


def _active_sessions():
    import win32ts, win32security
    result = []
    for session in win32ts.WTSEnumerateSessions():
        session_id = session['SessionId']
        if session_id <= 0 or session['State'] != win32ts.WTSActive:
            continue
        user = win32ts.WTSQuerySessionInformation(None, session_id, win32ts.WTSUserName)
        domain = win32ts.WTSQuerySessionInformation(None, session_id, win32ts.WTSDomainName)
        if not user:
            continue
        sid, *_ = win32security.LookupAccountName(None, domain + '\\' + user)
        result.append({'session_id': session_id, 'sid': win32security.ConvertSidToStringSid(sid)})
    return result


def _restore_companion_task(paths, operation_id, item):
    """A password-free existing interactive token; never a SYSTEM GUI process."""
    import win32com.client
    if item not in companion_restore_decisions([item], _active_sessions()):
        return False
    scheduler = win32com.client.Dispatch('Schedule.Service'); scheduler.Connect()
    folder = scheduler.GetFolder('\\')
    name = 'EndpointCompanionRestore-' + operation_id + '-' + item['role'] + '-' + str(item['session_id'])
    definition = scheduler.NewTask(0)
    definition.Principal.UserId = item['sid']
    definition.Principal.LogonType = 3  # TASK_LOGON_INTERACTIVE_TOKEN
    definition.Principal.RunLevel = 0  # TASK_RUNLEVEL_LUA
    definition.Settings.Enabled = True
    definition.Settings.DisallowStartIfOnBatteries = False
    definition.Settings.StopIfGoingOnBatteries = False
    definition.Settings.ExecutionTimeLimit = 'PT0S'
    action = definition.Actions.Create(0)
    action.Path = str(paths.install_root / _COMPANIONS[item['role']])
    action.Arguments = ''
    security = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;' + item['sid'] + ')'
    try:
        # No update/replace flag: a pre-existing foreign task is a conflict.
        task = folder.RegisterTaskDefinition(name, definition, 2, item['sid'], None, 3, security)
    except Exception:
        return False
    try:
        if item not in companion_restore_decisions([item], _active_sessions()):
            return False
        task.RunEx(None, 4, item['session_id'], '')  # TASK_RUN_USE_SESSION_ID
        return True
    finally:
        # Deleting the launcher registration does not stop its interactive process.
        folder.DeleteTask(name, 0)


def _service_outcomes(paths, record):
    import win32serviceutil, win32service
    inputs = _read(_root(paths, record.binding.operation_id) / 'inputs.json')
    result = {}
    for name, before in inputs['service_states'].items():
        if before != 'Running':
            result[name] = 'not-required'
            continue
        try:
            result[name] = 'running' if win32serviceutil.QueryServiceStatus(name)[1] == win32service.SERVICE_RUNNING else 'not-running'
        except Exception:
            result[name] = 'unavailable'
    return result


def _verified_companion_files(paths, record):
    from .staged_foundation_rollback import _resolve_media, _read_expected_media
    from .legacy_foundation_upgrade import canonical_release, verified_rollback_foundation_bytes
    from . import msi_inventory
    release = record.binding.new_release if record.phase == 'accepted' else record.binding.old_release
    relative = 'packages/' + release['package_sha256'] + '/EndpointAgent.msi'
    if not (fence.state_root(paths) / relative).exists():
        # Genuine legacy media may live in the original retained archive.
        relative = _resolve_media(paths, record)['old']['relative_path']
    expected = _read_expected_media(paths, {'relative_path': relative, 'release': release})
    if provenance.verified_foundation_release(paths) != release:
        _fail()
    return (verified_rollback_foundation_bytes(paths, expected) if canonical_release(release) is not None
            else msi_inventory.verified_foundation_bytes(expected, paths.install_root))


def restore_staged_companions(paths, operation_id):
    record = state.read_staged_update(paths)
    if record is None or record.binding.operation_id != operation_id or record.phase not in {'accepted','rolled-back'}:
        _fail()
    value = _read(_root(paths, operation_id) / 'companions.json')
    if (not isinstance(value, dict) or set(value) != {'schema_version','binding_sha256','before'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['binding_sha256'] != _binding_hash(record)):
        _fail()
    decisions = companion_restore_decisions(value['before'], _active_sessions())
    result = {'services': _service_outcomes(paths, record), 'users': 'not-required'}
    if value['before'] and not decisions:
        result['users'] = 'session-unavailable'
    elif decisions:
        from .msi_inventory import ProvenanceConflict
        body_completed = False
        try:
            with _verified_companion_files(paths, record):
                already = _probe_companions(paths)
                launched = [item in already or _restore_companion_task(paths, operation_id, item) for item in decisions]
                body_completed = True
        except ProvenanceConflict:
            if not body_completed:
                raise
            # A completed launch does not waive the post-use identity guard.
            # Reacquire the complete native/byte/pin proof once, without replaying
            # any launch. Persistent failure still propagates and keeps recovery.
            with _verified_companion_files(paths, record):
                pass
        result['users'] = 'launch-requested' if all(launched) else 'deferred'
    return result
