"""Offline-safe exclusion for canonical Setup, OTA and journal mutations.

Never span an await or candidate proof wait. Async owners use timeout_ms=0.
Only tests replace the fixed object name; paths cannot change Windows identity.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from .update_paths import WindowsUpdatePaths

_MUTEX_NAME = r'Global\EndpointPlatform.Agent.UpdateTransaction'
_SERVICE_SIDS = (
    'S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691',
    'S-1-5-80-327494974-20047353-929432329-1920152597-707704661',
)
_RIGHTS = {'S-1-5-18': 0x1F0001, 'S-1-5-32-544': 0x1F0001,
           **dict.fromkeys(_SERVICE_SIDS, 0x120001), 'S-1-3-4': 0x20000}
_MUTEX_SDDL = 'D:P' + ''.join(f'(A;;0x{rights:x};;;{sid})' for sid, rights in _RIGHTS.items())
_OWNERS = {'S-1-5-18', 'S-1-5-32-544', 'S-1-5-19', *_SERVICE_SIDS}
_POSIX_LOCK = threading.RLock()
_POSIX_LOCAL = threading.local()


class UpdateInProgress(RuntimeError):
    """A competing owner currently holds the mutation boundary."""


def _validate_mutex_security(handle):
    import win32security
    descriptor = win32security.GetSecurityInfo(handle, win32security.SE_KERNEL_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
    owner = descriptor.GetSecurityDescriptorOwner()
    dacl = descriptor.GetSecurityDescriptorDacl()
    if (owner is None or win32security.ConvertSidToStringSid(owner) not in _OWNERS
        or not descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED
        or dacl is None or dacl.GetAceCount() != len(_RIGHTS)):
        raise ValueError('update exclusion security is invalid')
    actual = {}
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        if len(ace) != 3 or ace[0] != (win32security.ACCESS_ALLOWED_ACE_TYPE, 0):
            raise ValueError('update exclusion ACE is invalid')
        sid = win32security.ConvertSidToStringSid(ace[2])
        if sid in actual:
            raise ValueError('update exclusion has duplicate ACE')
        actual[sid] = ace[1]
    if actual != _RIGHTS:
        raise ValueError('update exclusion permissions differ')


def _assert_canonical_caller():
    import win32security
    allowed = ('S-1-5-18', 'S-1-5-32-544', *_SERVICE_SIDS)
    if not any(win32security.CheckTokenMembership(None, win32security.ConvertStringSidToSid(sid))
               for sid in allowed):
        raise PermissionError('update exclusion requires a canonical service or administrator')


@contextmanager
def _windows_transaction(timeout_ms):
    import ctypes
    from ctypes import wintypes
    import win32event
    import win32security
    _assert_canonical_caller()
    descriptor = ctypes.create_string_buffer(bytes(
        win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(_MUTEX_SDDL, 1)))
    class Attributes(ctypes.Structure):
        _fields_ = [('length', wintypes.DWORD), ('descriptor', wintypes.LPVOID), ('inherit', wintypes.BOOL)]
    attributes = Attributes(ctypes.sizeof(Attributes), ctypes.cast(descriptor, wintypes.LPVOID), False)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel.CreateMutexExW
    create.argtypes = [ctypes.POINTER(Attributes), wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    handle = create(ctypes.byref(attributes), _MUTEX_NAME, 0, 0x120001)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    acquired = False
    try:
        _validate_mutex_security(handle)
        result = win32event.WaitForSingleObject(handle, timeout_ms)
        if result == win32event.WAIT_TIMEOUT:
            raise UpdateInProgress('UPDATE_IN_PROGRESS')
        if result not in (win32event.WAIT_OBJECT_0, win32event.WAIT_ABANDONED):
            raise OSError('update exclusion wait failed')
        acquired = True
        # An abandoned mutex conveys ownership, never journal validity.
        _validate_mutex_security(handle)
        yield
    finally:
        if acquired:
            win32event.ReleaseMutex(handle)
        close(handle)


@contextmanager
def update_transaction(paths: WindowsUpdatePaths, *, timeout_ms: int = 30000):
    """Serialize a synchronous mutation; never change the Windows object by path."""
    if os.name == 'nt':
        with _windows_transaction(timeout_ms):
            yield
        return
    import fcntl
    # Linux uses an existing data root: creating untrusted parents is forbidden.
    root = paths.updates_root.parent.absolute()
    for parent in (root, *root.parents):
        details = parent.lstat()
        if (not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode)
            or (parent == root and (details.st_uid != os.geteuid() or details.st_mode & 0o022))):
            raise ValueError('update transaction root is unsafe')
    deadline = time.monotonic() + timeout_ms / 1000
    if not _POSIX_LOCK.acquire(timeout=timeout_ms / 1000):
        raise UpdateInProgress('UPDATE_IN_PROGRESS')
    descriptor = None
    try:
        held = getattr(_POSIX_LOCAL, 'held', {})
        if root in held:
            yield
            return
        descriptor = os.open(root / '.update-transaction.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or stat.S_IMODE(details.st_mode) != 0o600 or details.st_uid != os.geteuid():
            raise ValueError('update transaction lock is unsafe')
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise UpdateInProgress('UPDATE_IN_PROGRESS') from None
                time.sleep(min(.01, max(0, deadline-time.monotonic())))
        _POSIX_LOCAL.held = {**held, root: descriptor}
        try:
            yield
        finally:
            _POSIX_LOCAL.held = held
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        _POSIX_LOCK.release()


def _unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('update state has duplicate keys')
        result[key] = value
    return result


def _assert_state_security(path):
    if os.name != 'nt':
        return
    import win32security
    descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
    owner = descriptor.GetSecurityDescriptorOwner()
    dacl = descriptor.GetSecurityDescriptorDacl()
    if owner is None or win32security.ConvertSidToStringSid(owner) not in _OWNERS or dacl is None:
        raise ValueError('update state owner or DACL is invalid')
    # Read-only installer ACLs may include Users. No unrelated writer is allowed.
    writers = {'S-1-5-18', 'S-1-5-32-544', *_SERVICE_SIDS}
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        if len(ace) != 3 or ace[0][0] != win32security.ACCESS_ALLOWED_ACE_TYPE:
            raise ValueError('update state ACE is invalid')
        if ace[1] & 0x500D0156 and win32security.ConvertSidToStringSid(ace[2]) not in writers:
            raise ValueError('update state has an unrelated writer')


def _valid_time(value):
    if value is None:
        return True
    try:
        return isinstance(value, str) and datetime.fromisoformat(value).tzinfo is not None
    except ValueError:
        return False


_ID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
_VERSION = re.compile(r'^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$')
_CODES = {'failed':'launcher_apply_failed', 'rolled_back':'launcher_rolled_back', 'applied':'post_restart_handshake_confirmed'}


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _read_state(path, limit):
    for parent in (path, *path.parents):
        if parent.exists() or parent.is_symlink():
            details = parent.lstat()
            if stat.S_ISLNK(details.st_mode) or getattr(details, 'st_file_attributes', 0) & 0x400:
                raise ValueError('update state contains a reparse point')
    if not path.exists():
        return None
    _assert_state_security(path)
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or not 0 < details.st_size <= limit:
        raise ValueError('update state size or identity is invalid')
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        if (details.st_dev, details.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('update state identity changed')
        raw = stream.read(limit+1)
    if len(raw) > limit:
        raise ValueError('update state exceeds bound')
    try:
        payload = json.loads(raw, object_pairs_hook=_unique)
    except RecursionError as error:
        raise ValueError('update state nesting exceeds bound') from error
    if payload is None:
        raise ValueError('update state cannot be null')
    return payload


def active_update_state(paths: WindowsUpdatePaths) -> str | None:
    """Read-only Setup gate. Caller holds the transaction; malformed state raises."""
    for root in (paths.install_root, paths.updates_root.parent, paths.updates_root):
        if root.exists():
            _assert_state_security(root)
    result = None
    for path, limit, required, state in (
        (paths.pending_path, 16384, {'operation_id', 'version'}, 'pending'),
        (paths.updates_root/'startup-attempt.json', 4096, {'operation_id','version','attempt_id'}, 'verifying'),
        (paths.updates_root/'terminal-outcome.json', 4096, {'operation_id','reported_version','status','safe_code'}, 'terminal-report-pending'),
        (paths.restore_path, 4096, {'version'}, 'recovery-pending'),
        (paths.transition_path, 16384, {'operation_id','attempt_id','candidate','previous_bytes','status'}, 'recovery-pending'),
    ):
        payload = _read_state(path, limit)
        if payload is not None:
            if not isinstance(payload, dict) or not required <= payload.keys() or any(payload[key] in (None, '') for key in required):
                raise ValueError('update lifecycle state is invalid')
            for key in required:
                if key == 'candidate':
                    if not isinstance(payload[key], dict) or not _matches(_VERSION, payload[key].get('version')):
                        raise ValueError('update candidate identity is invalid')
                elif not isinstance(payload[key], str) or not 0 < len(payload[key]) <= 8192:
                    raise ValueError('update lifecycle field is invalid')
            for key in ('version', 'reported_version'):
                if key in payload and not _matches(_VERSION, payload[key]):
                    raise ValueError('update lifecycle version is invalid')
            if 'status' in payload:
                allowed = {'prepared', 'accepted'} if path == paths.transition_path else {'failed', 'rolled_back'}
                if payload['status'] not in allowed:
                    raise ValueError('update lifecycle status is invalid')
            result = state
    reports = _read_state(paths.updates_root/'endpoint_update_reports.json', 4*1024*1024)
    delivered = set()
    if reports is not None:
        fields = {'operation_id','report_key','status','reported_version','safe_code','delivered_at'}
        if not isinstance(reports, list) or any(not isinstance(r, dict) or set(r) != fields for r in reports):
            raise ValueError('update report journal is invalid')
        keys = set()
        identities = set()
        for record in reports:
            identity = (record['operation_id'], record['status'], record['reported_version'], record['safe_code'])
            if (not all(isinstance(record[key], str) for key in fields - {'delivered_at'})
                or not _matches(_ID, record['operation_id'])
                or re.fullmatch('[0-9a-f]{32}', record['report_key']) is None
                or not _matches(_VERSION, record['reported_version'])
                or record['status'] not in _CODES or record['safe_code'] != _CODES[record['status']]
                or not _valid_time(record['delivered_at']) or record['report_key'] in keys or identity in identities):
                raise ValueError('update report identity is invalid')
            keys.add(record['report_key'])
            identities.add(identity)
            if record['delivered_at'] is None:
                result = result or 'terminal-report-pending'
            else:
                delivered.add(record['operation_id'])
    handoffs = _read_state(paths.updates_root/'endpoint_update_state.json', 256*1024)
    if handoffs is not None:
        fields = {'operation_id','assigned_version','rollback_version','scheduled_ack_delivered_at'}
        if not isinstance(handoffs, list) or any(not isinstance(r, dict) or set(r) != fields for r in handoffs):
            raise ValueError('update handoff journal is invalid')
        seen = set()
        for record in handoffs:
            if (not _matches(_ID, record['operation_id'])
                or not _matches(_VERSION, record['assigned_version'])
                or not _matches(_VERSION, record['rollback_version'])
                or not _valid_time(record['scheduled_ack_delivered_at']) or record['operation_id'] in seen):
                raise ValueError('update handoff identity is invalid')
            seen.add(record['operation_id'])
        if any(record['operation_id'] not in delivered for record in handoffs):
            result = result or 'pending'
    return result
