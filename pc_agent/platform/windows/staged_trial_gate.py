"""Volatile, OS-enforced revocation of a staged candidate's durable proof.

Only the authenticated elevated begin phase creates these objects. Zero-access
handles in its long-lived owner keep their names alive; the service opens them
with its fixed service SID. No filesystem fallback can confer readiness.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from contextlib import contextmanager, ExitStack
from ctypes import wintypes

from .local_ipc import SERVICE_SID

_ACCESS = {'mutex': 0x120001, 'event': 0x120002}
_FULL = {'mutex': 0x1F0001, 'event': 0x1F0003}
_OWNERS = {'S-1-5-18', 'S-1-5-32-544'}
_POISONED = []  # Keep an unreleasable lock until this process exits.
_POISONED_NAMES = set()


class GateUnavailable(RuntimeError):
    pass


class GateBusy(GateUnavailable):
    """A bounded reader could not snapshot an in-progress publication."""


def _rights(kind):
    return {**dict.fromkeys(_OWNERS, _FULL[kind]), SERVICE_SID: _ACCESS[kind], 'S-1-3-4': 0x20000}


def _names(request):
    bound = json.dumps(request, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    prefix = 'Global\\EndpointPlatform.Agent.StagedTrial.' + hashlib.sha256(bound).hexdigest()
    return prefix + '.Mutex', prefix + '.Ready'


def _validate(handle, kind):
    import win32security as security
    descriptor = security.GetSecurityInfo(handle, security.SE_KERNEL_OBJECT,
        security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION)
    owner, dacl = descriptor.GetSecurityDescriptorOwner(), descriptor.GetSecurityDescriptorDacl()
    if (owner is None or security.ConvertSidToStringSid(owner) not in _OWNERS
            or not descriptor.GetSecurityDescriptorControl()[0] & security.SE_DACL_PROTECTED
            or dacl is None or dacl.GetAceCount() != len(_rights(kind))):
        raise GateUnavailable('trial gate security is invalid')
    actual = {}
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        if len(ace) != 3 or ace[0] != (security.ACCESS_ALLOWED_ACE_TYPE, 0):
            raise GateUnavailable('trial gate ACE is invalid')
        sid = security.ConvertSidToStringSid(ace[2])
        if sid in actual:
            raise GateUnavailable('trial gate has duplicate ACE')
        actual[sid] = ace[1]
    if actual != _rights(kind):
        raise GateUnavailable('trial gate permissions differ')


class _Api:
    def __init__(self):
        if os.name != 'nt':
            raise GateUnavailable('Windows trial gate is unavailable')
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'CloseHandle': ([wintypes.HANDLE], wintypes.BOOL),
            'CreateMutexExW': ([wintypes.LPVOID, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD], wintypes.HANDLE),
            'CreateEventExW': ([wintypes.LPVOID, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD], wintypes.HANDLE),
            'OpenMutexW': ([wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR], wintypes.HANDLE),
            'OpenEventW': ([wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR], wintypes.HANDLE),
            'WaitForSingleObject': ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
            'ReleaseMutex': ([wintypes.HANDLE], wintypes.BOOL),
            'SetEvent': ([wintypes.HANDLE], wintypes.BOOL),
            'ResetEvent': ([wintypes.HANDLE], wintypes.BOOL),
            'GetCurrentProcess': ([], wintypes.HANDLE),
            'GetProcessTimes': ([wintypes.HANDLE] + [ctypes.POINTER(ctypes.c_uint64)] * 4, wintypes.BOOL),
            'QueryFullProcessImageNameW': ([wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            'DuplicateHandle': ([wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.kernel, name)
            function.argtypes, function.restype = args, result

    def checked(self, name, *args):
        result = getattr(self.kernel, name)(*args)
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())
        return result


def _created(api, handle):
    times = [ctypes.c_uint64() for _ in range(4)]
    api.checked('GetProcessTimes', handle, *[ctypes.byref(value) for value in times])
    return times[0].value


def process_created():
    api = _Api()
    return _created(api, api.kernel.GetCurrentProcess())


def _process_path(handle):
    api = _Api()
    path, length = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
    api.checked('QueryFullProcessImageNameW', int(handle), 0, path, ctypes.byref(length))
    return path.value


class TrialGate:
    def __init__(self, api, mutex, event, names):
        self.api, self.mutex, self.event = api, mutex, event
        self.names = names
        self.poisoned = False

    def close(self):
        if self.poisoned:
            return
        for name in ('event', 'mutex'):
            handle = getattr(self, name)
            if handle:
                self.api.kernel.CloseHandle(handle)
                setattr(self, name, None)

    def __del__(self):
        self.close()

    def _poison(self):
        if not self.poisoned:
            self.poisoned = True
            _POISONED_NAMES.add(self.names)
            _POISONED.append(self)

    @contextmanager
    def locked(self, timeout_ms=1000):
        if self.poisoned or self.names in _POISONED_NAMES:
            raise GateUnavailable('trial gate was poisoned')
        result = self.api.kernel.WaitForSingleObject(self.mutex, timeout_ms)
        if result == 0x80:  # Ownership is granted, but the prior publication is untrusted.
            self.api.kernel.ResetEvent(self.event)
            self._poison()
            raise GateUnavailable('trial gate was abandoned')
        if result == 0x102:
            raise GateBusy('trial gate publication is busy')
        if result != 0:
            raise GateUnavailable('trial gate lock unavailable')
        try:
            _validate(self.mutex, 'mutex')
            _validate(self.event, 'event')
            yield self
        except BaseException:
            # A security or kernel failure cannot release a possibly signalled
            # old proof. Ordinary publication failures occur after reset and
            # are handled by the writer inside this boundary.
            self._poison()
            raise
        finally:
            if not self.poisoned:
                if not self.api.kernel.ReleaseMutex(self.mutex):
                    self._poison()

    def reset(self):
        self.api.checked('ResetEvent', self.event)

    def publish(self):
        self.api.checked('SetEvent', self.event)

    def ready(self):
        result = self.api.kernel.WaitForSingleObject(self.event, 0)
        if result not in (0, 0x102):
            raise GateUnavailable('trial gate readiness unavailable')
        return result == 0


def _new_gate(request):
    import win32security as security
    api, handles = _Api(), []
    class Attributes(ctypes.Structure):
        _fields_ = [('length', wintypes.DWORD), ('descriptor', wintypes.LPVOID), ('inherit', wintypes.BOOL)]
    try:
        for kind, name in zip(('mutex', 'event'), _names(request)):
            sddl = 'D:P' + ''.join(f'(A;;0x{mask:x};;;{sid})' for sid, mask in _rights(kind).items())
            descriptor = ctypes.create_string_buffer(bytes(security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)))
            attributes = Attributes(ctypes.sizeof(Attributes), ctypes.cast(descriptor, wintypes.LPVOID), False)
            function = 'CreateMutexExW' if kind == 'mutex' else 'CreateEventExW'
            ctypes.set_last_error(0)
            handle = api.checked(function, ctypes.byref(attributes), name, 0 if kind == 'mutex' else 1, _ACCESS[kind])
            existed = ctypes.get_last_error() == 183
            handles.append(handle)
            if existed:
                raise GateUnavailable('preexisting trial gate rejected')
            _validate(handle, kind)
        return TrialGate(api, *handles, _names(request))
    except BaseException:
        for handle in handles:
            api.kernel.CloseHandle(handle)
        raise


def open_gate(request):
    api, handles = _Api(), []
    try:
        for kind, name in zip(('mutex', 'event'), _names(request)):
            function = 'OpenMutexW' if kind == 'mutex' else 'OpenEventW'
            handle = getattr(api.kernel, function)(_ACCESS[kind], False, name)
            if not handle:
                error = ctypes.get_last_error()
                if error == 2:
                    raise FileNotFoundError('trial gate is absent')
                raise ctypes.WinError(error)
            handles.append(handle)
            _validate(handle, kind)
        return TrialGate(api, *handles, _names(request))
    except BaseException:
        for handle in handles:
            api.kernel.CloseHandle(handle)
        raise


def create_trial_gate(request, owner):
    """Keep reset objects alive in the currently authenticated native owner."""
    import win32api
    from .installer_transaction_bridge import NativeIdentity
    if not isinstance(owner, dict) or not owner.get('elevated'):
        raise GateUnavailable('trial gate requires the authenticated elevated owner')
    identity = NativeIdentity(owner['pid'])
    gate, target, copied = None, None, []
    try:
        if identity.value != owner:
            raise GateUnavailable('trial gate owner identity changed')
        target = win32api.OpenProcess(0x00101040, False, owner['pid'])
        api = _Api()
        if _created(api, int(target)) != owner['created']:
            raise GateUnavailable('trial gate owner process was replaced')
        gate = _new_gate(request)
        for handle in (gate.mutex, gate.event):
            duplicate = wintypes.HANDLE()
            api.checked('DuplicateHandle', api.kernel.GetCurrentProcess(), handle, int(target),
                        ctypes.byref(duplicate), 0, False, 0)
            copied.append(duplicate.value)
        identity.assert_alive()
    except BaseException:
        if target is not None:
            # Undo a partial transfer; zero-access handles only retain names.
            for handle in copied:
                local = wintypes.HANDLE()
                if api.kernel.DuplicateHandle(int(target), handle, api.kernel.GetCurrentProcess(),
                        ctypes.byref(local), 0, False, 1):
                    api.kernel.CloseHandle(local)
        raise
    finally:
        if gate is not None: gate.close()
        if target is not None: target.Close()
        identity.close()


class _CandidateProcess:
    """Retain a LocalService image without elevated-operator admission rules."""
    def __init__(self, pid):
        from pathlib import Path
        import win32api
        import win32file
        import win32security as security
        from endpoint_contracts.runtime_payload import reject_reparse_ancestors
        self.stack = ExitStack()
        try:
            if type(pid) is not int or pid <= 0:
                raise GateUnavailable('trial candidate PID is invalid')
            self.process = win32api.OpenProcess(0x00101000, False, pid)
            self.stack.callback(self.process.Close)
            token = security.OpenProcessToken(self.process, 8)
            self.stack.callback(token.Close)
            sid = security.ConvertSidToStringSid(security.GetTokenInformation(token, security.TokenUser)[0])
            if sid != 'S-1-5-19':
                raise GateUnavailable('trial candidate is not LocalService')
            groups = security.GetTokenInformation(token, security.TokenGroups)
            if not any(security.ConvertSidToStringSid(sid) == SERVICE_SID and flags & 4 and not flags & 16
                       for sid, flags in groups):
                raise GateUnavailable('trial candidate is not the canonical service')
            self.image_path = Path(_process_path(self.process))
            reject_reparse_ancestors(self.image_path)
            image = win32file.CreateFile(str(self.image_path), 0x80000000, 1, None, 3, 0x00200000, None)
            self.stack.callback(image.Close)
            if win32file.GetFileInformationByHandle(image)[0] & 0x400:
                raise GateUnavailable('trial candidate image is a reparse point')
            digest = hashlib.sha256()
            while True:
                _, block = win32file.ReadFile(image, 1024 * 1024)
                if not block: break
                digest.update(block)
            self.value = {'pid': pid, 'created': _created(_Api(), int(self.process)),
                          'hash': digest.hexdigest(), 'sid': sid}
            self.assert_alive()
        except BaseException:
            self.stack.close()
            raise

    def assert_alive(self):
        if _Api().kernel.WaitForSingleObject(int(self.process), 0) != 0x102:
            raise GateUnavailable('trial candidate process has exited')

    def close(self):
        self.stack.close()


@contextmanager
def live_candidate(paths, binding, pid, created):
    """Hold the actual process and image, rejecting PID reuse or another source."""
    from . import installation_provenance as provenance
    identity = _CandidateProcess(pid)
    try:
        if identity.value['created'] != created:
            raise GateUnavailable('trial candidate process identity differs')
        expected = paths.versions_root / binding.candidate_version / 'pc_agent.exe'
        if os.path.normcase(str(identity.image_path.absolute())) != os.path.normcase(str(expected.absolute())):
            raise GateUnavailable('trial candidate image path differs')
        selector = {'schema_version': 1, 'version': binding.candidate_version,
                    'source_revision': binding.candidate_source_revision}
        raw = json.dumps(selector, separators=(',', ':')).encode()
        core = provenance._inspect_core_value(paths, raw, selector, binding.new_release['version'])
        if (core.identity.version != binding.candidate_version
                or core.identity.source_revision != binding.candidate_source_revision
                or core.identity.tree_sha256 != binding.candidate_tree_sha256
                or not any(item.path == 'pc_agent.exe' and item.sha256 == identity.value['hash']
                           for item in core.identity.files)):
            raise GateUnavailable('trial candidate source differs')
        identity.assert_alive()
        yield identity
        # A successful durable acceptance is terminal. Process exit after its
        # publication must not turn that accepted receipt into a helper error.
    finally:
        identity.close()
