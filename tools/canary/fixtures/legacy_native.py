"""Read-only Windows adapter for immutable nonproduction core83/86/87.

Uses existing pywin32 APIs plus typed ctypes calls for exact creation times,
held-handle parent identity and machine-scoped MSI queries. No mutation,
impersonation, elevation, installer repair, cache read, shell or polling loop.
"""
from contextlib import ExitStack, contextmanager
import ctypes
from ctypes import wintypes as w
from hashlib import sha256
import os
from pathlib import PureWindowsPath

from tools.canary.fixtures.legacy_authority import (
    COMPONENT, IMAGE, PRODUCT, SERVICE_SID,
    Image, Observation, Process, Rejected, Service, Token, check_acl,
)


class _BasicProcess(ctypes.Structure):
    _fields_ = [("reserved1", ctypes.c_void_p), ("peb", ctypes.c_void_p),
        ("reserved2", ctypes.c_void_p * 2), ("pid", ctypes.c_size_t),
        ("parent", ctypes.c_size_t)]


class _Times(ctypes.Structure):
    _fields_ = [("low", w.DWORD), ("high", w.DWORD)]

    def integer(self):
        return (self.high << 32) | self.low


def _function(library, name, result, *arguments):
    fn = getattr(library, name)
    fn.restype, fn.argtypes = result, arguments
    return fn


class NativeAuthority:
    """One bounded read session; all owned handles belong to its ExitStack."""

    @contextmanager
    def hold(self):
        if os.name != "nt":
            raise Rejected("windows_required")
        import win32api
        import win32file
        import win32security
        import win32service

        self.api, self.file, self.security, self.scm = win32api, win32file, win32security, win32service
        with ExitStack() as stack:
            self.stack = stack
            self.processes, self.files = [], []
            self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            self.ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
            self._times = _function(self.kernel, "GetProcessTimes", w.BOOL, w.HANDLE,
                *([ctypes.POINTER(_Times)] * 4))
            self._image = _function(self.kernel, "QueryFullProcessImageNameW", w.BOOL,
                w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD))
            self._basic = _function(self.ntdll, "NtQueryInformationProcess", w.LONG,
                w.HANDLE, w.ULONG, ctypes.c_void_p, w.ULONG, ctypes.POINTER(w.ULONG))
            self._assert_not_impersonating()
            yield self

    def _own(self, handle, close=None):
        self.stack.callback(close or handle.Close, *([handle] if close else []))
        return handle

    def _assert_not_impersonating(self):
        try:
            token = self.security.OpenThreadToken(self.api.GetCurrentThread(), 8, True)
        except Exception as error:
            if getattr(error, "winerror", None) == 1008:  # ERROR_NO_TOKEN only
                return
            raise Rejected("thread_token_unavailable") from None
        token.Close()
        raise Rejected("thread_impersonation")

    def _token(self, process):
        # TOKEN_QUERY only, never TOKEN_DUPLICATE/READ_CONTROL/ADJUST_PRIVILEGES.
        token = self.security.OpenProcessToken(process, 8)
        try:
            def query(kind):
                return self.security.GetTokenInformation(token, kind)
            groups = query(self.security.TokenGroups)
            if len(groups) > 256 or query(self.security.TokenRestrictedSids) or query(self.security.TokenType) != 1:
                raise Rejected("unsupported_token")
            enabled = [(self.security.ConvertSidToStringSid(sid), flags) for sid, flags in groups
                if flags & 4 and not flags & 16]
            logons = [sid for sid, flags in enabled if flags & 0xC0000000 == 0xC0000000]
            if len(logons) != 1:
                raise Rejected("logon_identity")
            return Token(self.security.ConvertSidToStringSid(query(self.security.TokenUser)[0]),
                SERVICE_SID if SERVICE_SID in {sid for sid, _ in enabled} else "",
                logons[0], query(self.security.TokenSessionId),
                query(self.security.TokenStatistics)["AuthenticationId"])
        finally:
            token.Close()

    def _process(self, pid, handle):
        basic, count = _BasicProcess(), w.ULONG()
        if self._basic(int(handle), 0, ctypes.byref(basic), ctypes.sizeof(basic), ctypes.byref(count)) != 0:
            raise Rejected("process_parent_unavailable")
        if count.value != ctypes.sizeof(basic) or basic.pid != pid:
            raise Rejected("process_identity")
        created, exited, kernel, user = (_Times() for _ in range(4))
        if not self._times(int(handle), *map(ctypes.byref, (created, exited, kernel, user))) or exited.integer():
            raise Rejected("process_not_live")
        buffer, length = ctypes.create_unicode_buffer(32768), w.DWORD(32768)
        if not self._image(int(handle), 0, buffer, ctypes.byref(length)) or not 0 < length.value < 32768:
            raise Rejected("process_image_unavailable")
        return Process(pid, basic.parent, created.integer(), buffer.value, self._token(handle))

    def _open_process(self, pid):
        if pid <= 0:
            raise Rejected("process_identity")
        # QUERY_LIMITED_INFORMATION; no VM_READ, debug privilege or token changes.
        handle = self._own(self.api.OpenProcess(0x1000, False, pid))
        self.processes.append((pid, handle))
        return self._process(pid, handle)

    def _service(self):
        config = self.scm.QueryServiceConfig(self.service)
        status = self.scm.QueryServiceStatusEx(self.service)
        if status["ServiceType"] != config[0]:
            raise Rejected("service_type_changed")
        return Service(status["ProcessId"], config[0], config[1], status["CurrentState"],
            config[3], config[7], self.scm.QueryServiceConfig2(self.service, 5))

    def _file_identity(self, handle, path, directory):
        info = self.file.GetFileInformationByHandle(handle)
        if info[0] & 0x400 or bool(info[0] & 0x10) != directory:
            raise Rejected("reparse_or_wrong_type")
        final = self.file.GetFinalPathNameByHandle(handle, 0)
        if final != "\\\\?\\" + path:
            raise Rejected("noncanonical_image_path")
        if not directory and info[7] != 1:
            raise Rejected("image_hardlink")
        sd = self.security.GetSecurityInfo(handle, 1, 1 | 4)  # FILE_OBJECT, OWNER/DACL
        owner = sd.GetSecurityDescriptorOwner()
        dacl = sd.GetSecurityDescriptorDacl()
        if owner is None or dacl is None or dacl.GetAceCount() > 256:
            raise Rejected("image_acl")
        aces = []
        for index in range(dacl.GetAceCount()):
            ace = dacl.GetAce(index)
            if len(ace) != 3:
                raise Rejected("unsupported_image_ace")
            aces.append((*ace[0], ace[1], self.security.ConvertSidToStringSid(ace[2])))
        owner = self.security.ConvertSidToStringSid(owner)
        check_acl(owner, aces, directory=directory)
        # Exclude last-access time, which our read can change. Keep identity,
        # write/creation timestamps, link count, attributes and descriptor policy.
        return (info[0], info[1], info[3], *info[4:], owner, tuple(aces))

    def _open_image_chain(self):
        target = PureWindowsPath(IMAGE)
        chain = [*reversed(target.parents), target]
        if len(chain) != 5:
            raise Rejected("image_chain")
        for index, path in enumerate(chain):
            directory = index < len(chain) - 1
            path = str(path)
            # Hold every ancestor without SHARE_DELETE. The file also excludes
            # SHARE_WRITE, pinning its bytes while hashing and rechecking.
            handle = self._own(self.file.CreateFile(path,
                0x20080 if directory else 0x80000000, 3 if directory else 1,
                None, 3, 0x00200000 | (0x02000000 if directory else 0), None))
            identity = self._file_identity(handle, path, directory)
            self.files.append((path, directory, handle, identity))
        return self._hash_image()

    def _hash_image(self):
        path, _, handle, _ = self.files[-1]
        info = self.file.GetFileInformationByHandle(handle)
        size = (info[5] << 32) | info[6]
        if not 0 < size <= 32 * 1024 * 1024:
            raise Rejected("image_size")
        self.file.SetFilePointer(handle, 0, 0)
        digest, total = sha256(), 0
        # At most 33 reads of at most 1MiB, including required EOF.
        for _ in range(33):
            status, block = self.file.ReadFile(handle, 1024 * 1024)
            if status:
                raise Rejected("image_read")
            if not block:
                break
            total += len(block)
            if total > size:
                raise Rejected("image_changed")
            digest.update(block)
        else:
            raise Rejected("image_read_bound")
        if total != size:
            raise Rejected("image_changed")
        return Image(path, digest.hexdigest(), size)

    def observe(self):
        # Current process is opened first; a manual invocation cannot acquire
        # authority merely by naming the fixed host or passing a version.
        runtime = self._open_process(os.getpid())
        manager = self._own(self.scm.OpenSCManager(None, None, 1), self.scm.CloseServiceHandle)
        self.service = self._own(self.scm.OpenService(manager, "EndpointAgent", 1 | 4), self.scm.CloseServiceHandle)
        service = self._service()
        if runtime.parent != service.pid or service.pid <= 0:
            raise Rejected("not_service_child")
        inner = self._open_process(service.pid)
        outer = self._open_process(inner.parent)
        return Observation(service, (runtime, inner, outer), self._open_image_chain())

    def recheck(self):
        self._assert_not_impersonating()
        for path, directory, handle, before in self.files:
            if self._file_identity(handle, path, directory) != before:
                raise Rejected("image_identity_changed")
        image = self._hash_image()
        processes = tuple(self._process(pid, handle) for pid, handle in self.processes)
        # SCM PID/state is checked last, after the retained handle/token/image
        # observations. An exited/reused PID never substitutes its replacement.
        return Observation(self._service(), processes, image)

    def require_legacy_product(self):
        """Three machine-context inventory reads; never open/repair cached MSI."""
        msi = ctypes.WinDLL("msi", use_last_error=True)
        info = _function(msi, "MsiGetProductInfoExW", w.UINT, w.LPCWSTR, w.LPCWSTR,
            w.DWORD, w.LPCWSTR, w.LPWSTR, ctypes.POINTER(w.DWORD))
        state = _function(msi, "MsiQueryComponentStateW", w.UINT, w.LPCWSTR, w.LPCWSTR,
            w.DWORD, w.LPCWSTR, ctypes.POINTER(ctypes.c_int))
        component_path = _function(msi, "MsiGetComponentPathExW", ctypes.c_int,
            w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD))
        for prop, expected in (("State", "5"), ("VersionString", "3.2.81")):
            buffer, length = ctypes.create_unicode_buffer(256), w.DWORD(256)
            if info(PRODUCT, None, 4, prop, buffer, ctypes.byref(length)) != 0 or length.value >= 256 or buffer.value != expected:
                raise Rejected("legacy_product")
        installed = ctypes.c_int()
        if state(PRODUCT, None, 4, COMPONENT, ctypes.byref(installed)) != 0 or installed.value != 3:
            raise Rejected("legacy_component")
        buffer, length = ctypes.create_unicode_buffer(1024), w.DWORD(1024)
        if (component_path(PRODUCT, COMPONENT, None, 4, buffer, ctypes.byref(length)) != 3
            or length.value >= 1024 or buffer.value != IMAGE):
            raise Rejected("legacy_component_path")
