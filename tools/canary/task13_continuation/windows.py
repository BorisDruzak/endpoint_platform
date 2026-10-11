"""Fail-closed native Windows identity and protected retained file handles."""
import ctypes as ct
import hashlib
import os
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from uuid import UUID

from .codec import require

DWORD = ct.c_ulong
HANDLE = ct.c_void_p


@lru_cache(maxsize=1)
def api():
    require(os.name == "nt", "Windows native authority required")
    kernel = ct.WinDLL("kernel32", use_last_error=True)
    adv = ct.WinDLL("advapi32", use_last_error=True)
    declarations = [
        (kernel, "CreateFileW", HANDLE, [ct.c_wchar_p, DWORD, DWORD, HANDLE, DWORD, DWORD, HANDLE]),
        (kernel, "CloseHandle", ct.c_int, [HANDLE]),
        (kernel, "CreateDirectoryW", ct.c_int, [ct.c_wchar_p, HANDLE]),
        (kernel, "GetVolumeInformationW", ct.c_int, [ct.c_wchar_p, ct.c_wchar_p, DWORD, HANDLE,
                                                    HANDLE, HANDLE, ct.c_wchar_p, DWORD]),
        (kernel, "GetFileInformationByHandle", ct.c_int, [HANDLE, HANDLE]),
        (kernel, "GetFinalPathNameByHandleW", DWORD, [HANDLE, ct.c_wchar_p, DWORD, DWORD]),
        (kernel, "ReadFile", ct.c_int, [HANDLE, HANDLE, DWORD, ct.POINTER(DWORD), HANDLE]),
        (kernel, "WriteFile", ct.c_int, [HANDLE, HANDLE, DWORD, ct.POINTER(DWORD), HANDLE]),
        (kernel, "FlushFileBuffers", ct.c_int, [HANDLE]),
        (kernel, "SetFileInformationByHandle", ct.c_int, [HANDLE, ct.c_int, HANDLE, DWORD]),
        (kernel, "LocalFree", HANDLE, [HANDLE]),
        (kernel, "GetCurrentProcess", HANDLE, []),
        (kernel, "GetWindowsDirectoryW", DWORD, [ct.c_wchar_p, DWORD]),
        (kernel, "GetProcessTimes", ct.c_int, [HANDLE, HANDLE, HANDLE, HANDLE, HANDLE]),
        (kernel, "WaitForSingleObject", DWORD, [HANDLE,DWORD]),
        (kernel, "GetExitCodeProcess", ct.c_int, [HANDLE,ct.POINTER(DWORD)]),
        (adv, "OpenProcessToken", ct.c_int, [HANDLE, DWORD, ct.POINTER(HANDLE)]),
        (adv, "GetTokenInformation", ct.c_int, [HANDLE, ct.c_int, HANDLE, DWORD, ct.POINTER(DWORD)]),
        (adv, "ConvertSidToStringSidW", ct.c_int, [HANDLE, ct.POINTER(ct.c_wchar_p)]),
        (adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW", ct.c_int,
         [ct.c_wchar_p, DWORD, ct.POINTER(HANDLE), ct.POINTER(DWORD)]),
        (adv, "GetSecurityInfo", DWORD, [HANDLE, ct.c_int, DWORD, ct.POINTER(HANDLE), HANDLE,
                                        ct.POINTER(HANDLE), HANDLE, ct.POINTER(HANDLE)]),
        (adv, "GetSecurityDescriptorControl", ct.c_int, [HANDLE, HANDLE, HANDLE]),
        (adv, "GetAce", ct.c_int, [HANDLE, DWORD, ct.POINTER(HANDLE)]),
    ]
    for library, name, result, args in declarations:
        fn = getattr(library, name)
        fn.restype, fn.argtypes = result, args
    return kernel, adv


def checked(ok):
    if not ok:
        raise ct.WinError(ct.get_last_error())


def sid_text(adv, pointer):
    result = ct.c_wchar_p()
    checked(adv.ConvertSidToStringSidW(pointer, ct.byref(result)))
    try:
        return result.value
    finally:
        api()[0].LocalFree(ct.cast(result, HANDLE))


def observe_controller():
    """Kernel-observed current process, boot GUID and elevated token; no fallback."""
    import winreg
    kernel, adv = api()
    times = [ct.c_ulonglong() for _ in range(4)]
    checked(kernel.GetProcessTimes(kernel.GetCurrentProcess(), *(ct.byref(v) for v in times)))
    token = HANDLE()
    checked(adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ct.byref(token)))
    try:
        size = DWORD()
        adv.GetTokenInformation(token, 1, None, 0, ct.byref(size))
        require(0 < size.value < 65536, "token size")
        user = ct.create_string_buffer(size.value)
        checked(adv.GetTokenInformation(token, 1, user, size, ct.byref(size)))
        sid = sid_text(adv, ct.cast(user, ct.POINTER(HANDLE))[0])
        elevated = DWORD()
        checked(adv.GetTokenInformation(token, 20, ct.byref(elevated), 4, ct.byref(size)))
        require(elevated.value == 1, "elevated controller token required")
    finally:
        kernel.CloseHandle(token)
    ntdll = ct.WinDLL("ntdll")
    query = ntdll.NtQuerySystemInformation
    query.argtypes, query.restype = [ct.c_int, HANDLE, DWORD, ct.POINTER(DWORD)], ct.c_long
    boot, length = ct.create_string_buffer(32), DWORD()
    require(query(90, boot, 32, ct.byref(length)) == 0 and length.value == 32,
            "native boot identity unavailable")
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                        winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        machine, _ = winreg.QueryValueEx(key, "MachineGuid")
    return {"host_id": hashlib.sha256(machine.encode("utf-8")).hexdigest(),
            "boot_id": str(UUID(bytes_le=boot.raw[:16])), "pid": os.getpid(),
            "birth": times[0].value, "token_sid": sid, "elevated": True}


@contextmanager
def security_attributes():
    kernel, adv = api()
    descriptor = HANDLE()
    checked(adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1, ct.byref(descriptor), None))

    class Attributes(ct.Structure):
        _fields_ = [("length", DWORD), ("descriptor", HANDLE), ("inherit", ct.c_int)]

    attributes = Attributes(ct.sizeof(Attributes), descriptor, 0)
    try:
        yield ct.byref(attributes)
    finally:
        kernel.LocalFree(descriptor)


def check_security(handle, protected):
    kernel, adv = api()
    owner, dacl, descriptor = HANDLE(), HANDLE(), HANDLE()
    require(adv.GetSecurityInfo(handle, 1, 5, ct.byref(owner), None, ct.byref(dacl), None,
                                ct.byref(descriptor)) == 0, "native security query failed")
    try:
        allowed = {"S-1-5-18", "S-1-5-32-544"}
        require(owner and sid_text(adv, owner) in allowed and dacl, "protected owner/DACL required")
        control, revision = ct.c_ushort(), DWORD()
        checked(adv.GetSecurityDescriptorControl(descriptor, ct.byref(control), ct.byref(revision)))
        require(not protected or control.value & 0x1000, "protected DACL required")
        count = ct.c_ushort.from_address(dacl.value + 4).value
        require(0 < count < 32, "restrictive nonempty DACL required")
        for index in range(count):
            ace = HANDLE()
            checked(adv.GetAce(dacl, index, ct.byref(ace)))
            require(ct.c_ubyte.from_address(ace.value).value == 0
                    and sid_text(adv, ace.value + 8) in allowed, "untrusted ACL trustee/type")
    finally:
        kernel.LocalFree(descriptor)


def information(handle, path, directory, expected_links=1):
    class Info(ct.Structure):
        _fields_ = [("attrs", DWORD), ("creation", ct.c_ulonglong), ("access", ct.c_ulonglong),
                    ("write", ct.c_ulonglong), ("volume", DWORD), ("high", DWORD), ("low", DWORD),
                    ("links", DWORD), ("index_high", DWORD), ("index_low", DWORD)]
        _pack_ = 4
    kernel, _ = api()
    info = Info()
    checked(kernel.GetFileInformationByHandle(handle, ct.byref(info)))
    require(not info.attrs & 0x400 and bool(info.attrs & 0x10) == directory, "reparse/type mismatch")
    require(directory or info.links == expected_links, "file hardlink identity changed/refused")
    target = ct.create_unicode_buffer(32768)
    size = kernel.GetFinalPathNameByHandleW(handle, target, len(target), 0)
    require(0 < size < len(target) and target.value.removeprefix("\\\\?\\").casefold()
            == str(path).casefold(), "retained handle path mismatch")
    return (info.high << 32) | info.low


@contextmanager
def retained(path, *, directory=False, writable=False, create=False, protected=False, security=True, expected_links=1):
    path = Path(path).absolute()
    require(path.drive and not str(path).startswith("\\\\") and ":" not in str(path)[2:], "local path required")
    kernel, _ = api()
    filesystem = ct.create_unicode_buffer(32)
    checked(kernel.GetVolumeInformationW(path.anchor, None, 0, None, None, None, filesystem, 32))
    require(filesystem.value == "NTFS", "local NTFS required")
    with security_attributes() as attributes:
        handle = kernel.CreateFileW(str(path), 0x80000000 | 0x20000 | (0x40010000 if writable else 0),
                                    3 if directory else 1, attributes if create else None,
                                    1 if create else 3, 0x200000 | (0x2000000 if directory else 0), None)
    if handle == ct.c_void_p(-1).value:
        error = ct.get_last_error()
        if error in (80, 183):
            raise FileExistsError("exclusive file already exists")
        raise ct.WinError(error)
    try:
        information(handle, path, directory,expected_links)
        if security:
            check_security(handle, protected)
        yield handle
    finally:
        kernel.CloseHandle(handle)


def read_handle(handle, path, limit=64 * 1024 * 1024, *, expected_links=1):
    size = information(handle, path, False,expected_links)
    require(size <= limit, "file size limit")
    buffer, count = ct.create_string_buffer(size + 1), DWORD()
    checked(api()[0].ReadFile(handle, buffer, size + 1, ct.byref(count), None))
    require(count.value == size, "retained read length changed")
    return buffer.raw[:size]


def write_handle(handle, raw):
    require(type(raw) is bytes and len(raw) <= 64 * 1024 * 1024, "bounded file bytes required")
    count = DWORD()
    checked(api()[0].WriteFile(handle, raw, len(raw), ct.byref(count), None))
    require(count.value == len(raw), "incomplete file write")
    checked(api()[0].FlushFileBuffers(handle))


def flush_volume(path):
    """Flush file-system metadata too; uncertainty consumes the claim, never retries."""
    kernel, _ = api()
    handle = kernel.CreateFileW("\\\\.\\" + Path(path).drive, 0xC0000000, 3, None, 3, 0, None)
    if handle == ct.c_void_p(-1).value:
        raise ct.WinError(ct.get_last_error())
    try:
        checked(kernel.FlushFileBuffers(handle))
    finally:
        kernel.CloseHandle(handle)


def rename_handle(handle, destination):
    class Rename(ct.Structure):
        _fields_ = [("replace", ct.c_ubyte), ("root", HANDLE), ("length", DWORD),
                    ("name", ct.c_wchar * (len(str(destination)) + 1))]
    data = Rename(0, None, len(str(destination).encode("utf-16-le")), str(destination))
    checked(api()[0].SetFileInformationByHandle(handle, 3, ct.byref(data), ct.sizeof(data)))


def system_core_paths():
    buffer = ct.create_unicode_buffer(32768)
    length = api()[0].GetWindowsDirectoryW(buffer,len(buffer))
    require(0 < length < len(buffer),"native Windows directory required")
    base = Path(buffer.value)/"System32"
    return {base/"OpenSSH/ssh.exe",base/"WindowsPowerShell/v1.0/powershell.exe"}


def process_birth(handle):
    times=[ct.c_ulonglong() for _ in range(4)]
    checked(api()[0].GetProcessTimes(handle,*(ct.byref(t) for t in times)))
    require(times[0].value>0,'kernel process birth')
    return times[0].value


def retained_process_exit(handle):
    signal=api()[0].WaitForSingleObject(handle,0)
    code=DWORD()
    checked(api()[0].GetExitCodeProcess(handle,ct.byref(code)))
    require(signal==0 and code.value!=259,'retained root exit unconfirmed')
    return {'wait_result':signal,'exit_code':code.value,'birth':process_birth(handle)}
