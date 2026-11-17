"""Standard pipes inherited by windowed native installer processes."""

import ctypes
import os
from ctypes import wintypes


def write_inherited_pipe(value: bytes, *, handle_number=-11, kernel=None) -> None:
    """Windowed PyInstaller has no sys.stdout; use only its inherited pipe."""
    kernel = kernel or ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel.GetStdHandle
    query.argtypes = [wintypes.DWORD]
    query.restype = wintypes.HANDLE
    handle = query(wintypes.DWORD(handle_number).value)
    if handle in (None, 0, -1, wintypes.HANDLE(-1).value):
        raise OSError("PREFLIGHT_STDOUT_UNAVAILABLE")
    write = kernel.WriteFile
    write.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    write.restype = wintypes.BOOL
    buffer = ctypes.create_string_buffer(value)
    count = wintypes.DWORD()
    if not write(
        handle, buffer, len(value), ctypes.byref(count), None
    ) or count.value != len(value):
        raise OSError("PREFLIGHT_STDOUT_WRITE_FAILED")


def read_inherited_pipe(max_bytes: int) -> str:
    """Read only the redirected pipe when windowed PyInstaller has no stdin."""
    import msvcrt

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_handle = kernel.GetStdHandle
    get_handle.argtypes = [wintypes.DWORD]
    get_handle.restype = wintypes.HANDLE
    get_type = kernel.GetFileType
    get_type.argtypes = [wintypes.HANDLE]
    get_type.restype = wintypes.DWORD
    handle = get_handle(wintypes.DWORD(-10).value)
    if not handle or get_type(handle) != 3:  # FILE_TYPE_PIPE
        raise OSError("provisioning stdin pipe unavailable")
    descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    with os.fdopen(descriptor, "rb") as stream:
        return stream.read(max_bytes + 1).decode("ascii")
