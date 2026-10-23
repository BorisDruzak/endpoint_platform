"""OS-backed local/AD principal resolution without short-name domain guesses."""
from __future__ import annotations

from collections.abc import Callable
import ctypes
from pathlib import Path
import re
import socket

_SID = re.compile(r"^S-1-(?:[0-9]+-)*[0-9]+$")
_UPN = re.compile(r"^[^\s@\\]+@[A-Za-z0-9][A-Za-z0-9.-]+$")
_TIMEOUT_MS = 1000


def _local_login(uid: int) -> str | None:
    # NSS may return short names for AD users. Only the fixed local passwd
    # database establishes that a UID belongs to a local account.
    with Path('/etc/passwd').open('rb') as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        return None
    for line in raw.decode('utf-8', errors='strict').splitlines():
        fields = line.split(':')
        if len(fields) == 7 and fields[2].isascii() and fields[2].isdigit() and int(fields[2]) == uid:
            return fields[0]
    return None


def directory_identity(uid: int, os_login: str) -> tuple[str, str] | None:
    """Verify original UPN against a separate UID-to-SID result from SSSD.

    SSSD 2.9 can return an unqualified reverse name even for an AD UID. Its
    bounded original-attribute API supplies the directory UPN instead. No
    password, LDAP DN, group membership or other original attribute is read.
    """
    class KV(ctypes.Structure):
        _fields_ = [('key', ctypes.c_char_p), ('value', ctypes.c_char_p)]

    library = ctypes.CDLL('libsss_nss_idmap.so.0')
    libc = ctypes.CDLL(None)
    libc.free.argtypes = [ctypes.c_void_p]
    libc.free.restype = None
    library.sss_nss_getsidbyid_timeout.argtypes = [ctypes.c_uint32, ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int)]
    library.sss_nss_getsidbyid_timeout.restype = ctypes.c_int
    library.sss_nss_getorigbyusername_timeout.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.POINTER(ctypes.POINTER(KV)), ctypes.POINTER(ctypes.c_int)]
    library.sss_nss_getorigbyusername_timeout.restype = ctypes.c_int
    library.sss_nss_free_kv.argtypes = [ctypes.POINTER(KV)]
    library.sss_nss_free_kv.restype = None
    pointer, kind = ctypes.c_void_p(), ctypes.c_int()
    status = library.sss_nss_getsidbyid_timeout(uid, _TIMEOUT_MS, ctypes.byref(pointer), ctypes.byref(kind))
    if status != 0 or not pointer:
        return None
    try:
        sid = ctypes.string_at(pointer).decode('ascii')
    finally:
        libc.free(pointer)
    if kind.value not in {1, 3} or not _SID.fullmatch(sid):
        return None
    values = ctypes.POINTER(KV)()
    status = library.sss_nss_getorigbyusername_timeout(os_login.encode('utf-8'), _TIMEOUT_MS, ctypes.byref(values), ctypes.byref(kind))
    if status != 0 or not values:
        return None
    try:
        attributes = {}
        for index in range(128):
            row = values[index]
            if not row.key:
                break
            if row.key in {b'objectSIDString', b'userPrincipalName'} and row.value:
                if len(row.value) > 256:
                    return None
                attributes[row.key] = row.value.decode('utf-8', errors='strict')
        else:
            return None
        if kind.value not in {1, 3} or attributes.get(b'objectSIDString') != sid:
            return None
        return sid, attributes.get(b'userPrincipalName', '')
    finally:
        library.sss_nss_free_kv(values)


def resolve_login(
    uid: int, os_login: str, *,
    directory_lookup: Callable[[int, str], tuple[str, str] | None] = directory_identity,
    local_lookup: Callable[[int], str | None] = _local_login,
    hostname: str | None = None,
) -> str | None:
    if type(uid) is not int or not 0 < uid < 2**32 or not isinstance(os_login, str) or not 1 <= len(os_login) <= 256 or any(ord(ch) < 32 or ord(ch) == 127 for ch in os_login):
        return None
    try:
        local = local_lookup(uid)
        if local is not None:
            host = hostname if hostname is not None else socket.gethostname()
            login = f'{host}\\{local}'
            return login if local == os_login and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', host) and len(login) <= 256 else None
        directory = directory_lookup(uid, os_login)
        if directory is None:
            return None
        sid, upn = directory
        return upn.casefold() if _SID.fullmatch(sid) and len(upn) <= 256 and _UPN.fullmatch(upn) else None
    except (OSError, ValueError, TypeError, AttributeError):
        return None
