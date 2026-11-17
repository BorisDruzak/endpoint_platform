"""Read the verified Authenticode countersigner from Windows trust state."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
from uuid import UUID


class _FileInfo(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('path', wintypes.LPCWSTR),
                ('file', wintypes.HANDLE), ('subject', ctypes.c_void_p)]


class _TrustData(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('policy', ctypes.c_void_p),
                ('sip', ctypes.c_void_p), ('ui', wintypes.DWORD),
                ('revocation', wintypes.DWORD), ('choice', wintypes.DWORD),
                ('file', ctypes.POINTER(_FileInfo)), ('action', wintypes.DWORD),
                ('state', wintypes.HANDLE), ('url', wintypes.LPCWSTR),
                ('flags', wintypes.DWORD), ('context', wintypes.DWORD),
                ('signature_settings', ctypes.c_void_p)]


class _ProviderSigner(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('verified_as_of', wintypes.FILETIME),
                ('certificate_count', wintypes.DWORD), ('certificates', ctypes.c_void_p),
                ('signer_type', wintypes.DWORD), ('signer_info', ctypes.c_void_p),
                ('error', wintypes.DWORD), ('counter_count', wintypes.DWORD),
                ('counters', ctypes.c_void_p), ('chain', ctypes.c_void_p)]


class _ProviderCertificate(ctypes.Structure):
    # Only the prefix through pCert is used. WinTrust owns the returned context.
    _fields_ = [('size', wintypes.DWORD), ('context', ctypes.c_void_p)]


_GENERIC_VERIFY_V2 = UUID('00aac56b-cd44-11d0-8cc2-00c04fc295ee').bytes_le
_CERT_SHA1_HASH_PROP_ID = 3  # Authenticode publisher thumbprints use this property.
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800


def has_verified_timestamp(path: Path, publisher_thumbprint: str) -> bool:
    """Require a successful trust decision and its trusted primary countersigner."""
    wintrust = ctypes.WinDLL('wintrust.dll', winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32)
    crypt32 = ctypes.WinDLL('crypt32.dll', winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32)
    verify = wintrust.WinVerifyTrust
    verify.argtypes = (wintypes.HWND, ctypes.c_void_p, ctypes.POINTER(_TrustData))
    verify.restype = wintypes.LONG
    provider = wintrust.WTHelperProvDataFromStateData
    provider.argtypes = (wintypes.HANDLE,)
    provider.restype = ctypes.c_void_p
    signer = wintrust.WTHelperGetProvSignerFromChain
    signer.argtypes = (ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    signer.restype = ctypes.POINTER(_ProviderSigner)
    certificate = wintrust.WTHelperGetProvCertFromChain
    certificate.argtypes = (ctypes.POINTER(_ProviderSigner), wintypes.DWORD)
    certificate.restype = ctypes.POINTER(_ProviderCertificate)
    property_value = crypt32.CertGetCertificateContextProperty
    property_value.argtypes = (ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                               ctypes.POINTER(wintypes.DWORD))
    property_value.restype = wintypes.BOOL

    policy = ctypes.create_string_buffer(_GENERIC_VERIFY_V2)
    file_info = _FileInfo(ctypes.sizeof(_FileInfo), str(path))
    data = _TrustData(size=ctypes.sizeof(_TrustData), ui=2, choice=1,
                      file=ctypes.pointer(file_info), action=1)
    try:
        # Default Authenticode policy, file subject, no UI, keep trust state.
        if verify(-1, policy, ctypes.byref(data)) != 0 or not data.state:
            return False
        trust = provider(data.state)
        if not trust:
            return False
        primary = signer(trust, 0, False, 0)
        if not primary or primary.contents.error or primary.contents.counter_count != 1:
            return False
        primary_cert = certificate(primary, 0)
        digest = (ctypes.c_ubyte * 20)()
        size = wintypes.DWORD(len(digest))
        if (not primary_cert or not primary_cert.contents.context
                or not property_value(primary_cert.contents.context, _CERT_SHA1_HASH_PROP_ID,
                                      digest, ctypes.byref(size))
                or size.value != len(digest) or bytes(digest).hex().upper() != publisher_thumbprint):
            return False
        stamp = signer(trust, 0, True, 0)
        if not stamp or stamp.contents.error or not stamp.contents.chain:
            return False
        stamp_cert = certificate(stamp, 0)
        return bool(stamp_cert and stamp_cert.contents.context)
    finally:
        if data.state:
            data.action = 2  # WTD_STATEACTION_CLOSE
            verify(-1, policy, ctypes.byref(data))
