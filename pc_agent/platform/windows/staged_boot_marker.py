"""Operation-bound HKLM boot witnesses; no clock, log or kernel GUID fallback.

Only the signed initial owner creates/flushed persistent witnesses. Recovery
never recreates them. Product cleanup must not delete witnesses/live markers.
SYSTEM and administrators are the trusted registry authority boundary.
"""
from contextlib import contextmanager
from uuid import UUID, uuid4

from . import durable_state

ROOT = r'SOFTWARE\EndpointPlatformStagedBoot'
_SDDL = 'O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)'
_PREFIX = 'registry-boot-v1:'


def _fail():
    raise ValueError('RECOVERY_REQUIRED')


def _uuid(value):
    try:
        parsed = UUID(value)
        return isinstance(value, str) and str(parsed) == value and parsed.int != 0
    except (ValueError, TypeError, AttributeError):
        return False


def valid_token(value):
    return isinstance(value, str) and value.startswith(_PREFIX) and _uuid(value[len(_PREFIX):])


def _secure(key):
    import winreg
    import win32security
    if winreg.QueryInfoKey(int(key))[1] != 0:
        _fail()  # Reject REG_LINK values before any descriptor API can follow.
    descriptor = win32security.GetSecurityInfo(int(key), win32security.SE_REGISTRY_KEY, 7)
    dacl = descriptor.GetSecurityDescriptorDacl()
    if (dacl is None or dacl.GetAceCount() != 2
            or not descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED
            or win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) != 'S-1-5-32-544'
            or win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorGroup()) != 'S-1-5-32-544'):
        _fail()
    expected = {'S-1-5-18', 'S-1-5-32-544'}
    actual = set()
    for index in range(2):
        kind, mask, sid = dacl.GetAce(index)
        identity = win32security.ConvertSidToStringSid(sid)
        if kind != (0, 2) or mask != 0xF003F or identity not in expected:
            _fail()
        actual.add(identity)
    if actual != expected:
        _fail()


def _open(parent, name, *, missing_ok=False):
    import win32api
    import pywintypes
    try:
        # REG_OPTION_OPEN_LINK: inspect the key itself; link values are denied
        # by the empty-value invariant. Always use the machine 64-bit view.
        key = win32api.RegOpenKeyEx(parent, name, 8, 0x20119 | 0x100)
    except pywintypes.error as error:
        if missing_ok and error.winerror == 2:
            return None
        _fail()
    try:
        _secure(key)
        return key
    except pywintypes.error:
        key.Close()
        _fail()
    except BaseException:
        key.Close()
        raise


@contextmanager
def _witness(operation_id):
    import win32con
    if not _uuid(operation_id):
        _fail()
    root = _open(win32con.HKEY_LOCAL_MACHINE, ROOT)
    try:
        witness = _open(root, operation_id)
        try:
            yield witness
        finally:
            witness.Close()
    finally:
        root.Close()


def present(operation_id, token):
    if not valid_token(token):
        _fail()
    with _witness(operation_id) as witness:
        leaf = _open(witness, 'boot-' + token[len(_PREFIX):], missing_ok=True)
        if leaf is None:
            return False
        leaf.Close()
        return True


def capture(operation_id):
    """Fresh marker for a conservative gate, before a native attempt starts."""
    import win32api
    import win32security
    import pywintypes
    durable_state.installer_mutation_checkpoint(required=True)
    nonce = str(uuid4())
    security = pywintypes.SECURITY_ATTRIBUTES()
    security.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(_SDDL, 1)
    with _witness(operation_id) as witness:
        durable_state.installer_mutation_checkpoint(required=True)
        key, disposition = win32api.RegCreateKeyEx(witness, 'boot-'+nonce, 0xF003F | 0x100,
            Options=1, SecurityAttributes=security)
        try:
            if disposition != 1:
                _fail()
            _secure(key)
            durable_state.installer_mutation_checkpoint(required=True)
        finally:
            key.Close()
    return _PREFIX + nonce
