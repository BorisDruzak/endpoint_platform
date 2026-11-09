"""Offline bootstrap file authority shared by native facts and Support.

Keep this primitive free of Support runtime/network imports. ACL principals,
rights and path checks are the existing protected enrollment-file boundary.
"""
from pathlib import Path
import stat

TRUSTED_SIDS = {'S-1-5-18', 'S-1-5-32-544'}
# Exact identities already present in the canonical Agent172 data ACL policy.
# They are bootstrap readers/writers only, never principals in Support ACLs.
BOOTSTRAP_SERVICE_SIDS = (
    'S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691',
    'S-1-5-80-327494974-20047353-929432329-1920152597-707704661',
)


def reject_links(path: Path):
    for item in [*reversed(path.parents), path]:
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise ValueError('unsafe_support_path')
        if not stat.S_ISDIR(info.st_mode) and info.st_nlink != 1:
            raise ValueError('unsafe_support_path')


def assert_bootstrap_file(path: Path):
    reject_links(path)
    if not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('support_enrollment_unavailable')
    import win32security as security
    descriptor = security.GetNamedSecurityInfo(str(path),security.SE_FILE_OBJECT,
        security.OWNER_SECURITY_INFORMATION|security.DACL_SECURITY_INFORMATION)
    trusted = TRUSTED_SIDS|{'S-1-5-19'}
    if security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in trusted:
        raise ValueError('support_enrollment_unavailable')
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None:
        raise ValueError('support_enrollment_unavailable')
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        if len(ace)!=3 or ace[0][0]!=security.ACCESS_ALLOWED_ACE_TYPE:
            raise ValueError('support_enrollment_unavailable')
        sid=security.ConvertSidToStringSid(ace[2])
        if sid in trusted:
            continue
        import ntsecuritycon
        credential=path.name in {'device-credential','endpoint-ca.crt'}
        allowed={BOOTSTRAP_SERVICE_SIDS[0]:ntsecuritycon.FILE_GENERIC_READ,
                 BOOTSTRAP_SERVICE_SIDS[1]:ntsecuritycon.FILE_GENERIC_WRITE}
        if not credential:
            allowed=dict.fromkeys(BOOTSTRAP_SERVICE_SIDS,
                ntsecuritycon.FILE_GENERIC_READ|ntsecuritycon.FILE_GENERIC_WRITE|ntsecuritycon.DELETE)
        if sid not in allowed or ace[1]&~allowed[sid]:
            raise ValueError('support_enrollment_unavailable')


def read_optional_bootstrap_ascii(path: Path, *, default: str) -> str:
    """Default only for a missing leaf under an existing, non-reparse directory.

    Origin policy belongs to the caller. Existing files retain all bootstrap
    protection checks; access errors and dangling links never imply absence.
    """
    reject_links(path)
    try:
        path.lstat()
    except FileNotFoundError:
        if not stat.S_ISDIR(path.parent.stat().st_mode):
            raise ValueError('support_enrollment_unavailable')
        return default
    assert_bootstrap_file(path)
    return path.read_text(encoding='ascii').strip()
