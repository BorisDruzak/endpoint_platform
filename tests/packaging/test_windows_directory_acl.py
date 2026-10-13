"""Native access checks for the DACL authored by the MSI, with unchanged guards."""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest


@pytest.mark.skipif(os.name != 'nt', reason='native Windows ACL and restricted-token access check')
def test_msi_directory_dacl_denies_ordinary_user_mutations(tmp_path):
    import win32api
    import win32security as security
    from pc_agent.platform.windows.update_transaction import _assert_state_security
    if not ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip('native protected-owner fixture requires administrator')
    source=Path(__file__).resolve().parents[2]/'packaging/windows/wix/Components.wxs'
    namespace={'w':'http://wixtoolset.org/schemas/v4/wxs'}
    permissions=ET.parse(source).findall('.//w:CreateFolder/w:PermissionEx',namespace)
    assert len(permissions)==3
    assert len({item.get('Sddl') for item in permissions})==1
    descriptor=security.ConvertStringSecurityDescriptorToSecurityDescriptor(permissions[0].get('Sddl'),1)
    administrators=security.ConvertStringSidToSid('S-1-5-32-544')
    users=security.ConvertStringSidToSid('S-1-5-32-545')
    root=tmp_path/'installed';root.mkdir()
    security.SetNamedSecurityInfo(str(root),security.SE_FILE_OBJECT,
        security.OWNER_SECURITY_INFORMATION|security.DACL_SECURITY_INFORMATION|security.PROTECTED_DACL_SECURITY_INFORMATION,
        administrators,None,descriptor.GetSecurityDescriptorDacl(),None)
    child=root/'nested';child.mkdir()
    payload=child/'payload.bin';payload.write_bytes(b'installed fixture')
    objects=(root,child,payload)
    for path in objects:
        _assert_state_security(path)
    class Mapping(ctypes.Structure):
        _fields_=[('read',wintypes.DWORD),('write',wintypes.DWORD),('execute',wintypes.DWORD),('all',wintypes.DWORD)]
    api=ctypes.WinDLL('advapi32',use_last_error=True)
    get=api.GetNamedSecurityInfoW
    get.argtypes=[wintypes.LPCWSTR,ctypes.c_int,wintypes.DWORD]+[ctypes.POINTER(ctypes.c_void_p)]*5
    get.restype=wintypes.DWORD
    check=api.AccessCheck
    check.argtypes=[ctypes.c_void_p,wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(Mapping),ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(wintypes.BOOL)]
    check.restype=wintypes.BOOL
    free=ctypes.WinDLL('kernel32').LocalFree
    free.argtypes=[ctypes.c_void_p];free.restype=ctypes.c_void_p
    token=security.OpenProcessToken(win32api.GetCurrentProcess(),0xA)
    # A restricted Users SID requires both original and Users grants to allow
    # access; the administrator membership cannot supply extra mutation rights.
    restricted=security.CreateRestrictedToken(token,1,None,None,[(users,0)])
    impersonation=security.DuplicateToken(restricted,security.SecurityImpersonation)
    try:
        for path in objects:
            owner,group,dacl,sacl,sd=(ctypes.c_void_p() for _ in range(5))
            assert get(str(path),1,7,*[ctypes.byref(v) for v in (owner,group,dacl,sacl,sd)])==0
            try:
                mapping=Mapping(0x120089,0x120116,0x1200A9,0x1F01FF)
                for desired,allowed in [(0x1200A9,True),(2,False),(4,False),(0x40,False),
                                        (0x10000,False),(0x40000,False),(0x80000,False)]:
                    privileges=ctypes.create_string_buffer(1024)
                    size,granted,status=wintypes.DWORD(len(privileges)),wintypes.DWORD(),wintypes.BOOL()
                    assert check(sd,int(impersonation),desired,ctypes.byref(mapping),privileges,
                                 ctypes.byref(size),ctypes.byref(granted),ctypes.byref(status)),ctypes.get_last_error()
                    assert bool(status.value)==allowed,(path.name,desired,granted.value)
            finally:
                free(sd)
        bad=root/'untrusted';bad.mkdir()
        acl=security.GetNamedSecurityInfo(str(bad),security.SE_FILE_OBJECT,security.DACL_SECURITY_INFORMATION).GetSecurityDescriptorDacl()
        acl.AddAccessAllowedAce(security.ACL_REVISION,2,users)
        security.SetNamedSecurityInfo(str(bad),security.SE_FILE_OBJECT,security.DACL_SECURITY_INFORMATION,None,None,acl,None)
        with pytest.raises(ValueError,match='unrelated writer'):
            _assert_state_security(bad)
    finally:
        impersonation.Close();restricted.Close();token.Close()
