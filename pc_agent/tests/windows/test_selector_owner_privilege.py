"""Elevated administrators must preserve SYSTEM-owned selectors without leakage."""
import os

import pytest

from pc_agent.platform.windows import acl

pytestmark = pytest.mark.skipif(os.name != "nt", reason="native Windows tokens and NTFS")


@pytest.fixture
def system_selector(tmp_path):
    import win32api
    import win32security as security

    token = security.OpenProcessToken(win32api.GetCurrentProcess(), 0x2A)
    restore = security.LookupPrivilegeValue(None, "SeRestorePrivilege")
    privileges = dict(security.GetTokenInformation(token, security.TokenPrivileges))
    if restore not in privileges:
        token.Close()
        pytest.skip("requires an elevated administrator with restore privilege")
    original = privileges[restore]
    descriptor = security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1)
    security.SetNamedSecurityInfo(str(tmp_path), security.SE_FILE_OBJECT,
        security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, descriptor.GetSecurityDescriptorDacl(), None)
    source, temporary = tmp_path / "current.json", tmp_path / "temporary.json"
    source.write_bytes(b"original")
    temporary.write_bytes(b"replacement")
    try:
        security.AdjustTokenPrivileges(token, False, [(restore, 2)])
        security.SetNamedSecurityInfo(str(source), security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION,
            security.ConvertStringSidToSid("S-1-5-18"), None, None, None)
        security.AdjustTokenPrivileges(token, False, [(restore, 0)])
        yield source, temporary, token, restore
    finally:
        security.AdjustTokenPrivileges(token, False, [(restore, original)])
        token.Close()


@pytest.mark.parametrize("initial_attributes", [0, 2])
def test_elevated_copy_preserves_system_owner_and_restores_privilege(system_selector, initial_attributes):
    import win32security as security
    source, temporary, token, restore = system_selector
    security.AdjustTokenPrivileges(token, False, [(restore, initial_attributes)])

    acl.preserve_state_file_permissions(source, temporary)

    acl.assert_state_file_permissions_match(source, temporary)
    assert security.ConvertSidToStringSid(
        security.GetFileSecurity(str(temporary), 1).GetSecurityDescriptorOwner()) == "S-1-5-18"
    assert dict(security.GetTokenInformation(token, security.TokenPrivileges))[restore] == initial_attributes
    assert source.read_bytes() == b"original"


def test_failed_owner_copy_restores_disabled_privilege(system_selector, monkeypatch):
    import pywintypes
    import win32security as security
    source, temporary, token, restore = system_selector
    real_set = security.SetNamedSecurityInfo
    observed = []

    def denied(path, *args):
        if path == str(temporary):
            observed.append(dict(security.GetTokenInformation(token, security.TokenPrivileges))[restore] & 2)
            raise pywintypes.error(5, "SetNamedSecurityInfo", "diagnostic failure")
        return real_set(path, *args)

    monkeypatch.setattr(security, "SetNamedSecurityInfo", denied)
    with pytest.raises(acl.WindowsAclError):
        acl.preserve_state_file_permissions(source, temporary)
    assert dict(security.GetTokenInformation(token, security.TokenPrivileges))[restore] == 0
    assert observed == [2]
    assert source.read_bytes() == b"original"


@pytest.mark.parametrize("remove_restore", [False, True])
def test_copy_uses_effective_thread_token_without_process_privilege_leak(system_selector, remove_restore):
    import win32security as security
    source, temporary, process_token, restore = system_selector
    restricted = security.CreateRestrictedToken(
        process_token, 0, [], [(restore, 0)] if remove_restore else [], [])
    thread_token = security.DuplicateToken(restricted, security.SecurityImpersonation)
    try:
        security.ImpersonateLoggedOnUser(thread_token)
        try:
            if remove_restore:
                with pytest.raises(acl.WindowsAclError):
                    acl.preserve_state_file_permissions(source, temporary)
                assert security.ConvertSidToStringSid(
                    security.GetFileSecurity(str(temporary), 1).GetSecurityDescriptorOwner()) != "S-1-5-18"
            else:
                acl.preserve_state_file_permissions(source, temporary)
                acl.assert_state_file_permissions_match(source, temporary)
                assert dict(security.GetTokenInformation(thread_token, security.TokenPrivileges))[restore] == 0
        finally:
            security.RevertToSelf()
        assert dict(security.GetTokenInformation(process_token, security.TokenPrivileges))[restore] == 0
    finally:
        thread_token.Close()
        restricted.Close()
