"""Native parent-DACL validation must leave inherited enrollment leaves unchanged."""
import ctypes
import os
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import acl


@pytest.mark.skipif(os.name != "nt", reason="native Windows security descriptors")
@pytest.mark.parametrize("updater_rights", ["0x130116", "0x13019f"])
def test_existing_root_and_inherited_leaf_descriptors_are_preserved(tmp_path, monkeypatch, updater_rights):
    import ntsecuritycon
    import win32security as security
    from pc_agent.platform.windows.update_transaction import _SERVICE_SIDS

    if not ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip("native protected owner fixture requires administrator")
    root = tmp_path / "data"
    root.mkdir()
    sddl = ("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
            f"(A;OICI;0x13019f;;;{_SERVICE_SIDS[0]})"
            f"(A;OICI;{updater_rights};;;{_SERVICE_SIDS[1]})")
    descriptor = security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)
    security.SetNamedSecurityInfo(str(root), security.SE_FILE_OBJECT,
        security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
        security.ConvertStringSidToSid("S-1-5-32-544"), None, descriptor.GetSecurityDescriptorDacl(), None)
    identity = root / "identity-fixture.json"
    credential = root / "credential-fixture"
    identity.write_bytes(b"public identity fixture")
    credential.write_bytes(b"public credential fixture")
    objects = (root, identity, credential)
    information = security.OWNER_SECURITY_INFORMATION | security.GROUP_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION

    def descriptors():
        return [bytes(security.GetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT, information)) for path in objects]

    class NativeFixtureSecurity:
        """Real root/leaf APIs; isolated ancestors and fixed virtual account lookup."""
        def __getattr__(self, name):
            return getattr(security, name)

        def GetNamedSecurityInfo(self, path, *args):
            if path == str(root) or path.startswith(str(root) + os.sep):
                return security.GetNamedSecurityInfo(path, *args)
            # Never modify the shared pytest ancestor directories' ownership.
            return security.ConvertStringSecurityDescriptorToSecurityDescriptor("O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)", 1)

        def LookupAccountName(self, _system, principal):
            sid = _SERVICE_SIDS[(acl.SERVICE_PRINCIPAL, acl.UPDATER_PRINCIPAL).index(principal)]
            return security.ConvertStringSidToSid(sid), "", 0

    monkeypatch.setattr(acl, "MACHINE_DATA_ROOT", root)
    monkeypatch.setattr(acl.PyWin32AclAdapter, "_modules", staticmethod(lambda: (NativeFixtureSecurity(), ntsecuritycon)))
    before = descriptors()
    acl.apply_machine_data_acl()
    assert descriptors() == before
    assert identity.read_bytes() == b"public identity fixture"
    assert credential.read_bytes() == b"public credential fixture"

    # Exercise the complete data snapshot with real protected and inherited
    # leaf policies, without reading authentication contents in the snapshot.
    from pc_agent.platform.windows import installer_data_security as data
    security.SetNamedSecurityInfo(str(credential), security.SE_FILE_OBJECT,
        security.OWNER_SECURITY_INFORMATION,
        security.ConvertStringSidToSid("S-1-5-32-544"), None, None, None)
    credential.rename(root / "device-credential")
    identity.rename(root / "enrollment-identity.json")
    credential = root / "device-credential"
    identity = root / "enrollment-identity.json"
    objects = (root, identity, credential)
    acl.PyWin32AclAdapter().protect_credential(credential)
    monkeypatch.setattr(data, "_root", lambda _paths: root)
    snapshot = data._snapshot(None)
    assert snapshot["leaves"]["device-credential"] is not None
    for leaf in (credential, identity):
        approved = security.GetNamedSecurityInfo(str(leaf), security.SE_FILE_OBJECT, information)
        for invalid_sddl in ("O:BAG:BAD:NO_ACCESS_CONTROL", "O:BAG:BAD:P(A;;FA;;;WD)", "O:BAG:BAD:P(A;;FR;;;WD)"):
            invalid = security.ConvertStringSecurityDescriptorToSecurityDescriptor(invalid_sddl, 1)
            security.SetNamedSecurityInfo(str(leaf), security.SE_FILE_OBJECT,
                security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
                None, None, invalid.GetSecurityDescriptorDacl(), None)
            leaf_before = bytes(security.GetNamedSecurityInfo(str(leaf), security.SE_FILE_OBJECT, information))
            with pytest.raises((ValueError, acl.WindowsAclError)):
                data._snapshot(None)
            assert bytes(security.GetNamedSecurityInfo(str(leaf), security.SE_FILE_OBJECT, information)) == leaf_before
        security.SetNamedSecurityInfo(str(leaf), security.SE_FILE_OBJECT,
            security.DACL_SECURITY_INFORMATION | (security.PROTECTED_DACL_SECURITY_INFORMATION
                if approved.GetSecurityDescriptorControl()[0] & security.SE_DACL_PROTECTED else security.UNPROTECTED_DACL_SECURITY_INFORMATION),
            None, None, approved.GetSecurityDescriptorDacl(), None)
    data._snapshot(None)

    bad_dacl = security.GetNamedSecurityInfo(str(root), security.SE_FILE_OBJECT, security.DACL_SECURITY_INFORMATION).GetSecurityDescriptorDacl()
    bad_dacl.AddAccessAllowedAceEx(security.ACL_REVISION, 3, ntsecuritycon.FILE_GENERIC_WRITE,
                                  security.ConvertStringSidToSid("S-1-1-0"))
    security.SetNamedSecurityInfo(str(root), security.SE_FILE_OBJECT,
        security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, bad_dacl, None)
    invalid_before = descriptors()
    with pytest.raises(acl.WindowsAclError):
        acl.apply_machine_data_acl()
    assert descriptors() == invalid_before
