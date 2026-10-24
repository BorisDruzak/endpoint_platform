"""An MSI upgrade must never repair or propagate enrollment ACLs."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import acl


class Security:
    SE_FILE_OBJECT = 1
    OWNER_SECURITY_INFORMATION = 1
    GROUP_SECURITY_INFORMATION = 2
    DACL_SECURITY_INFORMATION = 4
    SE_DACL_PROTECTED = 0x1000
    ACCESS_ALLOWED_ACE_TYPE = 0
    OBJECT_INHERIT_ACE = 1
    CONTAINER_INHERIT_ACE = 2
    INHERIT_ONLY_ACE = 8
    INHERITED_ACE = 16

    def __init__(self, *, updater_mask=14):
        self.owner = "S-1-5-32-544"
        self.control = self.SE_DACL_PROTECTED
        self.entries = [((0, 3), 1, "S-1-5-18"),
                        ((0, 3), 1, "S-1-5-32-544"),
                        ((0, 3), 14, acl.SERVICE_PRINCIPAL),
                        ((0, 3), updater_mask, acl.UPDATER_PRINCIPAL)]

    def GetNamedSecurityInfo(self, *_args):
        return SimpleNamespace(GetSecurityDescriptorOwner=lambda: self.owner,
                               GetSecurityDescriptorControl=lambda: (self.control, 1),
                               GetSecurityDescriptorDacl=lambda: self)

    def parent_descriptor(self):
        parent = Security()
        parent.entries = [((0, 0), 0x1f01ff, "S-1-5-32-544")]
        return parent.GetNamedSecurityInfo()

    def GetAceCount(self):
        return len(self.entries)

    def GetAce(self, index):
        return self.entries[index]

    def LookupAccountName(self, _system, principal):
        return principal, "", 0

    def ConvertSidToStringSid(self, value):
        from pc_agent.platform.windows.update_transaction import _SERVICE_SIDS
        return {acl.SERVICE_PRINCIPAL:_SERVICE_SIDS[0],acl.UPDATER_PRINCIPAL:_SERVICE_SIDS[1]}.get(value,value)


RIGHTS = SimpleNamespace(FILE_ALL_ACCESS=1, FILE_GENERIC_READ=2,
                         FILE_GENERIC_WRITE=4, DELETE=8)


@pytest.mark.parametrize("updater_mask", [12, 14])
@pytest.mark.parametrize("flags", [0, 16])
def test_origin_keeps_existing_mutable_policies(updater_mask, flags):
    security = Security(updater_mask=updater_mask)
    security.entries = [((0, flags), mask, sid) for _, mask, sid in security.entries]
    acl._validate_machine_data_leaf_acl("endpoint-origin", security.GetNamedSecurityInfo(), security, RIGHTS)


@pytest.mark.parametrize("defect", [
    "service_write", "service_modify", "updater_read", "updater_modify", "admin_mask",
    "extra_sid", "duplicate", "deny", "flags", "inherited", "unprotected", "null",
])
def test_protected_origin_policy_rejects_noncanonical_descriptors(defect):
    security = Security()
    security.entries = [((0, 0), 1, "S-1-5-18"), ((0, 0), 1, "S-1-5-32-544"),
                        ((0, 0), 2, acl.SERVICE_PRINCIPAL), ((0, 0), 4, acl.UPDATER_PRINCIPAL)]
    if defect in {"service_write", "service_modify"}:
        security.entries[2] = ((0, 0), 4 if defect == "service_write" else 14, acl.SERVICE_PRINCIPAL)
    elif defect in {"updater_read", "updater_modify"}:
        security.entries[3] = ((0, 0), 2 if defect == "updater_read" else 14, acl.UPDATER_PRINCIPAL)
    elif defect == "admin_mask":
        security.entries[1] = ((0, 0), 14, "S-1-5-32-544")
    elif defect in {"extra_sid", "duplicate"}:
        security.entries.append(((0, 0), 1, "S-1-1-0" if defect == "extra_sid" else "S-1-5-18"))
    elif defect in {"deny", "flags", "inherited"}:
        security.entries[0] = ((1 if defect == "deny" else 0,
                                8 if defect == "flags" else 16 if defect == "inherited" else 0),
                               1, "S-1-5-18")
    elif defect == "unprotected":
        security.control = 0
    descriptor = security.GetNamedSecurityInfo()
    if defect == "null":
        descriptor.GetSecurityDescriptorDacl = lambda: None
    with pytest.raises(acl.WindowsAclError):
        acl._validate_machine_data_leaf_acl("endpoint-origin", descriptor, security, RIGHTS)


def test_identity_does_not_accept_the_protected_origin_policy():
    security = Security()
    security.entries = [((0, 0), 1, "S-1-5-18"), ((0, 0), 1, "S-1-5-32-544"),
                        ((0, 0), 2, acl.SERVICE_PRINCIPAL), ((0, 0), 4, acl.UPDATER_PRINCIPAL)]
    with pytest.raises(acl.WindowsAclError):
        acl._validate_machine_data_leaf_acl("enrollment-identity.json", security.GetNamedSecurityInfo(), security, RIGHTS)


@pytest.mark.parametrize('target',['root','credential','identity'])
def test_existing_data_validation_survives_removed_service_registration(installed_root,monkeypatch,target):
    security=Security()
    def absent(*_args):raise RuntimeError('LookupAccountName: service absent (1332)')
    security.LookupAccountName=absent
    monkeypatch.setattr(acl.PyWin32AclAdapter,'_modules',staticmethod(lambda:(security,RIGHTS)))
    if target=='root':acl.apply_machine_data_acl()
    else:
        credential=target=='credential'
        security.entries=[((0,16),1,'S-1-5-18'),((0,16),1,'S-1-5-32-544'),
            ((0,16),2 if credential else 14,acl.SERVICE_PRINCIPAL),
            ((0,16),4 if credential else 12,acl.UPDATER_PRINCIPAL)]
        descriptor=security.GetNamedSecurityInfo()
        acl._validate_machine_data_leaf_acl('device-credential' if credential else 'enrollment-identity.json',
            descriptor,security,RIGHTS)


@pytest.fixture
def installed_root(tmp_path, monkeypatch):
    monkeypatch.setattr(acl, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(acl, "MACHINE_DATA_ROOT", tmp_path)
    monkeypatch.setattr(acl, "replace_machine_data_acl",
                        lambda *_args, **_kwargs: pytest.fail("existing root ACL rewritten"))
    # Unit fixtures model protected containing directories independently of
    # the service-writable leaf root; native tests cover real descriptors.
    return tmp_path


@pytest.mark.parametrize("mask", [0x40, 0x40000, 0x80000, 0x10000, 0x40000000])
def test_effective_parent_namespace_writer_is_rejected(installed_root, monkeypatch, mask):
    security = Security()
    original = security.GetNamedSecurityInfo
    def descriptor(path, *args):
        if path == str(installed_root.parent):
            parent = Security()
            parent.entries = [((0, 0), mask, "S-1-1-0")]
            return parent.GetNamedSecurityInfo()
        return original(path, *args)
    security.GetNamedSecurityInfo = descriptor
    monkeypatch.setattr(acl.PyWin32AclAdapter, "_modules", staticmethod(lambda: (security, RIGHTS)))
    with pytest.raises(acl.WindowsAclError):
        acl.apply_machine_data_acl()


def test_parent_inherit_only_writer_is_not_an_effective_namespace_grant(installed_root, monkeypatch):
    security = Security()
    original = security.GetNamedSecurityInfo
    def descriptor(path, *args):
        if path == str(installed_root.parent):
            parent = Security()
            parent.entries = [((0, parent.INHERIT_ONLY_ACE), 0x1f01ff, "S-1-1-0")]
            return parent.GetNamedSecurityInfo()
        return original(path, *args)
    security.GetNamedSecurityInfo = descriptor
    monkeypatch.setattr(acl.PyWin32AclAdapter, "_modules", staticmethod(lambda: (security, RIGHTS)))
    acl.apply_machine_data_acl()


@pytest.mark.parametrize("updater_mask", [12, 14])
def test_existing_installer_or_provisioning_policy_is_read_only(installed_root, monkeypatch, updater_mask):
    security = Security(updater_mask=updater_mask)
    monkeypatch.setattr(acl.PyWin32AclAdapter, "_modules", staticmethod(lambda: (security, RIGHTS)))
    acl.apply_machine_data_acl()


@pytest.mark.parametrize("defect", ["owner", "unprotected", "null", "writer", "duplicate", "deny", "flags", "mask"])
def test_invalid_existing_policy_fails_without_normalization(installed_root, monkeypatch, defect):
    security = Security()
    if defect == "owner":
        security.owner = "S-1-5-21-1001"
    elif defect == "unprotected":
        security.control = 0
    elif defect == "null":
        security.GetNamedSecurityInfo = lambda *_args: SimpleNamespace(
            GetSecurityDescriptorOwner=lambda: security.owner,
            GetSecurityDescriptorControl=lambda: (security.control, 1),
            GetSecurityDescriptorDacl=lambda: None)
    elif defect in {"writer", "duplicate"}:
        security.entries.append(((0, 3), 1, "S-1-1-0" if defect == "writer" else "S-1-5-18"))
    else:
        security.entries[0] = ((1 if defect == "deny" else 0, 0 if defect == "flags" else 3),
                               15 if defect == "mask" else 1, "S-1-5-18")
    monkeypatch.setattr(acl.PyWin32AclAdapter, "_modules", staticmethod(lambda: (security, RIGHTS)))
    with pytest.raises(acl.WindowsAclError):
        acl.apply_machine_data_acl()


def test_absent_root_uses_existing_fresh_install_initializer(tmp_path, monkeypatch):
    target = tmp_path / "absent"
    calls = []
    monkeypatch.setattr(acl, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(acl, "MACHINE_DATA_ROOT", target)
    monkeypatch.setattr(acl.PyWin32AclAdapter, "_modules", staticmethod(lambda: (Security(), RIGHTS)))
    monkeypatch.setattr(acl, "replace_machine_data_acl", lambda path, **kwargs: calls.append(path))
    acl.apply_machine_data_acl()
    assert calls == [target]


def test_owner_changed_in_final_descriptor_is_rejected(installed_root, monkeypatch):
    security = Security()
    original = security.GetNamedSecurityInfo
    def changed(path, *args):
        descriptor = original(path, *args)
        if path == str(installed_root) and args[-1] & security.DACL_SECURITY_INFORMATION:
            descriptor.GetSecurityDescriptorOwner = lambda: "S-1-5-21-1001"
        return descriptor
    security.GetNamedSecurityInfo = changed
    monkeypatch.setattr(acl.PyWin32AclAdapter, "_modules", staticmethod(lambda: (security, RIGHTS)))
    with pytest.raises(acl.WindowsAclError):
        acl.apply_machine_data_acl()


def test_root_creation_race_never_rewrites_peer_directory(tmp_path, monkeypatch):
    target = tmp_path / "raced"
    security = Security()
    monkeypatch.setattr(acl, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(acl, "MACHINE_DATA_ROOT", target)
    monkeypatch.setattr(acl.PyWin32AclAdapter, "_modules", staticmethod(lambda: (security, RIGHTS)))
    monkeypatch.setattr(acl, "replace_machine_data_acl", lambda *_args, **_kwargs: pytest.fail("peer ACL rewritten"))
    original = Path.mkdir
    def peer_create(path, *args, **kwargs):
        if path == target:
            original(path)
            raise FileExistsError("peer won exclusive creation")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "mkdir", peer_create)
    with pytest.raises(acl.WindowsAclError, match="exclusive initialization"):
        acl.apply_machine_data_acl()
