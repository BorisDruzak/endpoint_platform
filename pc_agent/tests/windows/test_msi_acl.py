from __future__ import annotations

from pathlib import Path

import pytest


class _Acl:
    def __init__(self) -> None:
        self.aces: list[tuple[int, int, str]] = []

    def AddAccessAllowedAceEx(self, _revision: int, inheritance: int, mask: int, sid: str) -> None:
        self.aces.append((inheritance, mask, sid))


class _Security:
    ACL_REVISION = 2
    OBJECT_INHERIT_ACE = 1
    CONTAINER_INHERIT_ACE = 2
    SE_FILE_OBJECT = 3
    DACL_SECURITY_INFORMATION = 4
    PROTECTED_DACL_SECURITY_INFORMATION = 8
    OWNER_SECURITY_INFORMATION = 16

    def __init__(self) -> None:
        self.acl = _Acl()
        self.applied = None
        self.lookups: list[str] = []
        self.owners: dict[str, str] = {}

    def ACL(self) -> _Acl:
        return self.acl

    def LookupAccountName(self, _system, principal: str):
        self.lookups.append(principal)
        return principal, "", 0

    def ConvertStringSidToSid(self, value: str) -> str:
        return value

    def ConvertSidToStringSid(self, value: str) -> str:
        return value

    def GetNamedSecurityInfo(self, path: str, *_args):
        owner = self.owners.get(path, "S-1-5-32-544")

        class _Descriptor:
            def GetSecurityDescriptorOwner(self) -> str:
                return owner

        return _Descriptor()

    def SetNamedSecurityInfo(self, *args) -> None:
        self.applied = args


class _Rights:
    FILE_ALL_ACCESS = 0x1
    FILE_GENERIC_READ = 0x2
    FILE_GENERIC_WRITE = 0x4
    DELETE = 0x8


def test_msi_acl_replaces_inheritance_with_exact_machine_policy(tmp_path: Path) -> None:
    """Adding ACEs to an inherited installer DACL would leave unknown writers behind."""
    from pc_agent.platform.windows.acl import replace_machine_data_acl

    security = _Security()
    replace_machine_data_acl(tmp_path, win32security=security, ntsecuritycon=_Rights)

    assert security.applied is not None
    assert security.applied[0] == str(tmp_path)
    assert security.applied[2] == 12  # DACL_SECURITY_INFORMATION | PROTECTED_DACL...
    assert security.applied[5] is security.acl
    assert security.acl.aces == [
        (3, 0x1, "S-1-5-18"),
        (3, 0x1, "S-1-5-32-544"),
        (3, 0xE, "NT SERVICE\\EndpointAgent"),
        (3, 0xC, "NT SERVICE\\EndpointAgentUpdater"),
    ]
    assert security.lookups == [
        "NT SERVICE\\EndpointAgent",
        "NT SERVICE\\EndpointAgentUpdater",
    ]


def test_provisioning_acl_uses_well_known_builtin_sids_on_localized_windows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A localized Windows host may not resolve the English Administrators label."""
    from pc_agent.platform.windows.acl import PyWin32AclAdapter

    security = _Security()
    monkeypatch.setattr(
        PyWin32AclAdapter,
        "_modules",
        staticmethod(lambda: (security, _Rights)),
    )
    credential = tmp_path / "device-credential"
    credential.write_text("placeholder", encoding="ascii")

    PyWin32AclAdapter().protect_credential(credential)

    assert security.lookups == [
        "NT SERVICE\\EndpointAgent",
        "NT SERVICE\\EndpointAgentUpdater",
    ]
    assert security.acl.aces == [
        (0, 0x1, "S-1-5-18"),
        (0, 0x1, "S-1-5-32-544"),
        (0, 0x2, "NT SERVICE\\EndpointAgent"),
        (0, 0x4, "NT SERVICE\\EndpointAgentUpdater"),
    ]


def test_msi_acl_rejects_a_reparse_target_before_privileged_write(
    tmp_path: Path,
) -> None:
    """A junction at the data root must not redirect SYSTEM's DACL replacement."""
    from pc_agent.platform.windows.acl import WindowsAclError, replace_machine_data_acl

    real = tmp_path / "user-owned-target"
    real.mkdir()
    linked = tmp_path / "Agent"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlinks unavailable on this Windows test host: {error}")
    security = _Security()

    with pytest.raises(WindowsAclError, match="reparse"):
        replace_machine_data_acl(linked, win32security=security, ntsecuritycon=_Rights)

    assert security.applied is None


def test_msi_acl_rejects_an_untrusted_existing_owner(tmp_path: Path) -> None:
    """Replacing a user's directory DACL would convert an attacker-controlled path."""
    from pc_agent.platform.windows.acl import WindowsAclError, replace_machine_data_acl

    target = tmp_path / "Agent"
    target.mkdir()
    security = _Security()
    security.owners[str(target)] = "S-1-5-21-1000-1000-1000-1001"

    with pytest.raises(WindowsAclError, match="trusted owner"):
        replace_machine_data_acl(target, win32security=security, ntsecuritycon=_Rights)

    assert security.applied is None
