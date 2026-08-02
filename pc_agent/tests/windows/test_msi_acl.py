from __future__ import annotations

from pathlib import Path


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

    def __init__(self) -> None:
        self.acl = _Acl()
        self.applied = None
        self.lookups: list[str] = []

    def ACL(self) -> _Acl:
        return self.acl

    def LookupAccountName(self, _system, principal: str):
        self.lookups.append(principal)
        return principal, "", 0

    def ConvertStringSidToSid(self, value: str) -> str:
        return value

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
