"""Windows DACL policy for protected Endpoint Agent state."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


SYSTEM_PRINCIPAL = "SYSTEM"
ADMINISTRATORS_PRINCIPAL = "Administrators"
SERVICE_PRINCIPAL = "NT SERVICE\\EndpointAgent"
UPDATER_PRINCIPAL = "NT SERVICE\\EndpointAgentUpdater"
EXPECTED_PRINCIPALS = (
    SYSTEM_PRINCIPAL,
    ADMINISTRATORS_PRINCIPAL,
    SERVICE_PRINCIPAL,
    UPDATER_PRINCIPAL,
)


class WindowsAclError(RuntimeError):
    """The protected Windows DACL could not be applied or inspected."""


class AclAdapter(Protocol):
    def protect_directory(self, path: Path) -> None: ...
    def protect_credential(self, path: Path) -> None: ...
    def assert_protected_file(self, path: Path) -> None: ...


@dataclass(frozen=True, slots=True)
class AccessRule:
    principal: str
    rights: str


DIRECTORY_ACL = (
    AccessRule(SYSTEM_PRINCIPAL, "full_control"),
    AccessRule(ADMINISTRATORS_PRINCIPAL, "full_control"),
    AccessRule(SERVICE_PRINCIPAL, "modify"),
    AccessRule(UPDATER_PRINCIPAL, "modify"),
)
CREDENTIAL_ACL = (
    AccessRule(SYSTEM_PRINCIPAL, "full_control"),
    AccessRule(ADMINISTRATORS_PRINCIPAL, "full_control"),
    AccessRule(SERVICE_PRINCIPAL, "read"),
    # The updater can atomically replace a credential but cannot read it.
    AccessRule(UPDATER_PRINCIPAL, "write"),
)


class PyWin32AclAdapter:
    """Apply explicit DACLs without importing pywin32 on non-Windows hosts."""

    def protect_directory(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        self._apply(path, DIRECTORY_ACL)

    def protect_credential(self, path: Path) -> None:
        self._apply(path, CREDENTIAL_ACL)

    def assert_protected_file(self, path: Path) -> None:
        if not path.is_file():
            raise WindowsAclError("protected enrollment material is missing")
        self._require_windows()
        # Re-applying the fixed DACL rejects inherited ordinary-user access.
        self._apply(path, CREDENTIAL_ACL)

    def _apply(self, path: Path, rules: tuple[AccessRule, ...]) -> None:
        if os.name != "nt":
            # Test hosts cannot model Windows virtual accounts.  Restrict the
            # local fallback so accidental broad POSIX access is still avoided.
            if path.is_dir():
                path.chmod(stat.S_IRWXU)
            else:
                path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            return
        win32security, ntsecuritycon = self._modules()
        acl = win32security.ACL()
        rights = {
            "full_control": ntsecuritycon.FILE_ALL_ACCESS,
            "modify": ntsecuritycon.FILE_GENERIC_READ
            | ntsecuritycon.FILE_GENERIC_WRITE
            | ntsecuritycon.DELETE,
            "read": ntsecuritycon.FILE_GENERIC_READ,
            "write": ntsecuritycon.FILE_GENERIC_WRITE,
        }
        try:
            for rule in rules:
                sid, _domain, _kind = win32security.LookupAccountName(None, rule.principal)
                acl.AddAccessAllowedAce(win32security.ACL_REVISION, rights[rule.rights], sid)
            win32security.SetNamedSecurityInfo(
                str(path),
                win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION
                | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                acl,
                None,
            )
        except Exception as error:  # pywin32 exposes several platform-specific errors
            raise WindowsAclError("could not apply Endpoint Agent DACL") from error

    @staticmethod
    def _modules():
        try:
            import ntsecuritycon  # type: ignore[import-not-found]
            import win32security  # type: ignore[import-not-found]
        except ImportError as error:
            raise WindowsAclError("pywin32 is required for Windows ACLs") from error
        return win32security, ntsecuritycon

    @staticmethod
    def _require_windows() -> None:
        if os.name != "nt":
            raise WindowsAclError("protected-file ACL inspection requires Windows")


__all__ = [
    "ADMINISTRATORS_PRINCIPAL",
    "AclAdapter",
    "CREDENTIAL_ACL",
    "DIRECTORY_ACL",
    "EXPECTED_PRINCIPALS",
    "PyWin32AclAdapter",
    "SERVICE_PRINCIPAL",
    "SYSTEM_PRINCIPAL",
    "UPDATER_PRINCIPAL",
    "WindowsAclError",
]
