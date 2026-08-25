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
MACHINE_DATA_ROOT = Path(r"C:\ProgramData\Endpoint Platform\Agent")
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
    def protect_claim(self, path: Path) -> None: ...
    def protect_credential(self, path: Path) -> None: ...
    def protect_machine_data_file(self, path: Path) -> None: ...
    def protect_update_path(self, path: Path) -> None: ...
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
MACHINE_DATA_ACL = (
    AccessRule(SYSTEM_PRINCIPAL, "full_control"),
    AccessRule(ADMINISTRATORS_PRINCIPAL, "full_control"),
    AccessRule(SERVICE_PRINCIPAL, "modify"),
    AccessRule(UPDATER_PRINCIPAL, "write_delete"),
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

    def protect_machine_data_file(self, path: Path) -> None:
        """Protect a service-managed data file after an atomic replacement."""
        self._apply(path, MACHINE_DATA_ACL)

    def protect_update_path(self, path: Path) -> None:
        """Make agent-created update handoff state readable by the fixed worker only."""
        self._apply(path, DIRECTORY_ACL)

    def protect_claim(self, path: Path) -> None:
        self._apply(path, CREDENTIAL_ACL)

    def assert_protected_file(self, path: Path) -> None:
        if not path.is_file():
            raise WindowsAclError("protected enrollment material is missing")
        self._require_windows()
        self._reject_reparse_point(path)
        win32security, _ntsecuritycon = self._modules()
        try:
            descriptor = win32security.GetNamedSecurityInfo(
                str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
            )
            dacl = descriptor.GetSecurityDescriptorDacl()
            if dacl is None:
                raise WindowsAclError("protected enrollment material has no DACL")
            allowed = _allowed_sid_strings(dacl, win32security)
        except WindowsAclError:
            raise
        except Exception as error:
            raise WindowsAclError("could not inspect enrollment material DACL") from error
        if not allowed or not allowed.issubset(_expected_sid_strings(win32security)):
            raise WindowsAclError("enrollment material is not protected")

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
            "write_delete": ntsecuritycon.FILE_GENERIC_WRITE | ntsecuritycon.DELETE,
        }
        try:
            for rule in rules:
                if rule.principal == SYSTEM_PRINCIPAL:
                    sid = win32security.ConvertStringSidToSid("S-1-5-18")
                elif rule.principal == ADMINISTRATORS_PRINCIPAL:
                    sid = win32security.ConvertStringSidToSid("S-1-5-32-544")
                else:
                    sid, _domain, _kind = win32security.LookupAccountName(
                        None, rule.principal
                    )
                inheritance = 0
                if path.is_dir():
                    inheritance = (
                        win32security.OBJECT_INHERIT_ACE
                        | win32security.CONTAINER_INHERIT_ACE
                    )
                acl.AddAccessAllowedAceEx(
                    win32security.ACL_REVISION, inheritance, rights[rule.rights], sid
                )
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

    @staticmethod
    def _reject_reparse_point(path: Path) -> None:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        if path.is_symlink() or attributes & 0x400:
            raise WindowsAclError("protected enrollment material must not be a reparse point")


def _assert_nonreparse_directory(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise WindowsAclError("machine data path element is missing") from error
    if path.is_symlink() or getattr(details, "st_file_attributes", 0) & 0x400:
        raise WindowsAclError("machine data path contains a reparse point")
    if not path.is_dir():
        raise WindowsAclError("machine data path element is not a directory")


def _assert_trusted_owner(path: Path, win32security) -> None:
    try:
        descriptor = win32security.GetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION,
        )
        owner = win32security.ConvertSidToStringSid(
            descriptor.GetSecurityDescriptorOwner()
        )
    except Exception as error:
        raise WindowsAclError("could not inspect machine data owner") from error
    if owner not in {"S-1-5-18", "S-1-5-32-544"}:
        raise WindowsAclError("machine data path lacks a trusted owner")


def _prepare_trusted_directory_chain(
    path: Path, trusted_root: Path, win32security
) -> list[Path]:
    path = path.absolute()
    trusted_root = trusted_root.absolute()
    try:
        relative = path.relative_to(trusted_root)
    except ValueError as error:
        raise WindowsAclError("machine data path is outside its trusted root") from error

    # Reject redirection from the volume root through the trusted root before
    # creating any missing service-owned descendants.
    ancestor_chain = list(path.parents)[::-1] + [path]
    for candidate in ancestor_chain:
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        _assert_nonreparse_directory(candidate)

    trusted_chain = [trusted_root]
    current = trusted_root
    for part in relative.parts:
        current = current / part
        trusted_chain.append(current)
    for candidate in trusted_chain:
        try:
            candidate.lstat()
        except FileNotFoundError:
            candidate.mkdir()
        _assert_nonreparse_directory(candidate)
        _assert_trusted_owner(candidate, win32security)
    return trusted_chain


def replace_machine_data_acl(
    path: Path,
    *,
    win32security,
    ntsecuritycon,
    trusted_root: Path | None = None,
) -> None:
    """Replace, rather than extend, the machine data root DACL."""
    trusted_chain = _prepare_trusted_directory_chain(
        path, trusted_root or path.parent, win32security
    )
    acl = win32security.ACL()
    rights = {
        "full_control": ntsecuritycon.FILE_ALL_ACCESS,
        "modify": (
            ntsecuritycon.FILE_GENERIC_READ
            | ntsecuritycon.FILE_GENERIC_WRITE
            | ntsecuritycon.DELETE
        ),
        "write_delete": ntsecuritycon.FILE_GENERIC_WRITE | ntsecuritycon.DELETE,
    }
    inheritance = (
        win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE
    )
    try:
        # Close the validation-to-write window as far as the path API permits.
        for candidate in trusted_chain:
            _assert_nonreparse_directory(candidate)
            _assert_trusted_owner(candidate, win32security)
        for rule in MACHINE_DATA_ACL:
            if rule.principal == SYSTEM_PRINCIPAL:
                sid = win32security.ConvertStringSidToSid("S-1-5-18")
            elif rule.principal == ADMINISTRATORS_PRINCIPAL:
                sid = win32security.ConvertStringSidToSid("S-1-5-32-544")
            else:
                sid, _domain, _kind = win32security.LookupAccountName(
                    None, rule.principal
                )
            acl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION, inheritance, rights[rule.rights], sid
            )
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
    except Exception as error:
        raise WindowsAclError("could not replace machine data DACL") from error


def apply_machine_data_acl() -> None:
    """MSI custom-action boundary with a fixed, non-caller-controlled target."""
    if os.name != "nt":
        raise WindowsAclError("machine data DACL setup requires Windows")
    win32security, ntsecuritycon = PyWin32AclAdapter._modules()
    replace_machine_data_acl(
        MACHINE_DATA_ROOT,
        win32security=win32security,
        ntsecuritycon=ntsecuritycon,
        trusted_root=Path(r"C:\ProgramData"),
    )


def _allowed_sid_strings(dacl, win32security) -> set[str]:
    return {
        win32security.ConvertSidToStringSid(dacl.GetAce(index)[2])
        for index in range(dacl.GetAceCount())
        if dacl.GetAce(index)[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE
    }


def _expected_sid_strings(win32security) -> set[str]:
    """Use well-known SID values, never localized display account names."""
    virtual_accounts = (SERVICE_PRINCIPAL, UPDATER_PRINCIPAL)
    expected = {"S-1-5-18", "S-1-5-32-544"}
    for principal in virtual_accounts:
        sid, _domain, _kind = win32security.LookupAccountName(None, principal)
        expected.add(win32security.ConvertSidToStringSid(sid))
    return expected


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
    "apply_machine_data_acl",
    "replace_machine_data_acl",
]
