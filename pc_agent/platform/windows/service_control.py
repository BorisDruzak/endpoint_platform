"""SCM operations isolated behind a small injectable adapter."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


SERVICE_NAME = "EndpointAgent"
SERVICE_ACCOUNT = "NT AUTHORITY\\LocalService"
UPDATER_SERVICE_NAME = "EndpointAgentUpdater"
SERVICE_SID_NAMES = (SERVICE_NAME, UPDATER_SERVICE_NAME)
# Well-known SIDs avoid localized account-name lookups in the service DACL.
UPDATER_START_PRINCIPALS = ("S-1-5-18", "S-1-5-32-544", "NT SERVICE\\EndpointAgent")
SERVICE_RECOVERY_RESET_SECONDS = 24 * 60 * 60
SERVICE_RECOVERY_RESTART_DELAY_MS = 60 * 1000
SERVICE_RECOVERY_ACTIONS = "/".join(
    (f"restart/{SERVICE_RECOVERY_RESTART_DELAY_MS}",) * 3
)


class ServiceControl(Protocol):
    def start(self) -> None: ...


@dataclass(frozen=True, slots=True)
class WindowsServiceInstallSpec:
    """MSI-owned registration requirements; this module never installs a service."""

    name: str = SERVICE_NAME
    account: str = SERVICE_ACCOUNT
    start_type: str = "auto"


@dataclass(frozen=True, slots=True)
class WindowsUpdaterServiceInstallSpec:
    """MSI contract for an offline, demand-start update worker.

    The MSI applies the listed service-start DACL.  This neutral module exposes
    the policy for packaging tests without installing or starting any service.
    """

    name: str = UPDATER_SERVICE_NAME
    start_type: str = "demand"
    start_principals: tuple[str, str, str] = UPDATER_START_PRINCIPALS


def restrict_updater_start_permissions() -> None:
    """Replace the updater service DACL with its fixed SERVICE_START policy.

    This is an MSI custom-action boundary.  It accepts no service name or
    principal arguments, so a corrupted install property cannot grant service
    start rights to an arbitrary identity.
    """
    if os.name != "nt":
        raise RuntimeError("Windows SCM permissions require Windows")
    try:
        import win32con  # type: ignore[import-not-found]
        import win32security  # type: ignore[import-not-found]
        import win32service  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("pywin32 is required to protect updater start rights") from error
    scm = service = None
    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        service = win32service.OpenService(
            scm, UPDATER_SERVICE_NAME, service_dacl_write_access(win32con)
        )
        dacl = win32security.ACL()
        for principal, mask in updater_start_access_policy(
            service_all_access=win32service.SERVICE_ALL_ACCESS,
            service_start=win32service.SERVICE_START,
        ).items():
            if principal.startswith("S-"):
                sid = win32security.ConvertStringSidToSid(principal)
            else:
                sid, _domain, _kind = win32security.LookupAccountName(None, principal)
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION, mask, sid
            )
        descriptor = win32security.SECURITY_DESCRIPTOR()
        descriptor.SetSecurityDescriptorDacl(1, dacl, 0)
        win32service.SetServiceObjectSecurity(
            service, win32security.DACL_SECURITY_INFORMATION, descriptor
        )
    finally:
        if service is not None:
            win32service.CloseServiceHandle(service)
        if scm is not None:
            win32service.CloseServiceHandle(scm)


def service_dacl_write_access(win32security) -> int:
    """Return the SCM access mask used only to replace a service DACL."""
    return win32security.READ_CONTROL | win32security.WRITE_DAC


def configure_service_sids() -> None:
    """Apply the fixed virtual-SID and recovery policies to MSI-owned services."""
    if os.name != "nt":
        raise RuntimeError("Windows SCM service SID configuration requires Windows")
    try:
        import win32service  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("pywin32 is required to configure service SIDs") from error
    _configure_service_sids_with(win32service)
    configure_service_recovery()


def _configure_service_sids_with(win32service) -> None:
    """Configure only the fixed service names at the MSI custom-action boundary."""
    scm = None
    try:
        scm = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_CONNECT
        )
        for service_name in SERVICE_SID_NAMES:
            service = None
            try:
                service = win32service.OpenService(
                    scm, service_name, win32service.SERVICE_CHANGE_CONFIG
                )
                win32service.ChangeServiceConfig2(
                    service,
                    win32service.SERVICE_CONFIG_SERVICE_SID_INFO,
                    win32service.SERVICE_SID_TYPE_UNRESTRICTED,
                )
            finally:
                if service is not None:
                    win32service.CloseServiceHandle(service)
    finally:
        if scm is not None:
            win32service.CloseServiceHandle(scm)


def _windows_sc_executable() -> Path:
    """Return the system SCM utility without resolving it through a mutable PATH."""
    return Path(os.environ.get("SystemRoot", r"C:\\Windows")) / "System32" / "sc.exe"


def configure_service_recovery() -> None:
    """Set the fixed restart policy after MSI has registered both services."""
    if os.name != "nt":
        raise RuntimeError("Windows SCM recovery configuration requires Windows")
    _configure_service_recovery_with(subprocess.run, _windows_sc_executable())


def _configure_service_recovery_with(run, executable: Path) -> None:
    """Invoke only the fixed SCM recovery policy; no MSI property controls it."""
    for service_name in SERVICE_SID_NAMES:
        completed = run(
            [
                str(executable),
                "failure",
                service_name,
                "reset=",
                str(SERVICE_RECOVERY_RESET_SECONDS),
                "actions=",
                SERVICE_RECOVERY_ACTIONS,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        if completed.returncode != 0:
            raise RuntimeError("Windows SCM recovery configuration failed")


def updater_start_access_policy(*, service_all_access: int, service_start: int) -> dict[str, int]:
    """Normal SCM management for SYSTEM/Admins; start-only for EndpointAgent."""
    return {
        "S-1-5-18": service_all_access,
        "S-1-5-32-544": service_all_access,
        "NT SERVICE\\EndpointAgent": service_start,
    }


def trigger_pending_updater() -> None:
    """Start only the fixed demand-start updater using EndpointAgent's RP ACE."""
    try:
        import win32service  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("pywin32 is required to start EndpointAgentUpdater") from error
    _trigger_updater_with(win32service)


def _trigger_updater_with(win32service) -> None:
    scm = service = None
    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        service = win32service.OpenService(scm, UPDATER_SERVICE_NAME, win32service.SERVICE_START)
        win32service.StartService(service, None)
    finally:
        if service is not None:
            win32service.CloseServiceHandle(service)
        if scm is not None:
            win32service.CloseServiceHandle(scm)


class PyWin32ServiceControl:
    """Start the already-MSI-registered LocalService service."""

    def __init__(self, service_name: str = SERVICE_NAME) -> None:
        self._service_name = service_name

    def start(self) -> None:
        try:
            import win32serviceutil  # type: ignore[import-not-found]
        except ImportError as error:
            raise RuntimeError("pywin32 is required to control EndpointAgent") from error
        win32serviceutil.StartService(self._service_name)


__all__ = [
    "PyWin32ServiceControl",
    "SERVICE_ACCOUNT",
    "SERVICE_NAME",
    "ServiceControl",
    "UPDATER_SERVICE_NAME",
    "UPDATER_START_PRINCIPALS",
    "configure_service_recovery",
    "configure_service_sids",
    "WindowsServiceInstallSpec",
    "WindowsUpdaterServiceInstallSpec",
    "restrict_updater_start_permissions",
    "service_dacl_write_access",
    "updater_start_access_policy",
    "trigger_pending_updater",
]
