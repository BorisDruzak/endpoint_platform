"""SCM operations isolated behind a small injectable adapter."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol


SERVICE_NAME = "EndpointAgent"
SERVICE_ACCOUNT = "NT AUTHORITY\\LocalService"
UPDATER_SERVICE_NAME = "EndpointAgentUpdater"
UPDATER_START_PRINCIPALS = ("SYSTEM", "Administrators", "NT SERVICE\\EndpointAgent")


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
        import win32security  # type: ignore[import-not-found]
        import win32service  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("pywin32 is required to protect updater start rights") from error
    scm = service = None
    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        service = win32service.OpenService(
            scm, UPDATER_SERVICE_NAME, win32service.READ_CONTROL | win32service.WRITE_DAC
        )
        dacl = win32security.ACL()
        for principal in UPDATER_START_PRINCIPALS:
            sid, _domain, _kind = win32security.LookupAccountName(None, principal)
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION, win32service.SERVICE_START, sid
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
    "WindowsServiceInstallSpec",
    "WindowsUpdaterServiceInstallSpec",
    "restrict_updater_start_permissions",
]
