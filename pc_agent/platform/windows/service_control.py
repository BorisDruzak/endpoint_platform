"""SCM operations isolated behind a small injectable adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


SERVICE_NAME = "EndpointAgent"
SERVICE_ACCOUNT = "NT AUTHORITY\\LocalService"
UPDATER_SERVICE_NAME = "EndpointAgentUpdater"


class ServiceControl(Protocol):
    def start(self) -> None: ...


@dataclass(frozen=True, slots=True)
class WindowsServiceInstallSpec:
    """MSI-owned registration requirements; this module never installs a service."""

    name: str = SERVICE_NAME
    account: str = SERVICE_ACCOUNT
    start_type: str = "auto"


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
    "WindowsServiceInstallSpec",
]
