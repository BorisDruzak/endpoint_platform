"""LocalService entrypoint for the neutral, headless Endpoint Agent runtime."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Protocol, TYPE_CHECKING

from pc_agent.device_credential import read_device_credential
from pc_agent.enrollment_identity import ENROLLMENT_IDENTITY_FILENAME, read_enrollment_device_id
from pc_agent.version import EXIT_UPDATE_PENDING

from .service_control import SERVICE_ACCOUNT, SERVICE_NAME

if TYPE_CHECKING:
    from pc_agent.runtime.application import RuntimeSettings


class ScmStatusAdapter(Protocol):
    def report_start_pending(self) -> None: ...
    def report_running(self) -> None: ...
    def report_stop_pending(self) -> None: ...
    def report_stopped(self, exit_code: int) -> None: ...


class ServiceCoordinator:
    """Translate SCM stop controls into cancellation of the neutral runtime."""

    def __init__(
        self,
        run_agent: Callable[[], Awaitable[int]],
        scm: ScmStatusAdapter,
    ) -> None:
        self._run_agent = run_agent
        self._scm = scm
        self._task: asyncio.Task[int] | None = None
        self._stop_reported = False

    async def run(self) -> int:
        self._scm.report_start_pending()
        self._scm.report_running()
        self._task = asyncio.create_task(self._run_agent())
        exit_code = 0
        try:
            exit_code = await self._task
            return exit_code
        except asyncio.CancelledError:
            return 0
        finally:
            self._report_stop_pending()
            self._scm.report_stopped(exit_code)

    def request_stop(self) -> None:
        self._request_stop()

    def request_shutdown(self) -> None:
        self._request_stop()

    def _request_stop(self) -> None:
        self._report_stop_pending()
        if self._task is not None and not self._task.done():
            self._task.cancel()

    def _report_stop_pending(self) -> None:
        if not self._stop_reported:
            self._scm.report_stop_pending()
            self._stop_reported = True


def safe_status(settings: "RuntimeSettings") -> dict[str, object]:
    """Return only non-secret service readiness facts for ``--print-safe-status``."""
    credential = "invalid"
    identity = "invalid"
    configuration = "invalid"
    try:
        settings.validate()
        configuration = "valid"
        read_device_credential(settings.data_root / "device-credential")
        credential = "present"
        read_enrollment_device_id(settings.data_root / ENROLLMENT_IDENTITY_FILENAME)
        identity = "present"
    except Exception:
        pass
    return {
        "service": SERVICE_NAME,
        "account": SERVICE_ACCOUNT,
        "configuration": configuration,
        "credential": credential,
        "identity": identity,
    }


def print_safe_status(settings: "RuntimeSettings") -> int:
    print(json.dumps(safe_status(settings), separators=(",", ":"), sort_keys=True))
    return 0


def run_windows_service(settings: "RuntimeSettings") -> int:
    """Dispatch the MSI-registered service through pywin32 only on Windows."""
    try:
        import servicemanager  # type: ignore[import-not-found]
        import win32service  # type: ignore[import-not-found]
        import win32serviceutil  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("pywin32 is required for --windows-service") from error

    from pc_agent.runtime.application import run_runtime

    class _PyWin32StatusAdapter:
        def __init__(self, service) -> None:
            self._service = service

        def report_start_pending(self) -> None:
            self._service.ReportServiceStatus(win32service.SERVICE_START_PENDING)

        def report_running(self) -> None:
            self._service.ReportServiceStatus(win32service.SERVICE_RUNNING)

        def report_stop_pending(self) -> None:
            self._service.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

        def report_stopped(self, _exit_code: int) -> None:
            self._service.ReportServiceStatus(win32service.SERVICE_STOPPED)

    class EndpointAgentWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = "Endpoint Agent"
        _svc_description_ = "Headless Endpoint Agent Gateway runtime"

        def __init__(self, args) -> None:
            super().__init__(args)
            self._coordinator: ServiceCoordinator | None = None

        def SvcDoRun(self) -> None:
            self._coordinator = ServiceCoordinator(
                lambda: run_runtime(settings), _PyWin32StatusAdapter(self)
            )
            asyncio.run(self._coordinator.run())

        def SvcStop(self) -> None:
            if self._coordinator is not None:
                self._coordinator.request_stop()

        def SvcShutdown(self) -> None:
            if self._coordinator is not None:
                self._coordinator.request_shutdown()

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(EndpointAgentWindowsService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0


__all__ = [
    "SERVICE_ACCOUNT",
    "SERVICE_NAME",
    "ScmStatusAdapter",
    "ServiceCoordinator",
    "print_safe_status",
    "run_windows_service",
    "safe_status",
]
