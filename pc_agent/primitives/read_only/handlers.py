"""Platform adapters for bounded, non-mutating Endpoint diagnostics."""

from __future__ import annotations

import os
import socket
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime

from pydantic import ValidationError

from endpoint_contracts.read_only_primitives import (
    AdapterListParametersV1,
    AdapterListResultV1,
    AdapterSummaryV1,
    RouteGetParametersV1,
    RouteGetResultV1,
    SystemServiceStatusParametersV1,
    SystemServiceStatusResultV1,
)


_MAX_ADAPTERS = 32
_ALT_RPM = "/usr/bin/rpm"
_LINUX_UNITS = {
    "endpoint_agent": "endpoint-agent.service",
    "endpoint_agent_updater": "endpoint-agent-update.service",
}
_WINDOWS_SERVICES = {
    "endpoint_agent": "EndpointAgent",
    "endpoint_agent_updater": "EndpointAgentUpdater",
}


def _completed_at(value: datetime | None) -> datetime:
    return value or datetime.now(UTC)


def _route_source(target: str) -> tuple[str, str]:
    records = socket.getaddrinfo(target, 9, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    for family, _socket_type, _protocol, _canonical, address in records:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        connection = socket.socket(family, socket.SOCK_DGRAM)
        try:
            connection.connect(address)
            local_address = str(connection.getsockname()[0])
        finally:
            connection.close()
        return ("ipv4" if family == socket.AF_INET else "ipv6", local_address)
    raise OSError("no routable address family")


def route_get(
    parameters: RouteGetParametersV1,
    *,
    route_source: Callable[[str], tuple[str, str]] = _route_source,
    collected_at: datetime | None = None,
) -> RouteGetResultV1:
    """Read one selected route without running a command or sending a packet."""
    finished_at = _completed_at(collected_at)
    try:
        family, local_address = route_source(parameters.target)
        return RouteGetResultV1(
            schema_version="route_get_result_v1",
            target=parameters.target,
            family=family,
            local_address=local_address,
            status="succeeded",
            collected_at=finished_at,
        )
    except (OSError, UnicodeError, ValueError):
        return RouteGetResultV1(
            schema_version="route_get_result_v1",
            target=parameters.target,
            status="failed",
            error_code="route_unavailable",
            collected_at=finished_at,
        )


def adapter_list(
    _parameters: AdapterListParametersV1,
    *,
    list_interfaces: Callable[[], list[tuple[int, str]]] = socket.if_nameindex,
    collected_at: datetime | None = None,
) -> AdapterListResultV1:
    """Return a capped list of OS interface indexes and safe names only."""
    finished_at = _completed_at(collected_at)
    try:
        seen_names: set[str] = set()
        adapters: list[AdapterSummaryV1] = []
        for index, name in list_interfaces():
            try:
                item = AdapterSummaryV1(index=index, name=name)
            except ValidationError:
                continue
            if item.name in seen_names:
                continue
            seen_names.add(item.name)
            adapters.append(item)
        adapters.sort(key=lambda item: (item.index, item.name))
        adapters = adapters[:_MAX_ADAPTERS]
        return AdapterListResultV1(
            schema_version="adapter_list_result_v1",
            adapters=adapters,
            adapter_count=len(adapters),
            status="succeeded",
            collected_at=finished_at,
        )
    except OSError:
        return AdapterListResultV1(
            schema_version="adapter_list_result_v1",
            adapter_count=0,
            status="failed",
            error_code="adapter_enumeration_failed",
            collected_at=finished_at,
        )


def _linux_service_status(unit: str) -> str:
    completed = subprocess.run(
        ("/usr/bin/systemctl", "show", unit, "--property=ActiveState,LoadState", "--no-page"),
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
    )
    values = dict(
        line.split("=", 1)
        for line in completed.stdout.splitlines()
        if "=" in line
    )
    if values.get("LoadState") == "not-found":
        return "missing"
    return {
        "active": "active",
        "inactive": "inactive",
        "failed": "failed",
    }.get(values.get("ActiveState"), "unknown")


def _windows_service_status(service_name: str) -> str:
    try:
        import win32serviceutil  # type: ignore[import-not-found]
    except ImportError as error:
        raise OSError("Windows service query is unavailable") from error
    status = win32serviceutil.QueryServiceStatus(service_name)[1]
    return {4: "active", 1: "inactive", 7: "inactive"}.get(status, "unknown")


def _alt_package_version() -> str | None:
    try:
        completed = subprocess.run(
            (_ALT_RPM, "-q", "--qf", "%{VERSION}", "endpoint-agent"),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _windows_package_version() -> str | None:
    try:
        import winreg
    except ImportError:
        return None
    uninstall_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uninstall_key) as root:
            index = 0
            while True:
                try:
                    child_name = winreg.EnumKey(root, index)
                except OSError:
                    return None
                index += 1
                with winreg.OpenKey(root, child_name) as item:
                    try:
                        display_name, _ = winreg.QueryValueEx(item, "DisplayName")
                        display_version, _ = winreg.QueryValueEx(item, "DisplayVersion")
                        windows_installer, _ = winreg.QueryValueEx(item, "WindowsInstaller")
                    except OSError:
                        continue
                    if (
                        display_name == "Endpoint Agent"
                        and windows_installer == 1
                        and isinstance(display_version, str)
                    ):
                        return display_version.strip()
    except OSError:
        return None


def _bounded_package_version(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return SystemServiceStatusResultV1.model_validate(
            {
                "schema_version": "system_service_status_result_v1",
                "service_key": "endpoint_agent",
                "platform": "linux_amd64",
                "state": "unknown",
                "package_kind": "alt_rpm",
                "package_version": value,
                "status": "succeeded",
                "collected_at": datetime.now(UTC),
            }
        ).package_version
    except ValidationError:
        return None


def system_service_status(
    parameters: SystemServiceStatusParametersV1,
    *,
    platform_name: str | None = None,
    linux_service_status: Callable[[str], str] = _linux_service_status,
    windows_service_status: Callable[[str], str] = _windows_service_status,
    alt_package_version: Callable[[], str | None] = _alt_package_version,
    windows_package_version: Callable[[], str | None] = _windows_package_version,
    collected_at: datetime | None = None,
) -> SystemServiceStatusResultV1:
    """Read only a fixed Endpoint service and its fixed package projection."""
    finished_at = _completed_at(collected_at)
    platform = platform_name or ("windows" if os.name == "nt" else "linux")
    try:
        if platform == "linux":
            state = linux_service_status(_LINUX_UNITS[parameters.service_key])
            package_version = _bounded_package_version(alt_package_version())
            return SystemServiceStatusResultV1(
                schema_version="system_service_status_result_v1",
                service_key=parameters.service_key,
                platform="linux_amd64",
                state=state,
                package_kind="alt_rpm",
                package_version=package_version,
                status="succeeded",
                collected_at=finished_at,
            )
        if platform == "windows":
            state = windows_service_status(_WINDOWS_SERVICES[parameters.service_key])
            package_version = _bounded_package_version(windows_package_version())
            return SystemServiceStatusResultV1(
                schema_version="system_service_status_result_v1",
                service_key=parameters.service_key,
                platform="windows_amd64",
                state=state,
                package_kind="windows_msi",
                package_version=package_version,
                status="succeeded",
                collected_at=finished_at,
            )
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    return SystemServiceStatusResultV1(
        schema_version="system_service_status_result_v1",
        service_key=parameters.service_key,
        platform="windows_amd64" if platform == "windows" else "linux_amd64",
        state="unknown",
        package_kind="windows_msi" if platform == "windows" else "alt_rpm",
        status="failed",
        error_code="service_query_failed",
        collected_at=finished_at,
    )


__all__ = ["adapter_list", "route_get", "system_service_status"]
