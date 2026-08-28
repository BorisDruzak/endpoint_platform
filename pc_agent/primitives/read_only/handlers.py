"""Fixed native collectors for bounded, non-mutating Endpoint diagnostics."""

from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import ValidationError

from endpoint_contracts.read_only_primitives import (
    AdapterListParametersV1,
    AdapterListResultV1,
    AdapterSummaryItemV1,
    RouteGetParametersV1,
    RouteGetResultV1,
    ServiceStatusParametersV1,
    ServiceStatusResultV1,
)
from pc_agent.primitives.network.policy import AgentNetworkProbePolicy, NetworkProbeDenied


_MAX_ADAPTERS = 32
_LINUX_UNITS = {"endpoint_agent": "endpoint-agent.service"}
_WINDOWS_SERVICES = {
    "endpoint_agent": "EndpointAgent",
    "endpoint_agent_updater": "EndpointAgentUpdater",
}


def _completed_at(value: datetime | None) -> datetime:
    return value or datetime.now(UTC)


def _socket_family(family: Literal["any", "ipv4", "ipv6"]) -> int:
    return {"any": socket.AF_UNSPEC, "ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}[family]


def _resolve_candidates(
    target: str, port: int, family: Literal["any", "ipv4", "ipv6"]
) -> tuple[tuple[Literal["ipv4", "ipv6"], str], ...]:
    records = socket.getaddrinfo(target, port, _socket_family(family), socket.SOCK_DGRAM)
    candidates: list[tuple[Literal["ipv4", "ipv6"], str]] = []
    for address_family, _type, _protocol, _canonical, address in records:
        if address_family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        candidate_family: Literal["ipv4", "ipv6"] = (
            "ipv4" if address_family == socket.AF_INET else "ipv6"
        )
        candidate_ip = str(address[0])
        item = (candidate_family, candidate_ip)
        if item not in candidates:
            candidates.append(item)
    if not candidates:
        raise OSError("no supported DNS candidates")
    return tuple(candidates)


def _infer_source(
    resolved_ip: str,
    port: int,
    family: Literal["ipv4", "ipv6"],
    timeout_ms: int,
) -> str:
    address_family = socket.AF_INET if family == "ipv4" else socket.AF_INET6
    connection = socket.socket(address_family, socket.SOCK_DGRAM)
    try:
        connection.settimeout(timeout_ms / 1000)
        connection.connect((resolved_ip, port))
        return str(connection.getsockname()[0])
    finally:
        connection.close()


def _interface_for_source(source_ip: str) -> str | None:
    try:
        import psutil
    except ImportError:
        return None
    for name, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            candidate = getattr(address, "address", "").split("%", 1)[0]
            if candidate == source_ip:
                return name
    return None


def route_get(
    parameters: RouteGetParametersV1,
    *,
    policy: AgentNetworkProbePolicy,
    resolve_candidates: Callable[
        [str, int, Literal["any", "ipv4", "ipv6"]],
        tuple[tuple[Literal["ipv4", "ipv6"], str], ...],
    ] = _resolve_candidates,
    infer_source: Callable[[str, int, Literal["ipv4", "ipv6"], int], str] = _infer_source,
    interface_for_source: Callable[[str], str | None] = _interface_for_source,
    collected_at: datetime | None = None,
) -> RouteGetResultV1:
    """Infer a selected source address only after DNS candidates are allowed."""
    finished_at = _completed_at(collected_at)
    try:
        candidates = resolve_candidates(parameters.target, parameters.port, parameters.family)
    except (OSError, UnicodeError, ValueError):
        return _failed_route(parameters, "route_unavailable", finished_at)

    allowed_candidates: list[tuple[Literal["ipv4", "ipv6"], str]] = []
    for family, resolved_ip in candidates:
        try:
            policy.require_allowed(resolved_ip)
        except NetworkProbeDenied:
            continue
        allowed_candidates.append((family, resolved_ip))
    if not allowed_candidates:
        return _failed_route(parameters, "network_target_denied", finished_at)

    for family, resolved_ip in allowed_candidates:
        try:
            source_ip = infer_source(resolved_ip, parameters.port, family, parameters.timeout_ms)
            interface_name = interface_for_source(source_ip)
            return RouteGetResultV1(
                schema_version="route_get_result_v1",
                target=parameters.target,
                resolved_ip=resolved_ip,
                family=family,
                port=parameters.port,
                source_ip=source_ip,
                interface_name=interface_name,
                status="succeeded",
                collected_at=finished_at,
            )
        except (OSError, UnicodeError, ValueError, ValidationError):
            continue
    return _failed_route(parameters, "route_unavailable", finished_at)


def _failed_route(
    parameters: RouteGetParametersV1, error_code: str, collected_at: datetime
) -> RouteGetResultV1:
    return RouteGetResultV1(
        schema_version="route_get_result_v1",
        target=parameters.target,
        port=parameters.port,
        status="failed",
        error_code=error_code,
        collected_at=collected_at,
    )


def _psutil_interface_addresses() -> Mapping[str, list[Any]]:
    import psutil

    return psutil.net_if_addrs()


def _psutil_interface_stats() -> Mapping[str, Any]:
    import psutil

    return psutil.net_if_stats()


def _adapter_kind(name: str) -> Literal[
    "ethernet", "wifi", "loopback", "tunnel", "virtual", "unknown"
]:
    normalized = name.lower()
    if normalized in {"lo", "loopback"} or "loopback" in normalized:
        return "loopback"
    if any(value in normalized for value in ("wifi", "wi-fi", "wlan", "wireless")):
        return "wifi"
    if any(value in normalized for value in ("tun", "tap", "vpn", "ppp")):
        return "tunnel"
    if any(value in normalized for value in ("virtual", "veth", "docker", "vmnet")):
        return "virtual"
    return "ethernet" if normalized else "unknown"


def _addresses_for_adapter(addresses: list[Any]) -> tuple[list[str], list[str]]:
    ipv4: list[str] = []
    ipv6: list[str] = []
    for address in addresses:
        value = getattr(address, "address", "")
        if not isinstance(value, str):
            continue
        value = value.split("%", 1)[0]
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            continue
        destination = ipv4 if parsed.version == 4 else ipv6
        normalized = str(parsed)
        if normalized not in destination and len(destination) < 4:
            destination.append(normalized)
    return ipv4, ipv6


def _bounded_stat(value: object, maximum: int) -> int:
    if type(value) is not int:
        return 0
    return min(max(value, 0), maximum)


def adapter_list(
    _parameters: AdapterListParametersV1,
    *,
    interface_addresses: Callable[[], Mapping[str, list[Any]]] = _psutil_interface_addresses,
    interface_stats: Callable[[], Mapping[str, Any]] = _psutil_interface_stats,
    primary_interface_name: str | None = None,
    collected_at: datetime | None = None,
) -> AdapterListResultV1:
    """Project a capped psutil interface view with no MAC or profile data."""
    finished_at = _completed_at(collected_at)
    try:
        addresses = interface_addresses()
        stats = interface_stats()
        adapters: list[AdapterSummaryItemV1] = []
        for name in sorted(addresses):
            stat = stats.get(name)
            state = "unknown" if stat is None else ("up" if stat.isup else "down")
            ipv4, ipv6 = _addresses_for_adapter(addresses[name])
            try:
                adapters.append(
                    AdapterSummaryItemV1(
                        name=name,
                        state=state,
                        kind=_adapter_kind(name),
                        primary=name == primary_interface_name,
                        ipv4_addresses=ipv4,
                        ipv6_addresses=ipv6,
                        mtu=_bounded_stat(getattr(stat, "mtu", 0), 65535),
                        speed_mbps=_bounded_stat(getattr(stat, "speed", 0), 1_000_000),
                    )
                )
            except ValidationError:
                continue
            if len(adapters) == _MAX_ADAPTERS:
                break
        return AdapterListResultV1(
            schema_version="adapter_list_result_v1",
            adapters=adapters,
            adapter_count=len(adapters),
            up_count=sum(item.state == "up" for item in adapters),
            status="succeeded",
            collected_at=finished_at,
        )
    except (ImportError, OSError):
        return AdapterListResultV1(
            schema_version="adapter_list_result_v1",
            adapter_count=0,
            up_count=0,
            status="failed",
            error_code="adapter_enumeration_failed",
            collected_at=finished_at,
        )


def _linux_service_details(unit: str) -> tuple[bool, str, str]:
    completed = subprocess.run(
        ("/usr/bin/systemctl", "show", unit, "--property=ActiveState,LoadState,UnitFileState", "--no-page"),
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
    )
    values = dict(line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line)
    installed = values.get("LoadState") != "not-found"
    state = {"active": "running", "inactive": "stopped", "failed": "failed"}.get(
        values.get("ActiveState"), "not_found" if not installed else "unknown"
    )
    start_mode = {"enabled": "automatic", "disabled": "disabled"}.get(
        values.get("UnitFileState"), "manual" if installed else "unknown"
    )
    return installed, state, start_mode


def _windows_service_details(service_name: str) -> tuple[bool, str, str]:
    try:
        import win32serviceutil  # type: ignore[import-not-found]
    except ImportError as error:
        raise OSError("Windows SCM query is unavailable") from error
    state_code = win32serviceutil.QueryServiceStatus(service_name)[1]
    start_type = win32serviceutil.QueryServiceConfig(service_name)[1]
    state = {1: "stopped", 4: "running", 7: "paused"}.get(state_code, "unknown")
    start_mode = {2: "automatic", 3: "manual", 4: "disabled"}.get(start_type, "unknown")
    return True, state, start_mode


def service_status(
    parameters: ServiceStatusParametersV1,
    *,
    platform_name: str | None = None,
    linux_service_details: Callable[[str], tuple[bool, str, str]] = _linux_service_details,
    windows_service_details: Callable[[str], tuple[bool, str, str]] = _windows_service_details,
    collected_at: datetime | None = None,
) -> ServiceStatusResultV1:
    """Read a fixed logical Endpoint service without exposing OS identifiers."""
    finished_at = _completed_at(collected_at)
    platform = platform_name or ("windows" if os.name == "nt" else "linux")
    if platform == "linux" and parameters.service_key == "endpoint_agent_updater":
        return ServiceStatusResultV1(
            schema_version="service_status_result_v1",
            service_key=parameters.service_key,
            installed=False,
            state="not_found",
            start_mode="unknown",
            status="failed",
            error_code="service_unsupported",
            collected_at=finished_at,
        )
    try:
        if platform == "linux":
            details = linux_service_details(_LINUX_UNITS[parameters.service_key])
        elif platform == "windows":
            details = windows_service_details(_WINDOWS_SERVICES[parameters.service_key])
        else:
            raise OSError("unsupported platform")
        installed, state, start_mode = details
        return ServiceStatusResultV1(
            schema_version="service_status_result_v1",
            service_key=parameters.service_key,
            installed=installed,
            state=state,
            start_mode=start_mode,
            status="succeeded",
            collected_at=finished_at,
        )
    except (KeyError, OSError, subprocess.TimeoutExpired, ValueError):
        return ServiceStatusResultV1(
            schema_version="service_status_result_v1",
            service_key=parameters.service_key,
            installed=False,
            state="unknown",
            start_mode="unknown",
            status="failed",
            error_code="service_query_failed",
            collected_at=finished_at,
        )


__all__ = ["adapter_list", "route_get", "service_status"]
