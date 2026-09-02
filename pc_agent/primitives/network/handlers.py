"""Fixed DNS and TCP probe adapters that never expose local diagnostic text."""

from __future__ import annotations

import math
import os
import re
import socket
import subprocess
import time
import ctypes
from collections.abc import Callable, Iterator
from datetime import UTC, datetime

from endpoint_contracts.network_primitives import (
    DnsResolveParametersV1,
    DnsResolveResultV1,
    NetworkAddressV1,
    NetworkPingParametersV1,
    NetworkPingResultV1,
    TcpConnectParametersV1,
    TcpConnectResultV1,
)


def _completed_at(value: datetime | None) -> datetime:
    return value or datetime.now(UTC)


def _family(value: str) -> socket.AddressFamily:
    return {
        "any": socket.AF_UNSPEC,
        "ipv4": socket.AF_INET,
        "ipv6": socket.AF_INET6,
    }[value]


def resolve_dns(
    parameters: DnsResolveParametersV1,
    *,
    getaddrinfo: Callable[..., list[tuple[object, ...]]] = socket.getaddrinfo,
    getfqdn: Callable[[str], str] = socket.getfqdn,
    collected_at: datetime | None = None,
) -> DnsResolveResultV1:
    """Resolve one validated target into at most sixteen IP addresses."""
    finished_at = _completed_at(collected_at)
    try:
        records = getaddrinfo(
            parameters.target, 0, _family(parameters.family), socket.SOCK_STREAM
        )
    except (socket.gaierror, UnicodeError):
        return DnsResolveResultV1(
            schema_version="dns_resolve_result_v1",
            target=parameters.target,
            address_count=0,
            status="failed",
            error_code="dns_not_found",
            collected_at=finished_at,
        )
    except OSError:
        return DnsResolveResultV1(
            schema_version="dns_resolve_result_v1",
            target=parameters.target,
            address_count=0,
            status="failed",
            error_code="dns_failed",
            collected_at=finished_at,
        )

    addresses: list[NetworkAddressV1] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        family = record[0]
        sockaddr = record[4]
        if family not in {socket.AF_INET, socket.AF_INET6} or not sockaddr:
            continue
        address = str(sockaddr[0])
        normalized_family = "ipv4" if family == socket.AF_INET else "ipv6"
        key = (normalized_family, address)
        if key in seen:
            continue
        seen.add(key)
        addresses.append(NetworkAddressV1(family=normalized_family, address=address))
        if len(addresses) == 16:
            break
    if not addresses:
        return DnsResolveResultV1(
            schema_version="dns_resolve_result_v1",
            target=parameters.target,
            address_count=0,
            status="failed",
            error_code="dns_not_found",
            collected_at=finished_at,
        )
    try:
        canonical_name = getfqdn(parameters.target)
    except OSError:
        canonical_name = ""
    return DnsResolveResultV1(
        schema_version="dns_resolve_result_v1",
        target=parameters.target,
        canonical_name=canonical_name or None,
        addresses=addresses,
        address_count=len(addresses),
        status="succeeded",
        collected_at=finished_at,
    )


def tcp_connect(
    parameters: TcpConnectParametersV1,
    *,
    resolve: Callable[..., list[tuple[object, ...]]] = socket.getaddrinfo,
    connect: Callable[..., socket.socket] = socket.create_connection,
    monotonic_values: Iterator[float] | None = None,
    collected_at: datetime | None = None,
) -> TcpConnectResultV1:
    """Attempt a bounded connection using only socket APIs and safe result codes."""
    finished_at = _completed_at(collected_at)
    try:
        records = resolve(
            parameters.target, parameters.port, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except (socket.gaierror, UnicodeError):
        return _tcp_failure(parameters, "dns_not_found", finished_at)
    except OSError:
        return _tcp_failure(parameters, "dns_failed", finished_at)
    timeout_seconds = parameters.timeout_ms / 1000
    for record in records[:16]:
        family = record[0]
        sockaddr = record[4]
        if family not in {socket.AF_INET, socket.AF_INET6} or not sockaddr:
            continue
        resolved_ip = str(sockaddr[0])
        started_at = next(monotonic_values) if monotonic_values is not None else time.monotonic()
        connection: socket.socket | None = None
        try:
            connection = connect(sockaddr, timeout=timeout_seconds)
            ended_at = next(monotonic_values) if monotonic_values is not None else time.monotonic()
            return TcpConnectResultV1(
                schema_version="tcp_connect_result_v1",
                target=parameters.target,
                resolved_ip=resolved_ip,
                port=parameters.port,
                reachable=True,
                latency_ms=round(max(0.0, (ended_at - started_at) * 1000), 3),
                status="succeeded",
                collected_at=finished_at,
            )
        except TimeoutError:
            return _tcp_failure(parameters, "tcp_timed_out", finished_at, resolved_ip)
        except OSError:
            continue
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
    return _tcp_failure(parameters, "tcp_unreachable", finished_at)


def _tcp_failure(
    parameters: TcpConnectParametersV1,
    error_code: str,
    collected_at: datetime,
    resolved_ip: str | None = None,
) -> TcpConnectResultV1:
    return TcpConnectResultV1(
        schema_version="tcp_connect_result_v1",
        target=parameters.target,
        resolved_ip=resolved_ip,
        port=parameters.port,
        reachable=False,
        status="failed",
        error_code=error_code,
        collected_at=collected_at,
    )


def ping_host(
    parameters: NetworkPingParametersV1,
    *,
    platform_name: str | None = None,
    runner: Callable[[tuple[str, ...], float], tuple[int, str]] | None = None,
    resolve: Callable[..., list[tuple[object, ...]]] = socket.getaddrinfo,
    collected_at: datetime | None = None,
) -> NetworkPingResultV1:
    """Run a fixed OS ping adapter and map only bounded measurements."""
    finished_at = _completed_at(collected_at)
    resolved_ip = _resolve_first_ip(parameters.target, resolve)
    platform = platform_name or ("windows" if os.name == "nt" else "linux")
    if platform == "windows":
        argv = ("ping", "-n", str(parameters.count), "-w", str(parameters.timeout_ms), parameters.target)
    elif platform == "linux":
        argv = ("ping", "-c", str(parameters.count), "-W", str(max(1, math.ceil(parameters.timeout_ms / 1000))), parameters.target)
    else:
        return _ping_failure(parameters, "ping_platform_unsupported", finished_at, resolved_ip)
    execute = runner or _run_fixed_ping
    try:
        _return_code, output = execute(
            argv, min(30.0, parameters.count * (parameters.timeout_ms / 1000) + 2.0)
        )
    except FileNotFoundError:
        return _ping_failure(parameters, "ping_unavailable", finished_at, resolved_ip)
    except TimeoutError:
        return _ping_failure(parameters, "ping_timed_out", finished_at, resolved_ip)
    except OSError:
        return _ping_failure(parameters, "ping_failed", finished_at, resolved_ip)
    parsed = _parse_ping_output(output, platform)
    if parsed is None:
        return _ping_failure(parameters, "ping_parse_failed", finished_at, resolved_ip)
    transmitted, received, min_ms, avg_ms, max_ms = parsed
    if transmitted < 0 or received < 0 or received > transmitted:
        return _ping_failure(parameters, "ping_parse_failed", finished_at, resolved_ip)
    packet_loss = round((transmitted - received) * 100 / transmitted, 3) if transmitted else 100.0
    if received == 0:
        min_ms = avg_ms = max_ms = None
    elif any(value is None for value in (min_ms, avg_ms, max_ms)):
        return _ping_failure(parameters, "ping_parse_failed", finished_at, resolved_ip)
    return NetworkPingResultV1(
        schema_version="network_ping_result_v1",
        target=parameters.target,
        resolved_ip=resolved_ip,
        transmitted=transmitted,
        received=received,
        packet_loss_percent=packet_loss,
        min_ms=min_ms,
        avg_ms=avg_ms,
        max_ms=max_ms,
        reachable=received > 0,
        status="succeeded",
        collected_at=finished_at,
    )


def _run_fixed_ping(argv: tuple[str, ...], timeout_seconds: float) -> tuple[int, str]:
    options: dict[str, object] = {
        "check": False,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "text": True,
        "timeout": timeout_seconds,
    }
    if os.name == "nt":
        options["encoding"] = _windows_ping_output_encoding()
    try:
        completed = subprocess.run(
            argv,
            **options,
        )
    except subprocess.TimeoutExpired as error:
        raise TimeoutError("fixed ping adapter timed out") from error
    return completed.returncode, completed.stdout


def _windows_ping_output_encoding(
    *, get_oemcp: Callable[[], int] | None = None
) -> str:
    """Return the Windows OEM code page used by ping.exe summaries."""
    code_page = (get_oemcp or ctypes.windll.kernel32.GetOEMCP)()
    return f"cp{code_page}" if code_page > 0 else "utf-8"


def _parse_ping_output(
    output: str, platform: str
) -> tuple[int, int, float | None, float | None, float | None] | None:
    if not isinstance(output, str) or len(output) > 65_536:
        return None
    if platform == "linux":
        counts = re.search(r"(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets )?received", output)
        timings = re.search(r"=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/", output)
    else:
        counts = re.search(r"=\s*(\d+)\s*,\s*[^=\r\n]+=\s*(\d+)", output)
        timings = re.search(
            r"=\s*([0-9.]+)\s*(?:ms|мс(?:ек)?)\s*,\s*"
            r"[^=\r\n]+=\s*([0-9.]+)\s*(?:ms|мс(?:ек)?)\s*,\s*"
            r"[^=\r\n]+=\s*([0-9.]+)\s*(?:ms|мс(?:ек)?)",
            output,
            re.IGNORECASE,
        )
    if counts is None:
        return None
    transmitted, received = int(counts.group(1)), int(counts.group(2))
    if received == 0:
        return transmitted, received, None, None, None
    if timings is None:
        return None
    if platform == "linux":
        minimum, average, maximum = (float(timings.group(index)) for index in (1, 2, 3))
    else:
        minimum, maximum, average = (float(timings.group(index)) for index in (1, 2, 3))
    return transmitted, received, minimum, average, maximum


def _resolve_first_ip(target: str, resolve: Callable[..., list[tuple[object, ...]]]) -> str | None:
    try:
        records = resolve(target, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return None
    for record in records:
        if record[0] in {socket.AF_INET, socket.AF_INET6} and record[4]:
            return str(record[4][0])
    return None


def _ping_failure(
    parameters: NetworkPingParametersV1,
    error_code: str,
    collected_at: datetime,
    resolved_ip: str | None,
) -> NetworkPingResultV1:
    return NetworkPingResultV1(
        schema_version="network_ping_result_v1",
        target=parameters.target,
        resolved_ip=resolved_ip,
        transmitted=0,
        received=0,
        packet_loss_percent=100.0,
        reachable=False,
        status="failed",
        error_code=error_code,
        collected_at=collected_at,
    )
