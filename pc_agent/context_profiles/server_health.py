"""Evaluate the checks enabled by the administrator's local server role."""

from dataclasses import dataclass
import os
import re

import psutil

from endpoint_contracts.context import (
    ServerHealthApplicationV1,
    ServerHealthServiceV1,
    ServerHealthV1,
    ServerHealthVolumeV1,
    ServerRoleV1,
)


@dataclass(frozen=True)
class Volume:
    mount: str
    minimum_free_gib: int = 1


@dataclass(frozen=True)
class Role:
    platform: str
    services: tuple[str, ...]
    volumes: tuple[Volume, ...]


_AD_SERVICES = ("NTDS", "DNS", "Kdc", "Netlogon", "ADWS")
_DIRECTUM_SERVICES = ("DirectumRXServiceRunner", "W3SVC", "RabbitMQ")
_WINDOWS_VOLUMES = (Volume("C:\\", 10), Volume("S:\\", 10))

ROLES: dict[ServerRoleV1, Role] = {
    "endpoint_platform": Role(
        "linux",
        ("endpoint-platform.service", "endpoint-platform-worker.service", "nginx.service",
         "postgresql@16-main.service"),
        (Volume("/", 5), Volume("/boot")),
    ),
    "openvpn": Role(
        "linux", ("openvpn-server@server.service", "openvpn-web.service"),
        (Volume("/", 5), Volume("/boot"), Volume("/var/lib/netctl", 10)),
    ),
    "directum": Role("windows", _DIRECTUM_SERVICES, _WINDOWS_VOLUMES),
    "ad_directum": Role("windows", _AD_SERVICES + _DIRECTUM_SERVICES, _WINDOWS_VOLUMES),
    "ad_consultant": Role(
        "windows", _AD_SERVICES + ("W3SVC", "ConsServiceS400.2.24"), _WINDOWS_VOLUMES,
    ),
    "proxmox": Role(
        "linux",
        ("pve-cluster.service", "corosync.service", "pvedaemon.service", "pveproxy.service",
         "pvestatd.service", "pvescheduler.service"),
        (Volume("/", 5),),
    ),
}

PROBE_ERRORS = (OSError, TimeoutError, ValueError, psutil.Error)
_GIB = 1024**3


def collect_server_health(probe: object, *, warnings: list | None = None) -> ServerHealthV1 | None:
    requested = os.environ.get("ENDPOINT_AGENT_SERVER_ROLE", "").strip()
    if not requested:
        return None
    role_id = next((role_id for role_id in ROLES if role_id == requested), None)
    if role_id is None:
        if warnings is not None:
            warnings.append("source_unavailable")
        return None
    role = ROLES[role_id]
    if role.platform != getattr(probe, "platform_name", None):
        if warnings is not None:
            warnings.append("unsupported_platform")
        return None

    volumes = _volumes(probe, role.volumes)
    if role_id == "proxmox":
        storage, applications = _proxmox_checks(probe)
        volumes.extend(storage)
    else:
        applications = _applications(probe, role_id)
    return ServerHealthV1(
        role=role_id,
        services=[_service(probe, name, role.platform) for name in role.services],
        volumes=volumes,
        applications=applications,
    )


def _service(probe: object, name: str, platform: str) -> ServerHealthServiceV1:
    try:
        state = probe.server_service_state(name)
    except PROBE_ERRORS:
        state = "unknown"
    expected = "running" if platform == "windows" else "active/running"
    if state == expected:
        status = "ok"
    elif state in {"missing", "unknown"}:
        status = state
    else:
        status = "failed"
    return ServerHealthServiceV1(name=name, status=status, observed_state=state)


def _volumes(probe: object, volumes: tuple[Volume, ...]) -> list[ServerHealthVolumeV1]:
    try:
        local_mounts = probe.server_local_mounts()
    except PROBE_ERRORS:
        return [ServerHealthVolumeV1(mount=volume.mount, status="unknown") for volume in volumes]
    return [_volume(probe, volume, local_mounts) for volume in volumes]


def _volume(probe: object, volume: Volume, local_mounts: set[str]) -> ServerHealthVolumeV1:
    if volume.mount not in local_mounts:
        return ServerHealthVolumeV1(mount=volume.mount, status="missing")
    try:
        usage = probe.server_disk_usage(volume.mount)
    except PROBE_ERRORS:
        return ServerHealthVolumeV1(mount=volume.mount, status="unknown")
    if usage.total <= 0 or not 0 <= usage.free <= usage.total or not 0 <= usage.percent <= 100:
        return ServerHealthVolumeV1(mount=volume.mount, status="unknown")
    return _usage(volume.mount, usage.total, usage.free, usage.percent, volume.minimum_free_gib)


def _usage(mount: str, total: int, free: int, percent: float, minimum_gib: int) -> ServerHealthVolumeV1:
    if percent >= 90 or free < minimum_gib * _GIB:
        status = "critical"
    elif percent >= 80:
        status = "warning"
    else:
        status = "ok"
    return ServerHealthVolumeV1(
        mount=mount, status=status, used_percent=percent, total_bytes=total, free_bytes=free,
    )


_PROXMOX_CHECKS = ("proxmox_api", "proxmox_quorum", "proxmox_members", "proxmox_storage")


def _proxmox_checks(probe: object) -> tuple[list[ServerHealthVolumeV1], list[ServerHealthApplicationV1]]:
    try:
        snapshot = probe.proxmox_health_snapshot()
    except PROBE_ERRORS:
        snapshot = {}
    checks = snapshot.get("checks")
    checks = checks if isinstance(checks, dict) else {}
    http = snapshot.get("http_status")
    applications = [
        ServerHealthApplicationV1(
            name=name,
            status=checks[name] if checks.get(name) in ("ok", "failed", "unknown") else "unknown",
            http_status=http if name == "proxmox_api" and type(http) is int and 100 <= http <= 599 else None,
        )
        for name in _PROXMOX_CHECKS
    ]
    rows = snapshot.get("storage")
    volumes = []
    for row in rows[:15] if isinstance(rows, list) else []:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not re.fullmatch(r"[a-zA-Z0-9._-]{1,64}", row["id"]):
            continue
        label = f"PVE / {row['id']}"
        total, used = row.get("total"), row.get("used")
        if row.get("available") is False:
            volumes.append(ServerHealthVolumeV1(mount=label, status="critical"))
        elif type(total) is int and type(used) is int and total > 0 and 0 <= used <= total:
            volumes.append(_usage(label, total, total - used, round(100 * used / total, 1), 5))
        else:
            volumes.append(ServerHealthVolumeV1(mount=label, status="unknown"))
    return volumes, applications


def _applications(probe: object, role: ServerRoleV1) -> list[ServerHealthApplicationV1]:
    if role == "endpoint_platform":
        return [_http(probe, "endpoint_api_health", 8000, "/healthz", {200})]
    if role == "openvpn":
        return [
            _http(probe, "openvpn_web_http", 8088, "/", {200, 303}),
            _listener("openvpn_udp_listener", probe.server_udp_listener, 1194),
        ]
    checks = []
    if role in {"ad_directum", "ad_consultant"}:
        checks.extend([
            _listener("ad_dns_tcp", probe.server_tcp_listener, 53),
            _listener("ad_kerberos_tcp", probe.server_tcp_listener, 88),
            _listener("ad_ldap_tcp", probe.server_tcp_listener, 389),
        ])
    if role in {"directum", "ad_directum"}:
        checks.extend([
            _http(probe, "directum_http", 80, "/", {200, 302}),
            _listener("directum_rabbitmq_tcp", probe.server_tcp_listener, 5672),
        ])
    if role == "ad_consultant":
        checks.extend([
            _http(probe, "consultant_http", 80, "/cons/", {200}),
            _listener("consultant_tcp", probe.server_tcp_listener, 20024),
        ])
    return checks


def _http(probe: object, name: str, port: int, path: str, expected: set[int]) -> ServerHealthApplicationV1:
    try:
        code = probe.server_http_status(port, path)
    except (ConnectionRefusedError, ConnectionResetError):
        return ServerHealthApplicationV1(name=name, status="failed")
    except PROBE_ERRORS:
        return ServerHealthApplicationV1(name=name, status="unknown")
    if not 100 <= code <= 599:
        return ServerHealthApplicationV1(name=name, status="unknown")
    return ServerHealthApplicationV1(
        name=name, status="ok" if code in expected else "failed", http_status=code,
    )


def _listener(name: str, probe, port: int) -> ServerHealthApplicationV1:
    try:
        listening = probe(port)
    except PROBE_ERRORS:
        return ServerHealthApplicationV1(name=name, status="unknown")
    return ServerHealthApplicationV1(name=name, status="ok" if listening else "failed")
