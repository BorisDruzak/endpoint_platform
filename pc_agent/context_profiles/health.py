"""Volatile health facts from bounded local files and fixed service checks."""

from __future__ import annotations

from datetime import datetime, timezone

from endpoint_contracts.context import DeviceContextHealthV1

from .probe import NETWORK_MANAGER_STATUS_COMMAND, SSHD_STATUS_COMMAND


def collect_health(probe: object, *, collected_at: datetime | None = None) -> DeviceContextHealthV1:
    warnings: list[str] = []
    uptime = _first_number(_read(probe, "/proc/uptime", warnings), default=0)
    load = _first_number(_read(probe, "/proc/loadavg", warnings), default=0.0)
    free_bytes = _available_bytes(_read(probe, "/proc/meminfo", warnings), warnings)
    services = [
        {"name": "sshd", "status": _service_status(probe, SSHD_STATUS_COMMAND, warnings)},
        {
            "name": "NetworkManager",
            "status": _service_status(probe, NETWORK_MANAGER_STATUS_COMMAND, warnings),
        },
    ]
    return DeviceContextHealthV1(
        schema_version="device_context_v1",
        profile="health_v1",
        collected_at=collected_at or datetime.now(timezone.utc),
        sections={
            "resources": {
                "uptime_seconds": int(max(0, uptime)),
                "load_1m": max(0.0, load),
                "free_bytes": free_bytes,
            },
            "services": services,
        },
        warnings=list(dict.fromkeys(warnings))[:16],
    )


def _read(probe: object, path: str, warnings: list[str]) -> str:
    try:
        return str(probe.read_text(path, 16_384))
    except (OSError, ValueError, TimeoutError):
        warnings.append("source_unavailable")
        return ""


def _first_number(value: str, *, default: float) -> float:
    try:
        return float(value.split()[0])
    except (IndexError, ValueError):
        return default


def _available_bytes(value: str, warnings: list[str]) -> int:
    for line in value.splitlines():
        if line.startswith("MemAvailable:"):
            try:
                return max(0, int(line.split()[1]) * 1024)
            except (IndexError, ValueError):
                break
    warnings.append("source_unavailable")
    return 0


def _service_status(probe: object, command: tuple[str, ...], warnings: list[str]) -> str:
    try:
        status = str(probe.run(command, 2.0, 256)).strip().lower()
    except TimeoutError:
        warnings.append("command_timed_out")
        return "unknown"
    except (OSError, ValueError):
        warnings.append("command_failed")
        return "unknown"
    return status if status in {"active", "inactive", "failed"} else "unknown"
