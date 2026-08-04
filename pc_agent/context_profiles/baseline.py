"""Stable baseline facts collected from local ALT/Windows OS state only."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import json
import platform

from endpoint_contracts.context import DeviceContextBaselineV1
from pc_agent.version import AGENT_VERSION

from .probe import IP_LINK_COMMAND, LSBLK_COMMAND
from .stable_keys import bounded_text, disk_stable_key, interface_stable_key


def collect_baseline(probe: object, *, collected_at: datetime | None = None) -> DeviceContextBaselineV1:
    if str(getattr(probe, "platform_name", "")).lower() == "windows":
        return _collect_windows_baseline(probe, collected_at=collected_at)
    warnings: list[str] = []
    os_release = _read(probe, "/etc/os-release", warnings)
    system_platform = _platform_for(os_release, probe)
    storage = _storage(probe, warnings)
    interfaces = _interfaces(probe, warnings)
    memory_bytes = _memory_bytes(_read(probe, "/proc/meminfo", warnings), warnings)
    sections = {
        "system": {
            "platform": system_platform,
            "distribution": _distribution(os_release, system_platform),
            "architecture": _architecture(),
        },
        "hardware": {
            "manufacturer": bounded_text(_read(probe, "/sys/class/dmi/id/sys_vendor", warnings), fallback="Unknown"),
            "model": bounded_text(_read(probe, "/sys/class/dmi/id/product_name", warnings), fallback="Unknown"),
            "cpu_model": _cpu_model(_read(probe, "/proc/cpuinfo", warnings)),
            "memory_bytes": memory_bytes,
        },
        "storage": storage,
        "interfaces": interfaces,
        "software": [
            {
                "name": "endpoint-agent",
                "version": bounded_text(AGENT_VERSION, fallback="unknown", limit=128),
                "source": "system",
            }
        ],
    }
    return DeviceContextBaselineV1(
        schema_version="device_context_v1",
        profile="baseline_v1",
        collected_at=collected_at or datetime.now(timezone.utc),
        sections=sections,
        warnings=_unique_warnings(warnings),
    )


def _collect_windows_baseline(probe: object, *, collected_at: datetime | None) -> DeviceContextBaselineV1:
    from pc_agent.platform.windows.identity import collect_hardware, collect_system
    from pc_agent.platform.windows.network import collect_baseline_interfaces
    from pc_agent.platform.windows.software import collect_software
    from pc_agent.platform.windows.storage import collect_storage

    system = collect_system(probe)
    return DeviceContextBaselineV1(
        schema_version="device_context_v1",
        profile="baseline_v1",
        collected_at=collected_at or datetime.now(timezone.utc),
        sections={
            "system": {"platform": "windows", **system},
            "hardware": collect_hardware(probe),
            "storage": collect_storage(probe),
            "interfaces": collect_baseline_interfaces(probe),
            "software": collect_software(),
        },
        warnings=[],
    )


def _read(probe: object, path: str, warnings: list[str]) -> str:
    try:
        return str(probe.read_text(path, 16_384))
    except (OSError, ValueError, TimeoutError):
        warnings.append("source_unavailable")
        return ""


def _run(probe: object, command: tuple[str, ...], warnings: list[str]) -> str:
    try:
        return str(probe.run(command, 3.0, 32_768))
    except TimeoutError:
        warnings.append("command_timed_out")
    except (OSError, ValueError):
        warnings.append("command_failed")
    return ""


def _platform_for(os_release: str, probe: object) -> str:
    configured = str(getattr(probe, "platform_name", "")).lower()
    if configured in {"linux", "windows"}:
        return configured
    if os_release:
        return "linux"
    return "windows" if platform.system().lower() == "windows" else "linux"


def _distribution(os_release: str, system_platform: str) -> str:
    for line in os_release.splitlines():
        if line.startswith("PRETTY_NAME="):
            return bounded_text(line.split("=", 1)[1].strip().strip('"'), fallback="Unknown")
    return "Windows" if system_platform == "windows" else "Linux"


def _architecture() -> str:
    machine = platform.machine().lower()
    return "aarch64" if machine in {"aarch64", "arm64"} else "x86_64"


def _cpu_model(cpuinfo: str) -> str:
    for line in cpuinfo.splitlines():
        if ":" in line and line.split(":", 1)[0].strip().lower() in {"model name", "hardware"}:
            return bounded_text(line.split(":", 1)[1], fallback="Unknown")
    return "Unknown"


def _memory_bytes(meminfo: str, warnings: list[str]) -> int:
    for line in meminfo.splitlines():
        if line.startswith("MemTotal:"):
            fields = line.split()
            try:
                return max(1, int(fields[1]) * 1024)
            except (IndexError, ValueError):
                break
    warnings.append("source_unavailable")
    return 1


def _storage(probe: object, warnings: list[str]) -> list[dict[str, object]]:
    try:
        records = json.loads(_run(probe, LSBLK_COMMAND, warnings)).get("blockdevices", [])
    except (TypeError, ValueError, AttributeError):
        warnings.append("source_unavailable")
        records = []
    result: list[dict[str, object]] = []
    for record in records:
        if not isinstance(record, Mapping) or record.get("type") != "disk":
            continue
        try:
            size = max(1, int(record.get("size") or 0))
        except (TypeError, ValueError):
            size = 1
        name = bounded_text(record.get("name"), fallback="unknown", limit=64)
        result.append(
            {
                "stable_key": disk_stable_key(
                    wwn=record.get("wwn"), serial=record.get("serial"), fallback_name=name
                ),
                "model": bounded_text(record.get("model"), fallback="Unknown"),
                "size_bytes": size,
            }
        )
    if not result:
        warnings.append("source_unavailable")
        return [{"stable_key": "disk-unknown", "model": "Unknown", "size_bytes": 1}]
    return result[:64]


def _interfaces(probe: object, warnings: list[str]) -> list[dict[str, str]]:
    try:
        records = json.loads(_run(probe, IP_LINK_COMMAND, warnings))
    except (TypeError, ValueError):
        warnings.append("source_unavailable")
        return []
    result: list[dict[str, str]] = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        name = bounded_text(record.get("ifname"), fallback="unknown", limit=64)
        raw_type = str(record.get("link_type") or "").lower()
        link_type = "ethernet" if raw_type == "ether" else "loopback" if raw_type == "loopback" else "other"
        result.append(
            {
                "stable_key": interface_stable_key(mac=record.get("address"), fallback_name=name),
                "name": name,
                "link_type": link_type,
            }
        )
    return result[:64]


def _unique_warnings(warnings: list[str]) -> list[str]:
    return list(dict.fromkeys(warnings))[:16]
