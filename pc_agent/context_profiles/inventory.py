"""Bounded physical inventory collector for ALT/Linux hosts."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import json
import platform
import socket

from endpoint_contracts.context import DeviceContextInventoryV1

from .probe import IP_ADDRESS_COMMAND, IP_LINK_COMMAND, LSBLK_COMMAND
from .stable_keys import bounded_text, disk_stable_key, interface_stable_key


def collect_inventory(probe: object, *, collected_at: datetime | None = None) -> DeviceContextInventoryV1:
    warnings: list[str] = []
    os_release = _read(probe, "/etc/os-release", warnings)
    meminfo = _read(probe, "/proc/meminfo", warnings)
    cpuinfo = _read(probe, "/proc/cpuinfo", warnings)
    hardware = {
        "manufacturer": _optional(_read(probe, "/sys/class/dmi/id/sys_vendor", warnings)),
        "model": _optional(_read(probe, "/sys/class/dmi/id/product_name", warnings)),
        "serial_number": _optional(_read(probe, "/sys/class/dmi/id/product_serial", warnings)),
        "product_uuid": _optional(_read(probe, "/sys/class/dmi/id/product_uuid", warnings)),
        "cpu_model": _optional(_cpu_model(cpuinfo)),
        "bios_vendor": _optional(_read(probe, "/sys/class/dmi/id/bios_vendor", warnings)),
        "bios_version": _optional(_read(probe, "/sys/class/dmi/id/bios_version", warnings)),
        "baseboard_manufacturer": _optional(_read(probe, "/sys/class/dmi/id/board_vendor", warnings)),
        "baseboard_model": _optional(_read(probe, "/sys/class/dmi/id/board_name", warnings)),
        "baseboard_serial": _optional(_read(probe, "/sys/class/dmi/id/board_serial", warnings)),
    }
    return DeviceContextInventoryV1(
        schema_version="device_context_v1",
        profile="inventory_v1",
        collected_at=collected_at or datetime.now(timezone.utc),
        sections={
            "system": {
                "hostname": bounded_text(socket.gethostname(), fallback="unknown"),
                "platform": "linux",
                "os_name": _os_value(os_release, "NAME"),
                "os_version": _os_value(os_release, "VERSION_ID"),
                "os_build": None,
                "architecture": "aarch64" if platform.machine().lower() in {"aarch64", "arm64"} else "x86_64",
            },
            "hardware": hardware,
            "memory": {"total_bytes": _memory_bytes(meminfo), "memory_type": None, "module_count": 0, "modules": []},
            "storage": {"physical_devices": _storage(probe, warnings)},
            "interfaces": _interfaces(probe, warnings),
        },
        warnings=list(dict.fromkeys(warnings))[:16],
    )


def _read(probe: object, path: str, warnings: list[str]) -> str:
    try:
        value = str(probe.read_text(path, 16_384)).strip()
    except (OSError, ValueError, TimeoutError):
        value = ""
    if not value:
        warnings.append("source_unavailable")
    return value


def _run_json(probe: object, command: tuple[str, ...], warnings: list[str]) -> object:
    try:
        return json.loads(str(probe.run(command, 3.0, 32_768)))
    except TimeoutError:
        warnings.append("command_timed_out")
    except (OSError, ValueError, TypeError):
        warnings.append("command_failed")
    return []


def _optional(value: str) -> str | None:
    return bounded_text(value, fallback="", limit=256) or None


def _os_value(text: str, key: str) -> str | None:
    for line in text.splitlines():
        if line.startswith(f"{key}="):
            return _optional(line.split("=", 1)[1].strip().strip('"'))
    return None


def _cpu_model(text: str) -> str:
    for line in text.splitlines():
        if ":" in line and line.split(":", 1)[0].strip().lower() in {"model name", "hardware"}:
            return line.split(":", 1)[1].strip()
    return ""


def _memory_bytes(text: str) -> int | None:
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            try:
                return int(line.split()[1]) * 1024
            except (IndexError, ValueError):
                return None
    return None


def _storage(probe: object, warnings: list[str]) -> list[dict[str, object]]:
    records = _run_json(probe, LSBLK_COMMAND, warnings)
    result: list[dict[str, object]] = []
    for item in records.get("blockdevices", []) if isinstance(records, Mapping) else []:
        if not isinstance(item, Mapping) or item.get("type") != "disk":
            continue
        name = bounded_text(item.get("name"), fallback="unknown", limit=64)
        try:
            size = int(item.get("size")) if item.get("size") else None
        except (TypeError, ValueError):
            size = None
        result.append({"stable_key": disk_stable_key(wwn=item.get("wwn"), serial=item.get("serial"), fallback_name=name), "model": _optional(str(item.get("model") or "")), "serial": _optional(str(item.get("serial") or "")), "size_bytes": size, "media_type": "UNKNOWN", "bus_type": "UNKNOWN"})
    return result[:64]


def _interfaces(probe: object, warnings: list[str]) -> list[dict[str, object]]:
    links = _run_json(probe, IP_LINK_COMMAND, warnings)
    addresses = _run_json(probe, IP_ADDRESS_COMMAND, warnings)
    address_map: dict[str, tuple[list[str], list[str]]] = {}
    for item in addresses if isinstance(addresses, list) else []:
        if not isinstance(item, Mapping):
            continue
        ipv4, ipv6 = [], []
        for address in item.get("addr_info", []):
            if isinstance(address, Mapping) and address.get("local"):
                (ipv6 if address.get("family") == "inet6" else ipv4).append(str(address["local"]))
        address_map[str(item.get("ifname") or "")] = (ipv4[:16], ipv6[:16])
    result = []
    for item in links if isinstance(links, list) else []:
        if not isinstance(item, Mapping) or not item.get("ifname"):
            continue
        name, mac = str(item["ifname"]), _optional(str(item.get("address") or ""))
        normalized = mac.replace(":", "").replace("-", "").lower() if mac else None
        if normalized and len(normalized) != 12:
            normalized = None
        ipv4, ipv6 = address_map.get(name, ([], []))
        result.append({"name": bounded_text(name, fallback="unknown", limit=64), "stable_key": interface_stable_key(mac=normalized, fallback_name=name), "mac": normalized, "ipv4": ipv4, "ipv6": ipv6, "link_type": "ethernet" if item.get("link_type") == "ether" else "loopback" if item.get("link_type") == "loopback" else "other", "operational_state": "up" if str(item.get("operstate") or "").lower() == "up" else "down" if str(item.get("operstate") or "").lower() == "down" else "unknown"})
    return result[:64]
