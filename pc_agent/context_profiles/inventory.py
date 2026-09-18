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
    if str(getattr(probe, "platform_name", "")).lower() == "windows":
        return _collect_windows_inventory(probe, collected_at=collected_at)
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


def _collect_windows_inventory(probe: object, *, collected_at: datetime | None) -> DeviceContextInventoryV1:
    candidate = getattr(probe, "windows_inventory", None)
    try:
        raw = candidate() if callable(candidate) else {}
    except (OSError, ValueError, TimeoutError):
        raw = {}
    source = raw if isinstance(raw, Mapping) else {}
    system = source.get("system") if isinstance(source.get("system"), Mapping) else {}
    hardware = source.get("hardware") if isinstance(source.get("hardware"), Mapping) else {}
    memory = source.get("memory") if isinstance(source.get("memory"), Mapping) else {}
    storage = source.get("storage") if isinstance(source.get("storage"), list) else []
    interfaces = source.get("interfaces") if isinstance(source.get("interfaces"), list) else []
    physical_devices = []
    for item in storage[:64]:
        if not isinstance(item, Mapping):
            continue
        serial = _optional(str(item.get("serial") or ""))
        physical_devices.append({"stable_key": disk_stable_key(wwn=None, serial=serial, fallback_name=item.get("model") or "disk"), "model": _optional(str(item.get("model") or "")), "serial": serial, "size_bytes": item.get("size_bytes") if isinstance(item.get("size_bytes"), int) and item.get("size_bytes") > 0 else None, "media_type": item.get("media_type") if item.get("media_type") in {"HDD", "SSD", "UNKNOWN"} else "UNKNOWN", "bus_type": item.get("bus_type") if item.get("bus_type") in {"SATA", "NVME", "USB", "SAS", "OTHER", "UNKNOWN"} else "UNKNOWN"})
    normalized_interfaces = []
    for item in interfaces[:64]:
        if not isinstance(item, Mapping) or not item.get("name"):
            continue
        mac = _optional(str(item.get("mac") or ""))
        normalized = mac.replace(":", "").replace("-", "").lower() if mac else None
        if normalized and len(normalized) != 12:
            normalized = None
        normalized_interfaces.append({"name": bounded_text(item.get("name"), fallback="unknown", limit=64), "stable_key": interface_stable_key(mac=normalized, fallback_name=item.get("name")), "mac": normalized, "ipv4": [str(value) for value in item.get("ipv4", [])[:16]], "ipv6": [str(value) for value in item.get("ipv6", [])[:16]], "link_type": item.get("link_type") if item.get("link_type") in {"ethernet", "loopback", "wireless", "other"} else "other", "operational_state": item.get("operational_state") if item.get("operational_state") in {"up", "down", "unknown"} else "unknown"})
    return DeviceContextInventoryV1(schema_version="device_context_v1", profile="inventory_v1", collected_at=collected_at or datetime.now(timezone.utc), sections={"system": {"hostname": _optional(str(system.get("hostname") or "")), "platform": "windows", "os_name": _optional(str(system.get("os_name") or "")), "os_version": _optional(str(system.get("os_version") or "")), "os_build": _optional(str(system.get("os_build") or "")), "architecture": system.get("architecture") if system.get("architecture") in {"x86_64", "aarch64"} else None}, "hardware": {key: _optional(str(hardware.get(key) or "")) for key in ("manufacturer", "model", "serial_number", "product_uuid", "cpu_model", "bios_vendor", "bios_version", "baseboard_manufacturer", "baseboard_model", "baseboard_serial")}, "memory": {"total_bytes": memory.get("total_bytes") if isinstance(memory.get("total_bytes"), int) and memory.get("total_bytes") > 0 else None, "memory_type": memory.get("memory_type") if memory.get("memory_type") in {"DDR", "DDR2", "DDR3", "DDR4", "DDR5", "UNKNOWN"} else None, "module_count": len(memory.get("modules", [])) if isinstance(memory.get("modules"), list) else 0, "modules": []}, "storage": {"physical_devices": physical_devices}, "interfaces": normalized_interfaces}, warnings=[] if source else ["probe_unavailable"])


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
