"""Bounded Windows volume facts for the stable baseline profile."""

from __future__ import annotations

from collections.abc import Mapping
import ctypes
import os

from pc_agent.context_profiles.stable_keys import bounded_text, disk_stable_key


MAX_WINDOWS_VOLUMES = 26


def collect_storage(probe: object) -> list[dict[str, object]]:
    supplied = _probe_records(probe, "windows_storage")
    records = supplied if supplied is not None else _native_volumes()
    result: list[dict[str, object]] = []
    for record in records[:MAX_WINDOWS_VOLUMES]:
        size = _positive_int(record.get("size_bytes"), default=1)
        serial = record.get("serial")
        model = bounded_text(record.get("model"), fallback="Windows volume")
        result.append(
            {
                "stable_key": disk_stable_key(wwn=None, serial=serial, fallback_name=record.get("name") or "volume"),
                "model": model,
                "size_bytes": size,
            }
        )
    return result or [{"stable_key": "disk-unknown", "model": "Unknown", "size_bytes": 1}]


def native_storage() -> list[dict[str, object]]:
    return collect_storage(object())


def _probe_records(probe: object, name: str) -> list[Mapping[str, object]] | None:
    candidate = getattr(probe, name, None)
    if not callable(candidate):
        return None
    try:
        value = candidate()
    except (OSError, ValueError, TimeoutError):
        return None
    if not isinstance(value, list):
        return None
    return [record for record in value if isinstance(record, Mapping)]


def _native_volumes() -> list[dict[str, object]]:
    if os.name != "nt":
        return []
    try:
        bitmask = int(ctypes.windll.kernel32.GetLogicalDrives())
    except (AttributeError, OSError):
        return []
    records: list[dict[str, object]] = []
    for index in range(MAX_WINDOWS_VOLUMES):
        if not bitmask & (1 << index):
            continue
        root = f"{chr(ord('A') + index)}:\\"
        serial = ctypes.c_uint32(0)
        total = ctypes.c_ulonglong(0)
        try:
            valid = bool(
                ctypes.windll.kernel32.GetVolumeInformationW(root, None, 0, ctypes.byref(serial), None, None, None, 0)
                and ctypes.windll.kernel32.GetDiskFreeSpaceExW(root, None, ctypes.byref(total), None)
            )
        except (AttributeError, OSError):
            valid = False
        if valid:
            records.append({"name": root[:2], "serial": f"{serial.value:08x}", "model": "Windows volume", "size_bytes": int(total.value)})
    return records


def _positive_int(value: object, *, default: int) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


__all__ = ["MAX_WINDOWS_VOLUMES", "collect_storage", "native_storage"]
