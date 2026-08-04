"""Bounded Windows identity and local platform facts.

Device Context deliberately does not expose the stable machine identity.  The
identity helper here is shared with the agent's proven MachineGuid resolver so
that context collection never falls back to a hostname or an address.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import ctypes
import os
import platform
from pathlib import Path

from pc_agent.context_profiles.stable_keys import bounded_text
import pc_agent.core.machine_identity as machine_identity


MachineGuidReader = Callable[[], str | None]


def stable_machine_identity(
    *,
    machine_guid_reader: MachineGuidReader | None = None,
    fallback_file: Path | None = None,
) -> tuple[str, str]:
    """Resolve identity from MachineGuid, then the existing durable fallback.

    ``machine_guid_reader`` is injectable solely for native-API tests.  No
    hostname, DNS, network adapter or address participates in this result.
    """
    if machine_guid_reader is not None:
        machine_guid = str(machine_guid_reader() or "").strip()
        if machine_guid:
            return machine_identity._stable_uuid_from_seed(machine_guid, "windows_machine_guid"), "windows_machine_guid"
        return machine_identity._resolve_from_fallback_file(path=fallback_file)
    resolved = machine_identity._resolve_windows_machine_guid()
    return resolved if resolved is not None else machine_identity._resolve_from_fallback_file(path=fallback_file)


def collect_system(probe: object) -> dict[str, str]:
    supplied = _probe_mapping(probe, "windows_system")
    if supplied is not None:
        return {
            "distribution": bounded_text(supplied.get("distribution"), fallback="Windows"),
            "architecture": _architecture(supplied.get("architecture")),
        }
    release, version, _csd, _ptype = platform.win32_ver()
    distribution = " ".join(part for part in ("Windows", release, version) if part).strip()
    return {"distribution": bounded_text(distribution, fallback="Windows"), "architecture": _architecture(platform.machine())}


def collect_hardware(probe: object) -> dict[str, object]:
    supplied = _probe_mapping(probe, "windows_hardware")
    if supplied is not None:
        return {
            "manufacturer": bounded_text(supplied.get("manufacturer"), fallback="Unknown"),
            "model": bounded_text(supplied.get("model"), fallback="Unknown"),
            "cpu_model": bounded_text(supplied.get("cpu_model"), fallback="Unknown"),
            "memory_bytes": _positive_int(supplied.get("memory_bytes"), default=1),
        }
    return {
        "manufacturer": "Unknown",
        "model": "Unknown",
        "cpu_model": _processor_name(),
        "memory_bytes": _memory_bytes(),
    }


def collect_health(probe: object) -> dict[str, int]:
    supplied = _probe_mapping(probe, "windows_health")
    if supplied is not None:
        return {
            "uptime_seconds": max(0, _nonnegative_int(supplied.get("uptime_seconds"))),
            "free_bytes": _nonnegative_int(supplied.get("free_bytes")),
        }
    return {"uptime_seconds": _uptime_seconds(), "free_bytes": _available_memory_bytes()}


def is_windows_context(probe: object) -> bool:
    configured = str(getattr(probe, "platform_name", "")).strip().lower()
    return configured == "windows"


def native_system() -> dict[str, str]:
    """SystemProbe adapter for the fixed, local native fact surface."""
    return collect_system(object())


def native_hardware() -> dict[str, object]:
    """SystemProbe adapter for bounded registry and kernel32 facts."""
    return collect_hardware(object())


def native_health() -> dict[str, int]:
    return collect_health(object())


def _probe_mapping(probe: object, name: str) -> Mapping[str, object] | None:
    candidate = getattr(probe, name, None)
    if not callable(candidate):
        return None
    try:
        value = candidate()
    except (OSError, ValueError, TimeoutError):
        return None
    return value if isinstance(value, Mapping) else None


def _architecture(value: object) -> str:
    return "aarch64" if str(value or "").lower() in {"aarch64", "arm64"} else "x86_64"


def _positive_int(value: object, *, default: int) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def _nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _processor_name() -> str:
    if os.name != "nt":
        return "Unknown"
    try:
        import winreg

        access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            0,
            access,
        ) as key:
            value, _kind = winreg.QueryValueEx(key, "ProcessorNameString")
    except (ImportError, OSError):
        return "Unknown"
    return bounded_text(value, fallback="Unknown")


def _memory_bytes() -> int:
    if os.name != "nt":
        return 1

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(status)
    try:
        available = bool(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)))
    except (AttributeError, OSError):
        available = False
    return max(1, int(status.ullTotalPhys)) if available else 1


def _available_memory_bytes() -> int:
    if os.name != "nt":
        return 0

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(status)
    try:
        available = bool(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)))
    except (AttributeError, OSError):
        available = False
    return max(0, int(status.ullAvailPhys)) if available else 0


def _uptime_seconds() -> int:
    if os.name != "nt":
        return 0
    try:
        return max(0, int(ctypes.windll.kernel32.GetTickCount64() // 1000))
    except (AttributeError, OSError):
        return 0


__all__ = ["collect_hardware", "collect_health", "collect_system", "is_windows_context", "native_hardware", "native_health", "native_system", "stable_machine_identity"]
