"""Offline disk budgets for additional allocations, never existing retention."""
from __future__ import annotations

import errno
import ctypes
import os
from collections.abc import Iterable
from pathlib import Path
import shutil

MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MIN_MARGIN_BYTES = 64 * 1024 * 1024


class DiskInsufficient(OSError):
    """A bounded status without volume names, paths or raw OS error text."""

    def __init__(self) -> None:
        super().__init__("DISK_INSUFFICIENT")


def is_disk_full(error: BaseException) -> bool:
    """Recognize native disk-full errors, including wrapped durability errors."""
    for _ in range(8):
        if isinstance(error, DiskInsufficient) or getattr(error, "errno", None) == errno.ENOSPC or getattr(error, "winerror", None) in {39, 112}:
            return True
        cause = error.__cause__
        if cause is None or cause is error:
            break
        error = cause
    return False


def _validated_size(value: int, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("disk budget size is invalid")
    return value


def allocation_required_bytes(payload_bytes: int) -> int:
    """Add one margin to a validated volume's new payload allocations."""
    payload = _validated_size(payload_bytes, 4 * MAX_EXPANDED_BYTES)
    return payload + max(MIN_MARGIN_BYTES, (payload + 9) // 10)


def download_required_bytes(artifact_size: int) -> int:
    return allocation_required_bytes(_validated_size(artifact_size, MAX_ARTIFACT_BYTES))


def apply_required_bytes(artifact_size: int, expanded_size: int) -> int:
    return allocation_required_bytes(
        _validated_size(artifact_size, MAX_ARTIFACT_BYTES)
        + _validated_size(expanded_size, MAX_EXPANDED_BYTES)
    )


def require_disk_space(path: Path, required_bytes: int) -> None:
    if type(required_bytes) is not int or required_bytes < 0:
        raise ValueError("required disk space is invalid")
    existing = _existing_directory(path)
    if shutil.disk_usage(existing).free < required_bytes:
        raise DiskInsufficient()


def _existing_directory(path: Path) -> Path:
    existing = path.absolute()
    while not existing.exists():
        parent = existing.parent
        if parent == existing:
            raise OSError("disk target volume is unavailable")
        existing = parent
    if not existing.is_dir():
        existing = existing.parent
    return existing


def allocation_volume(path: Path) -> Path:
    """Resolve the receiving volume, including Windows mounted volumes."""
    existing = _existing_directory(path)
    if os.name == "nt":
        from ctypes import wintypes
        function = ctypes.WinDLL("kernel32", use_last_error=True).GetVolumePathNameW
        function.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        function.restype = wintypes.BOOL
        volume = ctypes.create_unicode_buffer(32768)
        if not function(str(existing), volume, len(volume)):
            raise OSError("disk target volume is unavailable")
        return Path(volume.value)
    device = existing.stat().st_dev
    while existing.parent != existing and existing.parent.stat().st_dev == device:
        existing = existing.parent
    return existing


def require_allocation_space(allocations: Iterable[tuple[Path, int]]) -> None:
    """Sum concurrent new allocations by receiving volume, then add margin."""
    volumes: dict[Path, int] = {}
    for path, size in allocations:
        volume = allocation_volume(path)
        volumes[volume] = volumes.get(volume, 0) + _validated_size(size, 4 * MAX_EXPANDED_BYTES)
    for volume, payload in volumes.items():
        require_disk_space(volume, allocation_required_bytes(payload))
