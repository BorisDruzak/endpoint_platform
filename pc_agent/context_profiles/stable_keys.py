"""Stable-key normalization for baseline facts; never expose a device identity."""

from __future__ import annotations

import re


_SAFE_KEY = re.compile(r"[^A-Za-z0-9._:-]+")


def bounded_text(value: object, *, fallback: str, limit: int = 256) -> str:
    text = " ".join(str(value or "").strip().split())
    return (text or fallback)[:limit]


def disk_stable_key(*, wwn: object, serial: object, fallback_name: object) -> str:
    if normalized := _normalized_key(wwn):
        return f"wwn-{normalized}"
    if normalized := _normalized_key(serial):
        return f"serial-{normalized}"
    return f"disk-{_normalized_key(fallback_name) or 'unknown'}"


def interface_stable_key(*, mac: object, fallback_name: object) -> str:
    normalized_mac = re.sub(r"[^0-9A-Fa-f]", "", str(mac or ""))
    if len(normalized_mac) == 12:
        return f"mac-{normalized_mac.lower()}"
    return f"iface-{_normalized_key(fallback_name) or 'unknown'}"


def _normalized_key(value: object) -> str:
    normalized = _SAFE_KEY.sub("-", str(value or "").strip())
    return normalized.strip("-._:")[:112].lower()
