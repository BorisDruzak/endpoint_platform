"""Windows local network facts without WMI, PowerShell, or connectivity probes."""

from __future__ import annotations

from collections.abc import Mapping
import socket

from pc_agent.context_profiles.stable_keys import bounded_text, interface_stable_key


MAX_WINDOWS_INTERFACES = 64
MAX_INTERFACE_ADDRESSES = 16


def collect_baseline_interfaces(probe: object) -> list[dict[str, str]]:
    return [
        {
            "stable_key": interface_stable_key(mac=record.get("mac"), fallback_name=record.get("name")),
            "name": bounded_text(record.get("name"), fallback="unknown", limit=64),
            "link_type": _link_type(record.get("link_type")),
        }
        for record in _interfaces(probe)
    ]


def collect_network_interfaces(probe: object) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for record in _interfaces(probe):
        addresses = [
            bounded_text(value, fallback="", limit=64)
            for value in record.get("addresses", [])
            if bounded_text(value, fallback="", limit=64)
        ]
        result.append({"name": bounded_text(record.get("name"), fallback="unknown", limit=64), "addresses": list(dict.fromkeys(addresses))[:MAX_INTERFACE_ADDRESSES]})
    return result


def collect_default_route(probe: object) -> dict[str, str | None]:
    candidate = getattr(probe, "windows_default_route", None)
    if callable(candidate):
        try:
            value = candidate()
        except (OSError, ValueError, TimeoutError):
            value = None
        if isinstance(value, Mapping):
            return {
                "interface": bounded_text(value.get("interface"), fallback="unknown", limit=64),
                "gateway": bounded_text(value.get("gateway"), fallback="", limit=64) or None,
            }
    return {"interface": "unknown", "gateway": None}


def native_interfaces() -> list[dict[str, object]]:
    """Use only socket's bounded interface-name API as a conservative fallback."""
    try:
        names = socket.if_nameindex()
    except OSError:
        return []
    return [{"name": name, "link_type": "other", "addresses": []} for _index, name in names[:MAX_WINDOWS_INTERFACES]]


def native_default_route() -> dict[str, str | None]:
    return {"interface": "unknown", "gateway": None}


def _interfaces(probe: object) -> list[Mapping[str, object]]:
    candidate = getattr(probe, "windows_interfaces", None)
    if callable(candidate):
        try:
            value = candidate()
        except (OSError, ValueError, TimeoutError):
            value = None
        if isinstance(value, list):
            return [record for record in value[:MAX_WINDOWS_INTERFACES] if isinstance(record, Mapping)]
    return native_interfaces()


def _link_type(value: object) -> str:
    normalized = str(value or "").lower()
    return normalized if normalized in {"ethernet", "loopback", "wireless", "other"} else "other"


__all__ = ["collect_baseline_interfaces", "collect_default_route", "collect_network_interfaces", "native_default_route", "native_interfaces"]
