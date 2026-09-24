"""Deterministic, privacy-preserving baseline normalization for semantic storage."""

from __future__ import annotations

from collections.abc import Mapping


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _field(source: Mapping[str, object], name: str) -> object:
    return source.get(name)


def _stable_sorted(items: object, *, fields: tuple[str, ...]) -> list[dict[str, object]]:
    if not isinstance(items, list):
        return []
    normalized = [
        {field: _field(_mapping(item), field) for field in fields}
        for item in items
        if isinstance(item, Mapping)
    ]
    return sorted(
        normalized,
        key=lambda item: tuple("" if item[field] is None else str(item[field]) for field in fields),
    )


def canonicalize_baseline(snapshot: Mapping[str, object] | object) -> dict[str, object]:
    """Return the baseline facts which are material for change detection.

    The input is deliberately treated as untrusted persisted JSON.  This makes
    canonicalization independent of transport timestamps, warnings, temporary
    addresses and caller-controlled ordering.  Interface stable keys remain,
    so a material network identity change is never hidden with an IP change.
    """
    source = _mapping(snapshot)
    if source.get("profile") != "baseline_v1":
        raise ValueError("semantic canonicalization requires a baseline snapshot")
    sections = _mapping(source.get("sections"))
    system = _mapping(sections.get("system"))
    hardware = _mapping(sections.get("hardware"))
    return {
        "schema_version": "device_context_baseline_canonical_v1",
        "profile": "baseline_v1",
        # Keeping an explicit null documents that collection time is excluded.
        "collected_at": None,
        "sections": {
            "system": {
                "architecture": _field(system, "architecture"),
                "distribution": _field(system, "distribution"),
                "platform": _field(system, "platform"),
            },
            "hardware": {
                "cpu_model": _field(hardware, "cpu_model"),
                "manufacturer": _field(hardware, "manufacturer"),
                "memory_bytes": _field(hardware, "memory_bytes"),
                "model": _field(hardware, "model"),
            },
            "storage": _stable_sorted(
                sections.get("storage"), fields=("stable_key", "model", "size_bytes")
            ),
            "interfaces": _stable_sorted(
                sections.get("interfaces"), fields=("stable_key", "name", "link_type")
            ),
            "software": _stable_sorted(
                sections.get("software"), fields=("name", "source", "version")
            ),
        },
    }


def canonicalize_inventory(snapshot: Mapping[str, object] | object) -> dict[str, object]:
    """Return stable physical inventory facts, excluding volatile observation data."""
    source = _mapping(snapshot)
    if source.get("profile") != "inventory_v1":
        raise ValueError("semantic canonicalization requires an inventory snapshot")
    sections = _mapping(source.get("sections"))
    return {
        "schema_version": "device_context_inventory_canonical_v1",
        "profile": "inventory_v1",
        "collected_at": None,
        "sections": {
            "system": dict(_mapping(sections.get("system"))),
            "hardware": dict(_mapping(sections.get("hardware"))),
            "memory": {
                "total_bytes": _field(_mapping(sections.get("memory")), "total_bytes"),
                "memory_type": _field(_mapping(sections.get("memory")), "memory_type"),
                "modules": _stable_sorted(_mapping(sections.get("memory")).get("modules"), fields=("slot", "serial", "capacity_bytes", "speed_mt_s", "memory_type")),
            },
            "storage": _stable_sorted(_mapping(sections.get("storage")).get("physical_devices"), fields=("stable_key", "model", "serial", "size_bytes", "media_type", "bus_type")),
            "interfaces": _stable_sorted(sections.get("interfaces"), fields=("stable_key", "mac", "name", "link_type", "operational_state")),
        },
    }


def canonicalize_session(snapshot: Mapping[str, object] | object) -> dict[str, object]:
    source = _mapping(snapshot)
    if source.get("profile") != "session_v1":
        raise ValueError("semantic canonicalization requires a session snapshot")
    sections = _mapping(source.get("sections"))
    return {
        "profile": "session_v1",
        "current_user_login": sections.get("current_user_login"),
        "interactive_session_present": sections.get("interactive_session_present"),
    }


def canonicalize_network(snapshot: Mapping[str, object] | object) -> dict[str, object]:
    source = _mapping(snapshot)
    if source.get("profile") != "network_v1":
        raise ValueError("semantic canonicalization requires a network snapshot")
    sections = _mapping(source.get("sections"))
    route = _mapping(sections.get("default_route"))
    interfaces = sections.get("interfaces")
    items = []
    if isinstance(interfaces, list):
        for interface in interfaces:
            if not isinstance(interface, Mapping):
                continue
            addresses = interface.get("addresses")
            items.append({
                "name": interface.get("name"),
                "addresses": sorted(addresses) if isinstance(addresses, list) else [],
            })
    return {
        "profile": "network_v1",
        "default_route": {"interface": route.get("interface"), "gateway": route.get("gateway")},
        "interfaces": sorted(items, key=lambda item: (str(item["name"]), item["addresses"])),
    }


__all__ = ["canonicalize_baseline", "canonicalize_inventory", "canonicalize_session", "canonicalize_network"]
