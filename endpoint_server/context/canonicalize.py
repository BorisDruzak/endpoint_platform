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


__all__ = ["canonicalize_baseline"]
