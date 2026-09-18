"""Fixed-code semantic diffs for baseline and inventory snapshots."""

from __future__ import annotations

from collections.abc import Mapping

from endpoint_contracts import DeviceContextDiffV1
from endpoint_contracts.context import DeviceContextDiffChangeV1

from .canonicalize import canonicalize_baseline, canonicalize_inventory
from .semantic_hash import semantic_hash


_CHANGE_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("PLATFORM_CHANGED", "system", "Platform changed"),
    ("HARDWARE_CHANGED", "hardware", "Hardware changed"),
    ("STORAGE_CHANGED", "storage", "Storage changed"),
    ("NETWORK_CHANGED", "interfaces", "Network interfaces changed"),
    ("SOFTWARE_CHANGED", "software", "Software changed"),
    ("AGENT_CHANGED", "agent", "Agent changed"),
)

_INVENTORY_CHANGE_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("HARDWARE_CHANGED", "hardware", "Hardware changed"),
    ("RAM_CHANGED", "memory", "RAM configuration changed"),
    ("STORAGE_CHANGED", "storage", "Storage changed"),
    ("NETWORK_CHANGED", "interfaces", "Network interfaces changed"),
)


def compare_snapshots(
    before: Mapping[str, object] | object,
    after: Mapping[str, object] | object,
) -> DeviceContextDiffV1:
    """Compare compatible observations without reflecting untrusted values."""
    before_profile = before.get("profile") if isinstance(before, Mapping) else None
    after_profile = after.get("profile") if isinstance(after, Mapping) else None
    if before_profile != after_profile or before_profile not in {"baseline_v1", "inventory_v1"}:
        raise ValueError("semantic comparison requires matching baseline or inventory snapshots")
    canonicalize = (
        canonicalize_baseline if before_profile == "baseline_v1" else canonicalize_inventory
    )
    change_fields = (
        _CHANGE_FIELDS if before_profile == "baseline_v1" else _INVENTORY_CHANGE_FIELDS
    )
    before_canonical = canonicalize(before)
    after_canonical = canonicalize(after)
    before_sections = before_canonical["sections"]
    after_sections = after_canonical["sections"]
    assert isinstance(before_sections, Mapping)
    assert isinstance(after_sections, Mapping)
    changes = [
        DeviceContextDiffChangeV1(code=code, summary=summary)
        for code, field, summary in change_fields
        if before_sections.get(field) != after_sections.get(field)
    ]
    return DeviceContextDiffV1(
        schema_version="device_context_diff_v1",
        profile=before_profile,
        from_hash=semantic_hash(before_canonical),
        to_hash=semantic_hash(after_canonical),
        changes=changes,
    )


__all__ = ["compare_snapshots"]
