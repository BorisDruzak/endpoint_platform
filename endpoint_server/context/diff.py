"""Fixed-code semantic diffs for baseline snapshots."""

from __future__ import annotations

from collections.abc import Mapping

from endpoint_contracts import DeviceContextDiffV1
from endpoint_contracts.context import DeviceContextDiffChangeV1

from .canonicalize import canonicalize_baseline
from .semantic_hash import semantic_hash


_CHANGE_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("platform_changed", "system", "Platform changed"),
    ("hardware_changed", "hardware", "Hardware changed"),
    ("storage_changed", "storage", "Storage changed"),
    ("network_changed", "interfaces", "Network interfaces changed"),
    ("software_changed", "software", "Software changed"),
    ("agent_changed", "agent", "Agent changed"),
)


def compare_snapshots(
    before: Mapping[str, object] | object,
    after: Mapping[str, object] | object,
) -> DeviceContextDiffV1:
    """Compare two baseline observations without reflecting untrusted values."""
    before_canonical = canonicalize_baseline(before)
    after_canonical = canonicalize_baseline(after)
    before_sections = before_canonical["sections"]
    after_sections = after_canonical["sections"]
    assert isinstance(before_sections, Mapping)
    assert isinstance(after_sections, Mapping)
    changes = [
        DeviceContextDiffChangeV1(code=code, summary=summary)
        for code, field, summary in _CHANGE_FIELDS
        if before_sections.get(field) != after_sections.get(field)
    ]
    return DeviceContextDiffV1(
        schema_version="device_context_diff_v1",
        profile="baseline_v1",
        from_hash=semantic_hash(before_canonical),
        to_hash=semantic_hash(after_canonical),
        changes=changes,
    )


__all__ = ["compare_snapshots"]
