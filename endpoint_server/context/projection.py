"""Safe public projections; raw Device Context transport never crosses this boundary."""

from __future__ import annotations

import re

from endpoint_contracts import DeviceContextEnvelopeV1

from .models import ContextCollection, ContextCurrent, ContextSnapshot


_BASELINE_MAC_KEY_RE = re.compile(r"^mac-[0-9a-f]{12}$")


def collection_projection(collection: ContextCollection) -> dict[str, object]:
    """Return collection lifecycle metadata, excluding requester and raw result."""
    return {
        "id": str(collection.id),
        "device_id": str(collection.device_id),
        "profile": collection.profile,
        "status": collection.status,
        "requested_at": collection.requested_at,
        "result_received_at": collection.result_received_at,
        "completed_at": collection.completed_at,
        "failure_code": collection.failure_code,
    }


def snapshot_projection(snapshot: ContextSnapshot) -> dict[str, object] | None:
    """Return a validated safe profile, refusing diagnostics and malformed JSON."""
    if snapshot.profile == "diagnostic_v1":
        return None
    try:
        envelope = DeviceContextEnvelopeV1.model_validate(snapshot.normalized_projection)
    except Exception:
        return None
    if envelope.profile == "diagnostic_v1":
        return None
    return {
        "id": str(snapshot.id),
        "profile": envelope.profile,
        "collected_at": envelope.collected_at,
        "semantic_hash": snapshot.semantic_hash,
        "warnings": envelope.warnings,
        "sections": envelope.sections.model_dump(mode="json"),
    }


def activity_current_projection(current: ContextCurrent) -> dict[str, object] | None:
    """Read only the latest validated Activity fields, not the older state snapshot."""
    if current.profile != "activity_v1" or current.last_projection is None:
        return None
    try:
        envelope = DeviceContextEnvelopeV1.model_validate(current.last_projection)
    except Exception:
        return None
    if envelope.profile != "activity_v1":
        return None
    return {
        "profile": "activity_v1",
        "collected_at": envelope.collected_at,
        "last_observed_at": current.last_observed_at or current.updated_at,
        "sections": envelope.sections.model_dump(mode="json"),
    }


def baseline_interface_mac_keys(snapshot: ContextSnapshot) -> tuple[str, ...]:
    """Return only canonical baseline interface identity keys for a service peer."""
    try:
        envelope = DeviceContextEnvelopeV1.model_validate(snapshot.normalized_projection)
    except Exception:
        return ()
    if envelope.profile != "baseline_v1":
        return ()
    return tuple(
        sorted(
            {
                interface.stable_key
                for interface in envelope.sections.interfaces
                if _BASELINE_MAC_KEY_RE.fullmatch(interface.stable_key)
            }
        )
    )


__all__ = [
    "activity_current_projection",
    "baseline_interface_mac_keys",
    "collection_projection",
    "snapshot_projection",
]
