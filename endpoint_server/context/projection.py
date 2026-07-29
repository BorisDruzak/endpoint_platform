"""Safe public projections; raw Device Context transport never crosses this boundary."""

from __future__ import annotations

from endpoint_contracts import DeviceContextEnvelopeV1

from .models import ContextCollection, ContextSnapshot


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


__all__ = ["collection_projection", "snapshot_projection"]
