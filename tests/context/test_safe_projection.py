from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from endpoint_server.context.projection import collection_projection, snapshot_projection
from endpoint_server.context.models import ContextCollection, ContextSnapshot


def test_snapshot_projection_excludes_raw_agent_result_diagnostic_and_secret_like_fields() -> None:
    snapshot = ContextSnapshot(
        id=uuid4(), collection_id=uuid4(), device_id=uuid4(), profile="diagnostic_v1",
        collected_at=datetime.now(UTC), semantic_hash="a" * 64,
        raw_payload={"token": "secret", "result_items": [{"traceback": "C:\\\\secret"}]},
        normalized_projection={"profile": "diagnostic_v1", "sections": {"log_excerpt": "raw diagnostic"}},
    )

    assert snapshot_projection(snapshot) is None


def test_collection_projection_never_includes_raw_transport_payload() -> None:
    collection = ContextCollection(
        id=uuid4(), device_id=uuid4(), profile="baseline_v1", requested_by="svc", idempotency_key="request-1",
        status="completed", requested_at=datetime.now(UTC), raw_result_payload={"token": "secret", "traceback": "raw"},
    )

    projection = collection_projection(collection)

    assert "raw" not in str(projection).lower()
    assert "token" not in str(projection).lower()
    assert "idempotency" not in projection
