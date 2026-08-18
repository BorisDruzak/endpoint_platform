"""Safe public projection of persisted Endpoint Operation state."""

from __future__ import annotations

from datetime import UTC, datetime

from endpoint_contracts import EndpointOperationV1
from endpoint_server.db.models.operations import EndpointOperation


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def project_operation(operation: EndpointOperation) -> EndpointOperationV1:
    """Exclude private request, idempotency, service, collection and command data."""
    return EndpointOperationV1.model_validate(
        {
            "schema_version": "endpoint_operation_v1",
            "operation_id": operation.id,
            "device_id": operation.device_id,
            "capability": operation.capability,
            "status": operation.status,
            "created_at": _as_utc(operation.created_at),
            "deadline_at": _as_utc(operation.deadline_at),
            "completed_at": (
                _as_utc(operation.completed_at)
                if operation.completed_at is not None
                else None
            ),
            "correlation": operation.correlation,
            "result_available": operation.status == "succeeded",
            "warnings": [],
        }
    )


__all__ = ["project_operation"]
