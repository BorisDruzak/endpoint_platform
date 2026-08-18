"""Safe public projection of persisted Endpoint Operation state."""

from __future__ import annotations

from datetime import UTC, datetime

from endpoint_contracts import (
    DiagnosticCollectionParametersV1,
    DeviceContextDiagnosticV1,
    EndpointDiagnosticResultV1,
    EndpointOperationV1,
)
from endpoint_server.context.models import ContextSnapshot
from endpoint_server.db.models.operations import EndpointOperation

from .redaction import sanitize_agent_public_text


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


def project_diagnostic_result(
    operation: EndpointOperation,
    snapshot: ContextSnapshot,
) -> EndpointDiagnosticResultV1 | None:
    """Validate one diagnostic snapshot into the smaller service-safe contract."""
    if (
        snapshot.profile != "diagnostic_v1"
        or snapshot.device_id != operation.device_id
        or snapshot.collection_id != operation.context_collection_id
    ):
        return None
    try:
        parameters = DiagnosticCollectionParametersV1.model_validate(
            operation.parameters
        )
        envelope = DeviceContextDiagnosticV1.model_validate(
            snapshot.normalized_projection
        )

        redaction_applied = False
        processes: list[dict[str, str]] = []
        for process in envelope.sections.processes:
            name, changed = sanitize_agent_public_text(process.name, limit=128)
            redaction_applied = redaction_applied or changed
            processes.append({"name": name, "state": process.state})

        log_excerpt: str | None = None
        if envelope.sections.log_excerpt is not None:
            log_excerpt, changed = sanitize_agent_public_text(
                envelope.sections.log_excerpt,
                limit=8192,
                allow_multiline=True,
            )
            redaction_applied = redaction_applied or changed

        warnings = list(envelope.warnings)
        if redaction_applied and "redaction_applied" not in warnings:
            warnings = [*warnings[:15], "redaction_applied"]
        return EndpointDiagnosticResultV1.model_validate(
            {
                "schema_version": "endpoint_diagnostic_result_v1",
                "profile": envelope.profile,
                "collected_at": envelope.collected_at,
                "reason": parameters.reason,
                "warnings": warnings,
                "processes": processes,
                "log_excerpt": log_excerpt,
            }
        )
    except Exception:
        return None


__all__ = ["project_diagnostic_result", "project_operation"]
