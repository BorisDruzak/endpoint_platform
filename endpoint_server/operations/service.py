"""Transactional service boundary for persisted Endpoint Operations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts import EndpointOperationCreateV1
from endpoint_server.audit.service import append_audit_event
from endpoint_server.context.models import ContextCollection
from endpoint_server.db.models import (
    Command,
    CommandDelivery,
    Device,
    EndpointOperation,
    ServiceClient,
)

from .capabilities import profile_for_capability


OPERATION_TTL = timedelta(minutes=15)
_ACTIVE_STATUSES = frozenset({"queued", "delivered", "acknowledged", "running"})


class OperationError(Exception):
    """Base error carrying a stable service/API-safe code."""

    code = "endpoint_operation_error"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class OperationConflict(OperationError):
    code = "endpoint_operation_idempotency_conflict"


class OperationNotFound(OperationError):
    code = "endpoint_operation_not_found"


class OperationValidationError(OperationError):
    code = "endpoint_operation_invalid"


def _uuid(value: UUID | str, name: str) -> UUID:
    try:
        return value if isinstance(value, UUID) else UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise OperationValidationError(f"{name} must be a UUID") from error


def _now(value: datetime | None = None) -> datetime:
    timestamp = value or datetime.now(UTC)
    if timestamp.utcoffset() is None:
        raise OperationValidationError("operation timestamp must be timezone-aware")
    return timestamp.astimezone(UTC)


def _idempotency_key(value: str) -> str:
    if (
        not isinstance(value, str)
        or not 8 <= len(value) <= 128
        or value != value.strip()
        or not value.isprintable()
    ):
        raise OperationValidationError(
            "idempotency key must be 8-128 trimmed printable characters"
        )
    return value


def _normalized_request(
    request: EndpointOperationCreateV1,
) -> tuple[str, dict[str, object], dict[str, object] | None]:
    if not isinstance(request, EndpointOperationCreateV1):
        raise OperationValidationError(
            "request must be an EndpointOperationCreateV1 contract"
        )
    parameters = request.parameters.model_dump(mode="json")
    correlation = (
        request.correlation.model_dump(mode="json")
        if request.correlation is not None
        else None
    )
    return request.capability, parameters, correlation


def _audit_request_id(
    correlation: dict[str, object] | None,
    operation_id: UUID,
) -> str:
    if correlation is not None and correlation.get("request_id") is not None:
        return str(correlation["request_id"])
    return f"operation-{operation_id.hex}"


async def _advisory_lock(session: AsyncSession, key: str) -> None:
    if session.get_bind().dialect.name == "postgresql":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": key},
        )


async def _append_operation_audit(
    session: AsyncSession,
    *,
    operation: EndpointOperation,
    action: str,
    actor_kind: str,
    actor_identifier: str | None,
    occurred_at: datetime,
) -> None:
    await append_audit_event(
        session,
        actor_kind=actor_kind,
        actor_identifier=actor_identifier,
        action=action,
        object_kind="endpoint_operation",
        object_identifier=str(operation.id),
        request_id=_audit_request_id(operation.correlation, operation.id),
        details={
            "capability": operation.capability,
            "device_id": operation.device_id,
            "status": operation.status,
        },
        occurred_at=occurred_at,
    )


async def create_operation_outcome(
    session: AsyncSession,
    *,
    request: EndpointOperationCreateV1,
    service_client_id: UUID | str,
    device_id: UUID | str,
    idempotency_key: str,
    now: datetime | None = None,
) -> tuple[EndpointOperation, bool]:
    """Create operation, private collection and audit in the caller's transaction."""
    checked_client_id = _uuid(service_client_id, "service client id")
    checked_device_id = _uuid(device_id, "device id")
    checked_key = _idempotency_key(idempotency_key)
    capability, parameters, correlation = _normalized_request(request)
    profile = profile_for_capability(capability)
    occurred_at = _now(now)

    await _advisory_lock(
        session,
        f"endpoint.operation:{checked_client_id}:{checked_key}",
    )
    client = await session.scalar(
        select(ServiceClient)
        .where(ServiceClient.id == checked_client_id)
        .with_for_update()
    )
    if client is None:
        raise OperationNotFound(
            "service client was not found",
            code="endpoint_operation_service_not_found",
        )

    existing = await session.scalar(
        select(EndpointOperation)
        .where(
            EndpointOperation.requested_by_service_client_id == checked_client_id,
            EndpointOperation.idempotency_key == checked_key,
        )
        .with_for_update()
    )
    if existing is not None:
        if (
            existing.device_id != checked_device_id
            or existing.capability != capability
            or existing.parameters != parameters
            or existing.correlation != correlation
        ):
            raise OperationConflict(
                "idempotency key already owns a different endpoint operation"
            )
        await _append_operation_audit(
            session,
            operation=existing,
            action="endpoint.operation_replayed",
            actor_kind="service",
            actor_identifier=client.client_identifier,
            occurred_at=occurred_at,
        )
        await session.flush()
        return existing, False

    device = await session.scalar(
        select(Device)
        .where(Device.id == checked_device_id, Device.retired_at.is_(None))
        .with_for_update()
    )
    if device is None:
        raise OperationNotFound(
            "active device was not found",
            code="endpoint_operation_device_not_found",
        )

    operation_id = uuid4()
    collection_id = uuid4()
    deadline_at = occurred_at + OPERATION_TTL
    operation = EndpointOperation(
        id=operation_id,
        created_at=occurred_at,
        requested_by_service_client_id=checked_client_id,
        device_id=checked_device_id,
        idempotency_key=checked_key,
        capability=capability,
        parameters=parameters,
        correlation=correlation,
        status="queued",
        deadline_at=deadline_at,
        completed_at=None,
        context_collection_id=collection_id,
        command_id=None,
    )
    collection = ContextCollection(
        id=collection_id,
        created_at=occurred_at,
        device_id=checked_device_id,
        profile=profile,
        requested_by=f"endpoint-operation:{checked_client_id.hex}",
        idempotency_key=checked_key,
        command_id=None,
        command_result_id=None,
        operation_id=operation_id,
        status="requested",
        requested_at=occurred_at,
        expires_at=deadline_at,
    )
    session.add_all((operation, collection))
    await _append_operation_audit(
        session,
        operation=operation,
        action="endpoint.operation_created",
        actor_kind="service",
        actor_identifier=client.client_identifier,
        occurred_at=occurred_at,
    )
    await session.flush()
    return operation, True


async def read_operation_for_service(
    session: AsyncSession,
    *,
    operation_id: UUID | str,
    service_client_id: UUID | str,
    now: datetime | None = None,
) -> EndpointOperation:
    """Read one operation only through its owning service-client identity."""
    checked_operation_id = _uuid(operation_id, "operation id")
    checked_client_id = _uuid(service_client_id, "service client id")
    operation = await session.scalar(
        select(EndpointOperation)
        .where(
            EndpointOperation.id == checked_operation_id,
            EndpointOperation.requested_by_service_client_id == checked_client_id,
        )
        .with_for_update()
    )
    if operation is None:
        raise OperationNotFound("endpoint operation was not found")
    client = await session.scalar(
        select(ServiceClient).where(ServiceClient.id == checked_client_id)
    )
    if client is None:
        raise OperationNotFound("endpoint operation was not found")
    await _append_operation_audit(
        session,
        operation=operation,
        action="endpoint.operation_read",
        actor_kind="service",
        actor_identifier=client.client_identifier,
        occurred_at=_now(now),
    )
    await session.flush()
    return operation


async def append_operation_terminal_audit(
    session: AsyncSession,
    operation: EndpointOperation,
    *,
    occurred_at: datetime,
) -> None:
    """Append one safe audit for a newly persisted device terminal state."""
    if operation.status not in {"succeeded", "failed", "canceled", "expired"}:
        raise OperationValidationError("operation status must be terminal")
    await _append_operation_audit(
        session,
        operation=operation,
        action=f"endpoint.operation_{operation.status}",
        actor_kind="device",
        actor_identifier=str(operation.device_id),
        occurred_at=_now(occurred_at),
    )


async def expire_operations(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> int:
    """Expire bounded queued work and its private collection in one transaction."""
    if not 1 <= limit <= 100:
        raise OperationValidationError("expiration limit must be between 1 and 100")
    expired_at = _now(now)
    operations = (
        await session.scalars(
            select(EndpointOperation)
            .where(
                EndpointOperation.status.in_(_ACTIVE_STATUSES),
                EndpointOperation.deadline_at <= expired_at,
            )
            .order_by(EndpointOperation.deadline_at, EndpointOperation.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    ).all()
    for operation in operations:
        operation.status = "expired"
        operation.completed_at = expired_at
        collection = await session.scalar(
            select(ContextCollection)
            .where(ContextCollection.operation_id == operation.id)
            .with_for_update()
        )
        if collection is not None and collection.status not in {
            "completed",
            "failed",
            "expired",
        }:
            collection.status = "expired"
            collection.failed_at = expired_at
            collection.failure_code = "operation_expired"
        if operation.command_id is not None:
            command = await session.scalar(
                select(Command)
                .where(
                    Command.id == operation.command_id,
                    Command.device_id == operation.device_id,
                )
                .with_for_update()
            )
            if command is not None and command.status not in {
                "succeeded",
                "failed",
                "canceled",
                "expired",
            }:
                command.status = "expired"
            delivery = await session.scalar(
                select(CommandDelivery)
                .where(CommandDelivery.command_id == operation.command_id)
                .with_for_update()
            )
            if delivery is not None and delivery.status not in {
                "succeeded",
                "failed",
                "canceled",
                "expired",
            }:
                delivery.status = "expired"
        await _append_operation_audit(
            session,
            operation=operation,
            action="endpoint.operation_expired",
            actor_kind="system",
            actor_identifier=None,
            occurred_at=expired_at,
        )
    await session.flush()
    return len(operations)


__all__ = [
    "OPERATION_TTL",
    "OperationConflict",
    "OperationError",
    "OperationNotFound",
    "OperationValidationError",
    "append_operation_terminal_audit",
    "create_operation_outcome",
    "expire_operations",
    "read_operation_for_service",
]
