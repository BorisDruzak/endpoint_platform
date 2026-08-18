"""Durable command delivery and result handling for Gateway WSS."""

from __future__ import annotations

import inspect
import hashlib
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import AbstractSet
from uuid import UUID, uuid4

from sqlalchemy import select

from endpoint_contracts import (
    AgentCommandAckV1,
    AgentResultV1,
    CommandCorrelationV1,
    DeviceContextDiagnosticV1,
    DiagnosticCollectionParametersV1,
)
from endpoint_contracts.gateway_ws import (
    CommandEnvelopeV1,
    GatewayCommandV1,
    ResultAckEnvelopeV1,
    ResultAckV1,
)
from endpoint_server.context.ingestion import ingest_context_result
from endpoint_server.context.models import ContextCollection, ContextSnapshot
from endpoint_server.context.repository import link_collection_command
from endpoint_server.context.service import ContextError
from endpoint_server.db.models import (
    Command,
    CommandDelivery,
    CommandResult,
    DeviceInstance,
    DeviceSession,
    EndpointOperation,
)
from endpoint_server.db.session import SessionProvider
from endpoint_server.operations.projection import project_diagnostic_result
from endpoint_server.operations.redaction import sanitize_agent_public_text
from endpoint_server.operations.service import (
    append_operation_terminal_audit,
    expire_operation_if_due,
)

SendCommand = Callable[[CommandEnvelopeV1], Awaitable[None] | None]
_TERMINAL_STATUSES = frozenset({"succeeded", "failed", "canceled", "expired"})
_MAX_AGENT_CLOCK_SKEW = timedelta(minutes=5)
_CAPABILITIES = {
    "baseline_v1": "context.baseline.collect",
    "health_v1": "context.health.collect",
    "network_v1": "context.network.collect",
    "diagnostic_v1": "context.diagnostic.collect",
}


class CommandStateRejected(ValueError):
    pass


def _command_payload(
    command: Command,
    collection: ContextCollection,
    capability: str,
    operation: EndpointOperation | None = None,
) -> GatewayCommandV1:
    created_at = _as_utc(command.created_at)
    deadline_at = _as_utc(command.expires_at)
    if created_at is None or deadline_at is None:
        raise CommandStateRejected("command timing is unavailable")
    parameters: dict[str, object] = {}
    requested_by_service = collection.requested_by
    idempotency_key = f"context-{collection.id.hex}"
    correlation = CommandCorrelationV1()
    if operation is not None:
        if capability != "context.diagnostic.collect":
            raise CommandStateRejected("operation capability is unavailable")
        try:
            parameters = DiagnosticCollectionParametersV1.model_validate(
                operation.parameters
            ).model_dump(mode="json")
        except Exception as error:
            raise CommandStateRejected(
                "operation parameters are unavailable"
            ) from error
        requested_by_service = "endpoint-platform"
        idempotency_key = f"endpoint-operation:{operation.id.hex}"
        correlation = CommandCorrelationV1(request_id=operation.id)
        deadline_at = _as_utc(operation.deadline_at)
        if deadline_at is None:
            raise CommandStateRejected("operation timing is unavailable")
    return GatewayCommandV1(
        schema_version="agent_command_v1",
        command_id=command.id,
        device_id=command.device_id,
        capability=capability,
        parameters=parameters,
        requested_by_service=requested_by_service,
        idempotency_key=idempotency_key,
        created_at=created_at,
        deadline_at=deadline_at,
        correlation=correlation,
    )


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def result_payload_digest(result: AgentResultV1) -> str:
    """Return a non-reversible identity for an accepted terminal result."""
    normalized = result.model_copy(
        update={"completed_at": result.completed_at.astimezone(UTC)}
    )
    payload = json.dumps(
        normalized.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


async def _operation_for_collection(
    session,
    collection: ContextCollection,
    *,
    command: Command | None = None,
) -> EndpointOperation | None:
    if collection.operation_id is None:
        return None
    operation = await session.scalar(
        select(EndpointOperation)
        .where(EndpointOperation.id == collection.operation_id)
        .with_for_update()
    )

    return _validate_operation_relation(collection, operation, command=command)


def _validate_operation_relation(
    collection: ContextCollection,
    operation: EndpointOperation | None,
    *,
    command: Command | None = None,
) -> EndpointOperation:
    expected_capability = _CAPABILITIES.get(collection.profile)
    if (
        operation is None
        or collection.operation_id != operation.id
        or operation.context_collection_id != collection.id
        or operation.device_id != collection.device_id
        or operation.capability != expected_capability
        or collection.profile != "diagnostic_v1"
    ):
        raise CommandStateRejected("operation collection relation is unavailable")
    if command is not None and (
        collection.command_id != command.id
        or operation.command_id != command.id
        or command.device_id != operation.device_id
        or command.command_kind != operation.capability
    ):
        raise CommandStateRejected("operation command relation is unavailable")
    return operation


async def resolve_command_context_relation(
    session,
    command: Command,
) -> tuple[ContextCollection | None, EndpointOperation | None]:
    """Classify a context command from both sides of the operation relation."""
    collection = await session.scalar(
        select(ContextCollection)
        .where(ContextCollection.command_id == command.id)
        .with_for_update()
    )
    direct_operation = await session.scalar(
        select(EndpointOperation)
        .where(EndpointOperation.command_id == command.id)
        .with_for_update()
    )
    if direct_operation is None:
        if collection is None or collection.operation_id is None:
            return collection, None
        return collection, await _operation_for_collection(
            session,
            collection,
            command=command,
        )

    canonical_collection = collection
    if (
        canonical_collection is None
        or canonical_collection.id != direct_operation.context_collection_id
    ):
        canonical_collection = await session.scalar(
            select(ContextCollection)
            .where(ContextCollection.id == direct_operation.context_collection_id)
            .with_for_update()
        )
    if canonical_collection is None or (
        collection is not None and collection.id != canonical_collection.id
    ):
        raise CommandStateRejected("operation collection relation is unavailable")
    return canonical_collection, _validate_operation_relation(
        canonical_collection,
        direct_operation,
        command=command,
    )


def _safe_operation_result(
    operation: EndpointOperation,
    result: AgentResultV1,
) -> AgentResultV1:
    try:
        parameters = DiagnosticCollectionParametersV1.model_validate(
            operation.parameters
        )
    except Exception as error:
        raise CommandStateRejected("operation parameters are unavailable") from error

    safe_message = result.message
    if safe_message is not None:
        safe_message, _ = sanitize_agent_public_text(
            safe_message,
            limit=4096,
            allow_multiline=True,
        )
    if result.status != "succeeded":
        if result.result_items:
            raise CommandStateRejected(
                "failed diagnostic result must not contain context"
            )
        return result.model_copy(update={"message": safe_message})
    if len(result.result_items) != 1:
        raise CommandStateRejected(
            "successful diagnostic result must contain one context envelope"
        )
    try:
        diagnostic = DeviceContextDiagnosticV1.model_validate(result.result_items[0])
    except Exception as error:
        raise CommandStateRejected("diagnostic context is unavailable") from error
    if diagnostic.sections.reason != parameters.reason:
        raise CommandStateRejected("diagnostic reason does not match operation")

    redaction_applied = False
    safe_processes = []
    for process in diagnostic.sections.processes:
        name, changed = sanitize_agent_public_text(process.name, limit=128)
        redaction_applied = redaction_applied or changed
        safe_processes.append(process.model_copy(update={"name": name}))
    safe_excerpt = diagnostic.sections.log_excerpt
    if safe_excerpt is not None:
        safe_excerpt, changed = sanitize_agent_public_text(
            safe_excerpt,
            limit=8192,
            allow_multiline=True,
        )
        redaction_applied = redaction_applied or changed
    warnings = list(diagnostic.warnings)
    if redaction_applied and "redaction_applied" not in warnings:
        warnings = [*warnings[:15], "redaction_applied"]
    safe_sections = diagnostic.sections.model_copy(
        update={
            "processes": safe_processes,
            "log_excerpt": safe_excerpt,
        }
    )
    safe_diagnostic = diagnostic.model_copy(
        update={"sections": safe_sections, "warnings": warnings}
    )
    return result.model_copy(
        update={
            "result_items": [safe_diagnostic.model_dump(mode="json")],
            "message": safe_message,
        }
    )


async def next_pending_command(
    session,
    device_id: UUID,
    allowed_capabilities: AbstractSet[str] | None = None,
    *,
    transport: str = "http_pull",
) -> GatewayCommandV1 | None:
    """Replay only unacknowledged deliveries before creating a new command."""
    if transport not in {"http_pull", "gateway_wss"}:
        raise ValueError("unsupported gateway transport")
    collections = (
        await session.scalars(
            select(ContextCollection)
            .where(
                ContextCollection.device_id == device_id,
                ContextCollection.status.in_(("requested", "delivered")),
            )
            .order_by(ContextCollection.requested_at, ContextCollection.id)
            .with_for_update(skip_locked=True)
        )
    ).all()
    now = datetime.now(UTC)
    for collection in collections:
        if collection.operation_id is not None and transport != "gateway_wss":
            continue
        capability = _CAPABILITIES.get(collection.profile)
        if capability is None or (
            allowed_capabilities is not None
            and capability not in allowed_capabilities
        ):
            continue
        operation = await _operation_for_collection(session, collection)
        if collection.command_id is not None:
            command = await session.scalar(
                select(Command)
                .where(
                    Command.id == collection.command_id,
                    Command.device_id == device_id,
                )
                .with_for_update()
            )
            if command is not None and command.status == "delivered":
                operation = await _operation_for_collection(
                    session,
                    collection,
                    command=command,
                )
                if operation is not None and await expire_operation_if_due(
                    session,
                    operation,
                    now=datetime.now(UTC),
                    collection=collection,
                ):
                    continue
                if operation is not None and operation.status != "delivered":
                    raise CommandStateRejected(
                        "operation delivery state is unavailable"
                    )
                if command.expires_at is None:
                    created_at = _as_utc(command.created_at)
                    if created_at is None:
                        raise CommandStateRejected("command timing is unavailable")
                    command.expires_at = created_at + timedelta(minutes=15)
                    await session.flush()
                return _command_payload(
                    command,
                    collection,
                    capability,
                    operation,
                )
            continue
        if operation is not None and await expire_operation_if_due(
            session,
            operation,
            now=datetime.now(UTC),
            collection=collection,
        ):
            continue
        if operation is not None and operation.status != "queued":
            raise CommandStateRejected("operation is not queued for delivery")
        deadline_at = (
            operation.deadline_at
            if operation is not None
            else collection.expires_at or now + timedelta(minutes=15)
        )
        command = Command(
            id=uuid4(),
            created_at=now,
            command_identifier=f"ctx-{collection.id.hex}",
            device_id=device_id,
            command_kind=capability,
            status="delivered",
            expires_at=deadline_at,
        )
        session.add(command)
        await session.flush()
        await link_collection_command(session, collection.id, command.id)
        collection.status = "delivered"
        if operation is not None:
            operation.command_id = command.id
            operation.status = "delivered"
        session.add(
            CommandDelivery(
                id=uuid4(),
                command_id=command.id,
                device_session_id=None,
                delivery_identifier=f"delivery-{command.id.hex}",
                status="delivered",
                acknowledged_at=None,
            )
        )
        return _command_payload(command, collection, capability, operation)
    return None


class CommandService:
    def __init__(self, session_provider: SessionProvider) -> None:
        self._session_provider = session_provider

    async def deliver_next(
        self,
        device_id: UUID,
        session_id: UUID,
        send: SendCommand,
        *,
        allowed_capabilities: AbstractSet[str] | None = None,
    ) -> bool:
        """Commit one delivery before exposing it to the network callback."""
        async with self._session_provider() as session:
            try:
                payload = await next_pending_command(
                    session,
                    device_id,
                    allowed_capabilities,
                    transport="gateway_wss",
                )
                if payload is None:
                    await session.commit()
                    return False
                delivery = await session.scalar(
                    select(CommandDelivery)
                    .where(CommandDelivery.command_id == payload.command_id)
                    .with_for_update()
                )
                if delivery is None:
                    raise CommandStateRejected("command delivery is unavailable")
                gateway_session = await session.scalar(
                    select(DeviceSession).where(
                        DeviceSession.id == session_id,
                        DeviceSession.device_id == device_id,
                        DeviceSession.closed_at.is_(None),
                    )
                )
                if gateway_session is None:
                    raise CommandStateRejected("gateway session is unavailable")
                delivery.device_session_id = session_id
                await session.commit()
            except Exception:
                await session.rollback()
                raise

        envelope = CommandEnvelopeV1(
            schema_version="gateway_ws_envelope_v1",
            kind="command",
            sequence=1,
            payload=payload,
        )
        sent = send(envelope)
        if inspect.isawaitable(sent):
            await sent
        return True

    async def record_ack(
        self,
        *,
        device_id: UUID,
        session_id: UUID,
        acknowledgement: AgentCommandAckV1,
    ) -> None:
        if acknowledgement.device_id != device_id:
            raise CommandStateRejected("acknowledgement device does not match session")
        if acknowledgement.status not in {"acknowledged", "running"}:
            raise CommandStateRejected("acknowledgement status is not actionable")
        async with self._session_provider() as session:
            try:
                gateway_session = await session.scalar(
                    select(DeviceSession)
                    .where(
                        DeviceSession.id == session_id,
                        DeviceSession.device_id == device_id,
                        DeviceSession.closed_at.is_(None),
                    )
                    .with_for_update()
                )
                command = await session.scalar(
                    select(Command)
                    .where(
                        Command.id == acknowledgement.command_id,
                        Command.device_id == device_id,
                    )
                    .with_for_update()
                )
                if gateway_session is None or command is None:
                    raise CommandStateRejected("command is unavailable")
                delivery = await session.scalar(
                    select(CommandDelivery)
                    .where(CommandDelivery.command_id == command.id)
                    .with_for_update()
                )
                if delivery is None or delivery.device_session_id != session_id:
                    raise CommandStateRejected("command delivery is unavailable")
                collection, operation = await resolve_command_context_relation(
                    session,
                    command,
                )
                if command.status in _TERMINAL_STATUSES:
                    if operation is not None and operation.status != command.status:
                        raise CommandStateRejected(
                            "operation terminal state is unavailable"
                        )
                    await session.rollback()
                    return
                if command.status not in {"delivered", "acknowledged", "running"}:
                    raise CommandStateRejected("command is unavailable")
                if operation is not None and operation.status not in {
                    "delivered",
                    "acknowledged",
                    "running",
                }:
                    raise CommandStateRejected("operation is unavailable")
                if command.status != "running" or acknowledgement.status == "running":
                    command.status = acknowledgement.status
                    delivery.status = acknowledgement.status
                if operation is not None and (
                    operation.status != "running"
                    or acknowledgement.status == "running"
                ):
                    operation.status = acknowledgement.status
                if delivery.acknowledged_at is None:
                    delivery.acknowledged_at = acknowledgement.acknowledged_at
                if collection is not None:
                    collection.status = "collecting"
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def record_result(
        self,
        *,
        device_id: UUID,
        device_instance_id: UUID,
        session_id: UUID,
        result_sequence: int,
        result: AgentResultV1,
    ) -> ResultAckEnvelopeV1:
        if result_sequence < 0:
            raise CommandStateRejected("result sequence must be non-negative")
        if result.device_id != device_id or result.status not in _TERMINAL_STATUSES:
            raise CommandStateRejected("terminal result does not match session")
        payload_digest = result_payload_digest(result)
        async with self._session_provider() as session:
            try:
                gateway_session = await session.scalar(
                    select(DeviceSession)
                    .where(
                        DeviceSession.id == session_id,
                        DeviceSession.device_id == device_id,
                        DeviceSession.device_instance_id == device_instance_id,
                        DeviceSession.closed_at.is_(None),
                    )
                    .with_for_update()
                )
                instance = await session.scalar(
                    select(DeviceInstance)
                    .where(
                        DeviceInstance.id == device_instance_id,
                        DeviceInstance.device_id == device_id,
                    )
                    .with_for_update()
                )
                command = await session.scalar(
                    select(Command)
                    .where(Command.id == result.command_id, Command.device_id == device_id)
                    .with_for_update()
                )
                if gateway_session is None or instance is None or command is None:
                    raise CommandStateRejected("result ownership is unavailable")

                delivery = await session.scalar(
                    select(CommandDelivery)
                    .where(CommandDelivery.command_id == command.id)
                    .with_for_update()
                )
                collection, operation = await resolve_command_context_relation(
                    session,
                    command,
                )

                result_identifier = f"result-{command.id.hex}"
                stored = await session.scalar(
                    select(CommandResult)
                    .where(CommandResult.result_identifier == result_identifier)
                    .with_for_update()
                )
                if stored is None:
                    accepted_result = result
                    accepted_at: datetime | None = None
                    if operation is not None:
                        if (
                            delivery is None
                            or delivery.device_session_id != session_id
                            or command.status
                            not in {"delivered", "acknowledged", "running"}
                            or operation.status
                            not in {"delivered", "acknowledged", "running"}
                        ):
                            raise CommandStateRejected(
                                "operation result delivery is unavailable"
                            )
                        completed_at = _as_utc(result.completed_at)
                        created_at = _as_utc(operation.created_at)
                        deadline_at = _as_utc(operation.deadline_at)
                        accepted_at = datetime.now(UTC)
                        if (
                            completed_at is None
                            or created_at is None
                            or deadline_at is None
                            or completed_at < created_at
                            or completed_at > accepted_at + _MAX_AGENT_CLOCK_SKEW
                            or accepted_at >= deadline_at
                        ):
                            raise CommandStateRejected(
                                "operation result timing is unavailable"
                            )
                        accepted_result = _safe_operation_result(
                            operation,
                            result,
                        ).model_copy(update={"completed_at": accepted_at})
                    stored = CommandResult(
                        id=uuid4(),
                        command_id=command.id,
                        delivery_id=delivery.id if delivery is not None else None,
                        result_identifier=result_identifier,
                        status=result.status,
                        completed_at=accepted_result.completed_at,
                        result_sequence=result_sequence,
                        result_payload_digest=payload_digest,
                    )
                    session.add(stored)
                    await session.flush()
                    if command.command_kind.startswith("context."):
                        ingested_collection = await ingest_context_result(
                            session,
                            stored.id,
                            accepted_result,
                            now=accepted_at,
                        )
                        if operation is not None and (
                            ingested_collection.id != collection.id
                            or ingested_collection.operation_id != operation.id
                            or (
                                result.status == "succeeded"
                                and ingested_collection.status != "completed"
                            )
                            or (
                                result.status != "succeeded"
                                and ingested_collection.status != "failed"
                            )
                        ):
                            raise CommandStateRejected(
                                "operation context result is unavailable"
                            )
                    command.status = result.status
                    if delivery is not None:
                        delivery.status = result.status
                    if operation is not None:
                        operation.status = result.status
                        operation.completed_at = accepted_at
                        await append_operation_terminal_audit(
                            session,
                            operation,
                            occurred_at=accepted_at,
                        )
                else:
                    if operation is not None:
                        delivery_session = (
                            await session.scalar(
                                select(DeviceSession)
                                .where(
                                    DeviceSession.id == delivery.device_session_id,
                                    DeviceSession.device_id == device_id,
                                )
                                .with_for_update()
                            )
                            if delivery is not None
                            and delivery.device_session_id is not None
                            else None
                        )
                        if (
                            delivery is None
                            or delivery_session is None
                            or delivery_session.device_instance_id
                            != device_instance_id
                            or stored.command_id != command.id
                            or stored.delivery_id != delivery.id
                            or stored.result_sequence is None
                            or stored.result_sequence < 0
                            or stored.result_payload_digest != payload_digest
                            or stored.status != result.status
                            or command.status != result.status
                            or delivery.status != result.status
                            or operation.status != result.status
                            or operation.completed_at is None
                            or _as_utc(stored.completed_at)
                            != _as_utc(operation.completed_at)
                            or collection.command_result_id != stored.id
                        ):
                            raise CommandStateRejected(
                                "operation result replay conflicts with stored result"
                            )
                        if result.status == "succeeded":
                            snapshot = await session.scalar(
                                select(ContextSnapshot).where(
                                    ContextSnapshot.collection_id == collection.id
                                )
                            )
                            if (
                                collection.status != "completed"
                                or snapshot is None
                                or project_diagnostic_result(operation, snapshot) is None
                            ):
                                raise CommandStateRejected(
                                    "operation result replay is unavailable"
                                )
                        elif collection.status != "failed":
                            raise CommandStateRejected(
                                "operation failure replay is unavailable"
                            )
                    elif stored.result_sequence is None:
                        stored.result_sequence = result_sequence

                instance.last_result_sequence = max(
                    instance.last_result_sequence,
                    result_sequence,
                )
                await session.commit()
            except ContextError as error:
                await session.rollback()
                raise CommandStateRejected(
                    "context result conflicts with command"
                ) from error
            except Exception:
                await session.rollback()
                raise

        return ResultAckEnvelopeV1(
            schema_version="gateway_ws_envelope_v1",
            kind="result_ack",
            sequence=result_sequence,
            payload=ResultAckV1(
                schema_version="result_ack_v1",
                command_id=result.command_id,
                result_sequence=result_sequence,
            ),
        )


__all__ = [
    "CommandService",
    "CommandStateRejected",
    "next_pending_command",
    "resolve_command_context_relation",
    "result_payload_digest",
]
