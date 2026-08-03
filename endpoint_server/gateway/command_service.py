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

from endpoint_contracts import AgentCommandAckV1, AgentResultV1
from endpoint_contracts.gateway_ws import (
    CommandEnvelopeV1,
    GatewayCommandV1,
    ResultAckEnvelopeV1,
    ResultAckV1,
)
from endpoint_server.context.ingestion import ingest_context_result
from endpoint_server.context.models import ContextCollection
from endpoint_server.context.repository import link_collection_command
from endpoint_server.context.service import ContextError
from endpoint_server.db.models import (
    Command,
    CommandDelivery,
    CommandResult,
    DeviceInstance,
    DeviceSession,
)
from endpoint_server.db.session import SessionProvider

SendCommand = Callable[[CommandEnvelopeV1], Awaitable[None] | None]
_TERMINAL_STATUSES = frozenset({"succeeded", "failed", "canceled", "expired"})
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
) -> GatewayCommandV1:
    created_at = _as_utc(command.created_at)
    deadline_at = _as_utc(command.expires_at)
    if created_at is None or deadline_at is None:
        raise CommandStateRejected("command timing is unavailable")
    return GatewayCommandV1(
        schema_version="agent_command_v1",
        command_id=command.id,
        device_id=command.device_id,
        capability=capability,
        parameters={},
        requested_by_service=collection.requested_by,
        idempotency_key=f"context-{collection.id.hex}",
        created_at=created_at,
        deadline_at=deadline_at,
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


async def next_pending_command(
    session,
    device_id: UUID,
    allowed_capabilities: AbstractSet[str] | None = None,
) -> GatewayCommandV1 | None:
    """Replay only unacknowledged deliveries before creating a new command."""
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
        capability = _CAPABILITIES.get(collection.profile)
        if capability is None or (
            allowed_capabilities is not None
            and capability not in allowed_capabilities
        ):
            continue
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
                if command.expires_at is None:
                    created_at = _as_utc(command.created_at)
                    if created_at is None:
                        raise CommandStateRejected("command timing is unavailable")
                    command.expires_at = created_at + timedelta(minutes=15)
                    await session.flush()
                return _command_payload(command, collection, capability)
            continue
        deadline_at = collection.expires_at or now + timedelta(minutes=15)
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
        return _command_payload(command, collection, capability)
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
                )
                if payload is None:
                    await session.rollback()
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
                if gateway_session is None or command is None or command.status not in {
                    "delivered",
                    "acknowledged",
                    "running",
                }:
                    raise CommandStateRejected("command is unavailable")
                delivery = await session.scalar(
                    select(CommandDelivery)
                    .where(CommandDelivery.command_id == command.id)
                    .with_for_update()
                )
                if delivery is None or delivery.device_session_id != session_id:
                    raise CommandStateRejected("command delivery is unavailable")
                if command.status != "running" or acknowledgement.status == "running":
                    command.status = acknowledgement.status
                    delivery.status = acknowledgement.status
                if delivery.acknowledged_at is None:
                    delivery.acknowledged_at = acknowledgement.acknowledged_at
                collection = await session.scalar(
                    select(ContextCollection)
                    .where(ContextCollection.command_id == command.id)
                    .with_for_update()
                )
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

                result_identifier = f"result-{command.id.hex}"
                stored = await session.scalar(
                    select(CommandResult)
                    .where(CommandResult.result_identifier == result_identifier)
                    .with_for_update()
                )
                if stored is None:
                    delivery = await session.scalar(
                        select(CommandDelivery)
                        .where(CommandDelivery.command_id == command.id)
                        .with_for_update()
                    )
                    stored = CommandResult(
                        id=uuid4(),
                        command_id=command.id,
                        delivery_id=delivery.id if delivery is not None else None,
                        result_identifier=result_identifier,
                        status=result.status,
                        completed_at=result.completed_at,
                        result_sequence=result_sequence,
                        result_payload_digest=payload_digest,
                    )
                    session.add(stored)
                    await session.flush()
                    if command.command_kind.startswith("context."):
                        await ingest_context_result(session, stored.id, result)
                    command.status = result.status
                else:
                    if stored.result_payload_digest != payload_digest:
                        raise CommandStateRejected(
                            "result payload conflicts with stored result"
                        )
                    if stored.result_sequence is None:
                        stored.result_sequence = result_sequence
                    elif stored.result_sequence != result_sequence:
                        raise CommandStateRejected(
                            "result sequence conflicts with stored result"
                        )

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
    "result_payload_digest",
]
