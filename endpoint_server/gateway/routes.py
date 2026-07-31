"""HTTPS pull Gateway for fixed Endpoint Platform agent capabilities."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts import AgentCommandAckV1, AgentCommandV1, AgentResultV1
from endpoint_server.context.ingestion import ingest_context_result
from endpoint_server.context.models import ContextCollection
from endpoint_server.context.repository import link_collection_command
from endpoint_server.db.models import Command, CommandDelivery, CommandResult
from endpoint_server.updates.agent_routes import _authenticate_device


router = APIRouter(prefix="/agent/v1/gateway", tags=["agent-gateway"])
_CAPABILITIES = {
    "baseline_v1": "context.baseline.collect",
    "health_v1": "context.health.collect",
    "network_v1": "context.network.collect",
    "diagnostic_v1": "context.diagnostic.collect",
}


def _unavailable() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Gateway command unavailable")


def _command_payload(
    command: Command, collection: ContextCollection, capability: str, now: datetime
) -> AgentCommandV1:
    return AgentCommandV1(
        schema_version="agent_command_v1",
        command_id=command.id,
        device_id=command.device_id,
        capability=capability,
        parameters={},
        requested_by_service=collection.requested_by,
        idempotency_key=f"context-{collection.id.hex}",
        created_at=now,
        deadline_at=collection.expires_at or now + timedelta(minutes=15),
    )


async def _next_pending_command(
    session: AsyncSession, device_id: UUID
) -> AgentCommandV1 | None:
    """Return a prior unacknowledged delivery before minting a new command."""
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
        if capability is None:
            continue
        if collection.command_id is not None:
            command = await session.scalar(
                select(Command)
                .where(Command.id == collection.command_id, Command.device_id == device_id)
                .with_for_update()
            )
            if command is not None and command.status == "delivered":
                return _command_payload(command, collection, capability, now)
            continue
        command = Command(
            id=uuid4(),
            command_identifier=f"ctx-{collection.id.hex}",
            device_id=device_id,
            command_kind=capability,
            status="delivered",
            expires_at=collection.expires_at,
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
        return _command_payload(command, collection, capability, now)
    return None


@router.get("/commands/next", response_model=AgentCommandV1, responses={204: {"description": "No command"}})
async def next_command(request: Request) -> AgentCommandV1 | Response:
    """Deliver at most one fixed-capability collection command to its device."""
    async with request.app.state.session_provider() as session:
        try:
            principal = await _authenticate_device(session, request)
            command = await _next_pending_command(session, principal.device.id)
            await session.commit()
            return command or Response(status_code=status.HTTP_204_NO_CONTENT)
        except HTTPException:
            await session.rollback()
            raise
        except Exception:
            await session.rollback()
            raise


@router.post("/commands/{command_id}/ack", status_code=status.HTTP_204_NO_CONTENT, response_class=Response, response_model=None)
async def acknowledge(command_id: UUID, body: AgentCommandAckV1, request: Request) -> None:
    async with request.app.state.session_provider() as session:
        try:
            principal = await _authenticate_device(session, request)
            command = await session.scalar(select(Command).where(Command.id == command_id, Command.device_id == principal.device.id).with_for_update())
            if (
                command is None
                or body.command_id != command.id
                or body.device_id != principal.device.id
                or body.status != "acknowledged"
            ):
                raise _unavailable()
            command.status = body.status
            collection = await session.scalar(
                select(ContextCollection)
                .where(ContextCollection.command_id == command.id)
                .with_for_update()
            )
            if collection is not None:
                collection.status = "collecting"
            delivery = await session.scalar(
                select(CommandDelivery)
                .where(CommandDelivery.command_id == command.id)
                .with_for_update()
            )
            if delivery is not None:
                delivery.status = body.status
                delivery.acknowledged_at = body.acknowledged_at
            await session.commit()
        except HTTPException:
            await session.rollback()
            raise
        except Exception:
            await session.rollback()
            raise


@router.post("/commands/{command_id}/results", status_code=status.HTTP_204_NO_CONTENT, response_class=Response, response_model=None)
async def submit_result(command_id: UUID, body: AgentResultV1, request: Request) -> None:
    async with request.app.state.session_provider() as session:
        try:
            principal = await _authenticate_device(session, request)
            command = await session.scalar(select(Command).where(Command.id == command_id, Command.device_id == principal.device.id).with_for_update())
            if command is None or body.command_id != command.id or body.device_id != principal.device.id:
                raise _unavailable()
            result_identifier = f"result-{command.id.hex}"
            result = await session.scalar(
                select(CommandResult)
                .where(CommandResult.result_identifier == result_identifier)
                .with_for_update()
            )
            if result is None:
                result = CommandResult(id=uuid4(), command_id=command.id, delivery_id=None,
                    result_identifier=result_identifier, status=body.status, completed_at=body.completed_at)
                session.add(result)
                await session.flush()
                await ingest_context_result(session, result.id, body)
                command.status = body.status
            elif result.command_id != command.id:
                raise _unavailable()
            await session.commit()
        except HTTPException:
            await session.rollback()
            raise
        except Exception:
            await session.rollback()
            raise
