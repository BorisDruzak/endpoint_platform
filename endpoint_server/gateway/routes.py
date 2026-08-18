"""HTTPS pull Gateway for fixed Endpoint Platform agent capabilities."""

from __future__ import annotations

from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select

from endpoint_contracts import AgentCommandAckV1, AgentCommandV1, AgentResultV1
from endpoint_server.context.ingestion import ingest_context_result
from endpoint_server.db.models import Command, CommandDelivery, CommandResult
from endpoint_server.updates.agent_routes import _authenticate_device

from .command_service import (
    CommandStateRejected,
    next_pending_command,
    resolve_command_context_relation,
    result_payload_digest,
)


router = APIRouter(prefix="/agent/v1/gateway", tags=["agent-gateway"])


def _unavailable() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Gateway command unavailable")


@router.get("/commands/next", response_model=AgentCommandV1, responses={204: {"description": "No command"}})
async def next_command(request: Request) -> AgentCommandV1 | Response:
    """Deliver at most one fixed-capability collection command to its device."""
    async with request.app.state.session_provider() as session:
        try:
            principal = await _authenticate_device(session, request)
            command = await next_pending_command(session, principal.device.id)
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
            try:
                collection, operation = await resolve_command_context_relation(
                    session,
                    command,
                )
            except CommandStateRejected as error:
                raise _unavailable() from error
            if operation is not None:
                raise _unavailable()
            command.status = body.status
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
            try:
                _collection, operation = await resolve_command_context_relation(
                    session,
                    command,
                )
            except CommandStateRejected as error:
                raise _unavailable() from error
            if operation is not None:
                raise _unavailable()
            result_identifier = f"result-{command.id.hex}"
            result = await session.scalar(
                select(CommandResult)
                .where(CommandResult.result_identifier == result_identifier)
                .with_for_update()
            )
            payload_digest = result_payload_digest(body)
            if result is None:
                result = CommandResult(id=uuid4(), command_id=command.id, delivery_id=None,
                    result_identifier=result_identifier, status=body.status,
                    completed_at=body.completed_at,
                    result_payload_digest=payload_digest)
                session.add(result)
                await session.flush()
                await ingest_context_result(session, result.id, body)
                command.status = body.status
            elif (
                result.command_id != command.id
                or result.result_payload_digest != payload_digest
            ):
                raise _unavailable()
            await session.commit()
        except HTTPException:
            await session.rollback()
            raise
        except Exception:
            await session.rollback()
            raise
