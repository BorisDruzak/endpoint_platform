"""Durable Endpoint runtime heartbeat ingestion and bounded service projection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import select

from endpoint_contracts import (
    AgentHeartbeatV1,
    RuntimeDiagnosticTargetEnvelopeV1,
    RuntimeDiagnosticTargetNotFoundEnvelopeV1,
    RuntimeDiagnosticTargetV1,
)
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.scopes import (
    ServicePrincipal,
    require_helpdesk_diagnostic_target_read,
)
from endpoint_server.db.models import Device, DeviceInstance, DeviceSession
from endpoint_server.updates.agent_routes import _authenticate_device


router = APIRouter(tags=["runtime"])
RUNTIME_HEARTBEAT_TTL = timedelta(seconds=90)
_RUNTIME_INSTANCE_IDENTIFIER = "runtime-gateway"


def _invalid_device_heartbeat() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid device credential",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _validated_correlation_id(value: str | None) -> str:
    if (
        value is None
        or not value
        or len(value) > 128
        or not value.isascii()
        or any(not 32 <= ord(character) <= 126 for character in value)
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid X-Correlation-ID",
        )
    return value


def _rfc3339_timestamp(value: datetime | None) -> str | None:
    """Serialize a durable timestamp before it crosses the strict HTTP contract."""
    if value is None:
        return None
    normalized = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return normalized.astimezone(UTC).isoformat().replace("+00:00", "Z")


@router.post(
    "/agent/v1/runtime/heartbeat",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
async def record_runtime_heartbeat(body: AgentHeartbeatV1, request: Request) -> None:
    """Record a device-bearer-bound heartbeat using only server-observed time."""
    async with request.app.state.session_provider() as session:
        try:
            principal = await _authenticate_device(session, request)
            if body.device_id != principal.device.id:
                raise _invalid_device_heartbeat()
            observed_at = datetime.now(UTC)
            instance = await session.scalar(
                select(DeviceInstance)
                .where(
                    DeviceInstance.device_id == principal.device.id,
                    DeviceInstance.instance_identifier == _RUNTIME_INSTANCE_IDENTIFIER,
                )
                .with_for_update()
            )
            if instance is None:
                instance = DeviceInstance(
                    id=uuid4(),
                    device_id=principal.device.id,
                    instance_identifier=_RUNTIME_INSTANCE_IDENTIFIER,
                    agent_version=body.agent_version,
                    last_seen_at=observed_at,
                )
                session.add(instance)
                await session.flush()
            else:
                instance.agent_version = body.agent_version
                instance.last_seen_at = observed_at
            runtime_session = await session.scalar(
                select(DeviceSession)
                .where(
                    DeviceSession.device_instance_id == instance.id,
                    DeviceSession.closed_at.is_(None),
                )
                .order_by(DeviceSession.last_handshake_at.desc(), DeviceSession.id.desc())
                .limit(1)
                .with_for_update()
            )
            if runtime_session is None:
                runtime_session = DeviceSession(
                    id=uuid4(),
                    device_id=principal.device.id,
                    device_instance_id=instance.id,
                    session_identifier=f"runtime-{uuid4().hex}",
                    expires_at=observed_at + RUNTIME_HEARTBEAT_TTL,
                    last_handshake_at=observed_at,
                    closed_at=None,
                )
                session.add(runtime_session)
            else:
                runtime_session.last_handshake_at = observed_at
                runtime_session.expires_at = observed_at + RUNTIME_HEARTBEAT_TTL
            await session.commit()
        except HTTPException:
            await session.rollback()
            raise
        except Exception:
            await session.rollback()
            raise


@router.get(
    "/service/v1/runtime/devices/{device_ref}",
    response_model=RuntimeDiagnosticTargetEnvelopeV1,
    responses={404: {"model": RuntimeDiagnosticTargetNotFoundEnvelopeV1}},
)
async def read_runtime_diagnostic_target(
    device_ref: UUID,
    request: Request,
    principal: Annotated[
        ServicePrincipal, Depends(require_helpdesk_diagnostic_target_read)
    ],
    correlation_id: Annotated[str | None, Header(alias="X-Correlation-ID")] = None,
) -> JSONResponse:
    """Return only Endpoint-owned runtime state for one opaque device UUID."""
    correlation_id = _validated_correlation_id(correlation_id)
    async with request.app.state.session_provider() as session:
        try:
            device = await session.scalar(select(Device).where(Device.id == device_ref))
            if device is None:
                missing = RuntimeDiagnosticTargetNotFoundEnvelopeV1(
                    correlation_id=correlation_id,
                    data={
                        "status": "not_found",
                        "code": "endpoint_device_not_found",
                    },
                )
                await append_audit_event(
                    session,
                    actor_kind="service",
                    actor_identifier=str(principal.client.id),
                    action="runtime.diagnostic_target_not_found",
                    object_kind="device",
                    object_identifier=str(device_ref),
                    request_id=audit_request_id(request),
                    details={"device_ref": str(device_ref)},
                )
                await session.commit()
                return JSONResponse(
                    status_code=status.HTTP_404_NOT_FOUND,
                    content=missing.model_dump(mode="json"),
                    headers={"X-Correlation-ID": correlation_id},
                )
            instance = await session.scalar(
                select(DeviceInstance)
                .where(
                    DeviceInstance.device_id == device.id,
                    DeviceInstance.instance_identifier == _RUNTIME_INSTANCE_IDENTIFIER,
                )
                .order_by(DeviceInstance.last_seen_at.desc(), DeviceInstance.id.desc())
                .limit(1)
            )
            runtime_session = None
            if instance is not None:
                runtime_session = await session.scalar(
                    select(DeviceSession)
                    .where(DeviceSession.device_instance_id == instance.id)
                    .order_by(
                        DeviceSession.last_handshake_at.desc(), DeviceSession.id.desc()
                    )
                    .limit(1)
                )
            now = datetime.now(UTC)
            expires_at = runtime_session.expires_at if runtime_session is not None else None
            if expires_at is not None and expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            online = (
                runtime_session is not None
                and runtime_session.closed_at is None
                and expires_at is not None
                and expires_at > now
            )
            envelope = RuntimeDiagnosticTargetEnvelopeV1(
                schema_version="endpoint_runtime_v1",
                correlation_id=correlation_id,
                data=RuntimeDiagnosticTargetV1(
                    device_ref=device.id,
                    online=online,
                    connection_state="online" if online else "offline",
                    last_seen_at=_rfc3339_timestamp(
                        instance.last_seen_at if instance is not None else None
                    ),
                    last_handshake_at=_rfc3339_timestamp(
                        runtime_session.last_handshake_at if runtime_session is not None else None
                    ),
                    agent_version=instance.agent_version if instance is not None else None,
                ),
            )
            await append_audit_event(
                session,
                actor_kind="service",
                actor_identifier=str(principal.client.id),
                action="runtime.diagnostic_target_read",
                object_kind="device",
                object_identifier=str(device.id),
                request_id=audit_request_id(request),
                details={
                    "device_ref": str(device.id),
                    "online": online,
                    "connection_state": envelope.data.connection_state,
                },
            )
            await session.commit()
            return JSONResponse(
                content=envelope.model_dump(mode="json"),
                headers={"X-Correlation-ID": correlation_id},
            )
        except HTTPException:
            await session.rollback()
            raise
        except Exception:
            await session.rollback()
            raise
