"""Durable Endpoint runtime heartbeat ingestion and bounded service projection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select

from endpoint_contracts import AgentHeartbeatV1
from endpoint_server.db.models import DeviceInstance, DeviceSession
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
