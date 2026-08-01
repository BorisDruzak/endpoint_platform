"""Durable server-observed Gateway session and heartbeat presence."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts import AgentHeartbeatV1, AgentHelloV1
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import Device, DeviceInstance, DeviceSession
from endpoint_server.db.session import SessionProvider


_PRESENCE_LIFETIME = timedelta(seconds=90)


class PresenceRejected(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class GatewayPresence:
    session_id: UUID
    device_instance_id: UUID


def _utc(value: datetime | None = None) -> datetime:
    timestamp = value or datetime.now(UTC)
    if timestamp.tzinfo is None:
        raise ValueError("presence timestamp must be timezone-aware")
    return timestamp.astimezone(UTC)


class PresenceService:
    def __init__(self, session_provider: SessionProvider) -> None:
        self._session_provider = session_provider

    async def open_session(
        self,
        *,
        device_id: UUID,
        hello: AgentHelloV1,
        source_address: str,
        observed_at: datetime | None = None,
    ) -> GatewayPresence:
        if hello.device_id != device_id:
            raise PresenceRejected("agent hello device does not match credential")
        try:
            canonical_source = str(ipaddress.ip_address(source_address))
        except ValueError as error:
            raise PresenceRejected("observed source address is invalid") from error
        now = _utc(observed_at)
        async with self._session_provider() as session:
            try:
                device = await session.scalar(
                    select(Device)
                    .where(Device.id == device_id, Device.retired_at.is_(None))
                    .with_for_update()
                )
                if device is None:
                    raise PresenceRejected("gateway device is unavailable")
                instance = await session.scalar(
                    select(DeviceInstance)
                    .where(
                        DeviceInstance.device_id == device_id,
                        DeviceInstance.instance_identifier
                        == str(hello.agent_instance_id),
                    )
                    .with_for_update()
                )
                if instance is None:
                    instance = DeviceInstance(
                        id=uuid4(),
                        device_id=device_id,
                        instance_identifier=str(hello.agent_instance_id),
                        agent_version=hello.agent_version,
                        last_seen_at=now,
                        last_result_sequence=0,
                    )
                    session.add(instance)
                    await session.flush()
                else:
                    instance.agent_version = hello.agent_version
                    instance.last_seen_at = now

                active_sessions = (
                    await session.scalars(
                        select(DeviceSession)
                        .where(
                            DeviceSession.device_id == device_id,
                            DeviceSession.closed_at.is_(None),
                        )
                        .order_by(DeviceSession.created_at, DeviceSession.id)
                        .with_for_update()
                    )
                ).all()
                for active in active_sessions:
                    active.closed_at = now
                    await self._audit(
                        session,
                        device_id=device_id,
                        session_id=active.id,
                        action="gateway.session_replaced",
                        details={"replacement": "new_authenticated_session"},
                        occurred_at=now,
                    )

                gateway_session = DeviceSession(
                    id=uuid4(),
                    device_id=device_id,
                    device_instance_id=instance.id,
                    session_identifier=f"gateway-{uuid4().hex}",
                    expires_at=now + _PRESENCE_LIFETIME,
                    closed_at=None,
                    last_seen_at=now,
                    source_address=canonical_source,
                )
                session.add(gateway_session)
                await self._audit(
                    session,
                    device_id=device_id,
                    session_id=gateway_session.id,
                    action="gateway.session_connected",
                    details={"source_address": canonical_source},
                    occurred_at=now,
                )
                await session.commit()
                return GatewayPresence(
                    session_id=gateway_session.id,
                    device_instance_id=instance.id,
                )
            except Exception:
                await session.rollback()
                raise

    async def record_heartbeat(
        self,
        *,
        device_id: UUID,
        session_id: UUID,
        heartbeat: AgentHeartbeatV1,
        observed_at: datetime | None = None,
    ) -> None:
        if heartbeat.device_id != device_id:
            raise PresenceRejected("heartbeat device does not match session")
        now = _utc(observed_at)
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
                if gateway_session is None:
                    raise PresenceRejected("gateway session is not active")
                instance = await session.scalar(
                    select(DeviceInstance)
                    .where(
                        DeviceInstance.id == gateway_session.device_instance_id,
                        DeviceInstance.device_id == device_id,
                    )
                    .with_for_update()
                )
                if instance is None:
                    raise PresenceRejected("gateway device instance is unavailable")
                gateway_session.last_seen_at = now
                gateway_session.expires_at = now + _PRESENCE_LIFETIME
                instance.last_seen_at = now
                instance.agent_version = heartbeat.agent_version
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def close_session(
        self,
        *,
        device_id: UUID,
        session_id: UUID,
        reason: str,
        observed_at: datetime | None = None,
    ) -> None:
        now = _utc(observed_at)
        async with self._session_provider() as session:
            try:
                gateway_session = await session.scalar(
                    select(DeviceSession)
                    .where(
                        DeviceSession.id == session_id,
                        DeviceSession.device_id == device_id,
                    )
                    .with_for_update()
                )
                if gateway_session is None or gateway_session.closed_at is not None:
                    await session.rollback()
                    return
                gateway_session.closed_at = now
                await self._audit(
                    session,
                    device_id=device_id,
                    session_id=session_id,
                    action="gateway.session_closed",
                    details={"reason": reason[:64]},
                    occurred_at=now,
                )
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    @staticmethod
    async def _audit(
        session: AsyncSession,
        *,
        device_id: UUID,
        session_id: UUID,
        action: str,
        details: dict[str, object],
        occurred_at: datetime,
    ) -> None:
        await append_audit_event(
            session,
            actor_kind="device",
            actor_identifier=str(device_id),
            action=action,
            object_kind="device_session",
            object_identifier=str(session_id),
            request_id=f"gateway-{session_id.hex}",
            details=details,
            occurred_at=occurred_at,
        )


__all__ = ["GatewayPresence", "PresenceRejected", "PresenceService"]
