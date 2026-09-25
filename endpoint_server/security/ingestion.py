"""Persist validated SecurityEvent batches under the applied server policy."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from collections.abc import Awaitable, Callable
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_contracts.gateway_ws import SecurityEventAckEnvelopeV1
from endpoint_contracts.security_events import (
    AgentSecurityEventBatchV1,
    SecurityEventAckV1,
)
from endpoint_server.policy.models import PolicyDeviceState
from endpoint_server.policy.service import resolve_effective_policy
from endpoint_server.security.models import SecurityEvent


class SecurityEventRejected(ValueError):
    """Safe reject that does not include untrusted event metadata."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise SecurityEventRejected("security event time must be timezone aware")
    return value.astimezone(UTC)


def _stored_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _enabled(policy: EndpointPolicyV1, event_type: str) -> bool:
    mode = {
        "USB_DEVICE_CONNECTED": policy.dlp.usb_device_events,
        "USB_DEVICE_DISCONNECTED": policy.dlp.usb_device_events,
        "PRINT_JOB": policy.dlp.print_events,
        "BROWSER_UPLOAD": policy.dlp.browser_upload_events,
        "BROWSER_PASTE": policy.dlp.browser_paste_events,
    }[event_type]
    return mode == "audit"


def _same_event(
    existing: SecurityEvent, event: object, metadata: dict[str, object]
) -> bool:
    return (
        existing.event_type == event.event_type
        and existing.channel == event.channel
        and existing.severity == event.severity
        and _stored_utc(existing.occurred_at) == event.occurred_at
        and existing.user_login == event.user_login
        and existing.policy_id == event.policy_id
        and existing.policy_version == event.policy_version
        and existing.safe_metadata == metadata
    )


async def ingest_gateway_security_events(
    session: AsyncSession,
    device_id: UUID,
    batch: AgentSecurityEventBatchV1,
    *,
    received_at: datetime | None = None,
) -> SecurityEventAckV1:
    """Stage idempotent rows; caller must commit before sending returned ACK."""
    when = _utc(received_at or datetime.now(UTC))
    version = await resolve_effective_policy(session, device_id)
    state = await session.scalar(
        select(PolicyDeviceState).where(PolicyDeviceState.device_id == device_id)
    )
    if (
        version is None
        or state is None
        or state.status != "APPLIED"
        or state.policy_version_id != version.id
        or state.policy_digest != version.digest
    ):
        raise SecurityEventRejected("security event policy is not applied")
    try:
        policy = EndpointPolicyV1.model_validate(version.document)
    except ValidationError as error:
        raise SecurityEventRejected("security event policy is invalid") from error
    for event in batch.events:
        occurred = _utc(event.occurred_at)
        if (
            event.policy_id != policy.policy_id
            or event.policy_version != policy.policy_version
            or not _enabled(policy, event.event_type)
        ):
            raise SecurityEventRejected("security event is outside applied policy")
        if occurred < when - timedelta(hours=24) or occurred > when + timedelta(
            minutes=5
        ):
            raise SecurityEventRejected("security event time is outside live bounds")

    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert = pg_insert
    elif dialect == "sqlite":
        insert = sqlite_insert
    else:
        raise SecurityEventRejected("unsupported security event database")
    for event in batch.events:
        metadata = event.safe_metadata.model_dump(mode="json", exclude_none=True)
        statement = (
            insert(SecurityEvent)
            .values(
                id=uuid4(),
                event_identifier=event.event_identifier,
                device_id=device_id,
                event_type=event.event_type,
                channel=event.channel,
                severity=event.severity,
                occurred_at=event.occurred_at,
                received_at=when,
                user_login=event.user_login,
                policy_id=event.policy_id,
                policy_version=event.policy_version,
                safe_metadata=metadata,
                expires_at=when
                + timedelta(days=policy.event_retention.security_event_days),
            )
            .on_conflict_do_nothing(index_elements=["device_id", "event_identifier"])
        )
        await session.execute(statement)
        existing = await session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.device_id == device_id,
                SecurityEvent.event_identifier == event.event_identifier,
            )
        )
        if existing is None or not _same_event(existing, event, metadata):
            raise SecurityEventRejected(
                "security event identifier conflicts with persisted event"
            )
    await session.flush()
    return SecurityEventAckV1(
        schema_version="security_event_ack_v1",
        batch_id=batch.batch_id,
        event_identifiers=[event.event_identifier for event in batch.events],
        persisted_at=when,
    )


async def commit_and_ack_security_events(
    session_provider: async_sessionmaker[AsyncSession],
    device_id: UUID,
    batch: AgentSecurityEventBatchV1,
    *,
    sequence: int,
    send: Callable[[SecurityEventAckEnvelopeV1], Awaitable[None]],
    received_at: datetime | None = None,
) -> None:
    """Never emit a success ACK before the whole database transaction commits."""
    async with session_provider() as session:
        acknowledgement = await ingest_gateway_security_events(
            session, device_id, batch, received_at=received_at
        )
        await session.commit()
    await send(
        SecurityEventAckEnvelopeV1(
            schema_version="gateway_ws_envelope_v1",
            kind="security_event_ack",
            sequence=sequence,
            payload=acknowledgement,
        )
    )


__all__ = [
    "SecurityEventRejected",
    "commit_and_ack_security_events",
    "ingest_gateway_security_events",
]
