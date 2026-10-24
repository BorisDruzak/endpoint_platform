"""Per-event savepoints and an outer commit before any durable disposition."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
import hashlib
import json
from uuid import UUID

from sqlalchemy import or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from endpoint_contracts.gateway_ws import PowerEventAckEnvelopeV1
from endpoint_contracts.power_events import (
    PowerEventV1,
    PowerEventBatchV1,
    PowerEventAckV1,
    PowerEventDispositionV1,
)
from endpoint_server.context.models import DeviceEvent
from endpoint_server.db.models import Device
from .models import PowerSourceState

POWER_RETENTION = timedelta(days=30)


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class PowerEventRejected(ValueError):
    pass


def _native_key(event: PowerEventV1) -> str:
    identity = [event.source, event.boot_id, event.native_record_id]
    return (
        "power:"
        + hashlib.sha256(
            json.dumps(identity, separators=(",", ":")).encode()
        ).hexdigest()
    )


def _stable(event: PowerEventV1):
    # Recovery may observe the same native record later; observation is not identity.
    return event.model_dump(mode="json", exclude={"event_identifier", "observed_at"})


async def _ingest_event(
    session: AsyncSession, device_id: UUID, event: PowerEventV1, when: datetime
):
    if utc(event.occurred_at) < when - POWER_RETENTION:
        raise PowerEventRejected("event_expired")
    if utc(event.occurred_at) > when + timedelta(minutes=5) or utc(
        event.observed_at
    ) > when + timedelta(minutes=5):
        raise PowerEventRejected("event_future")
    key = _native_key(event)
    existing = list(
        (
            await session.scalars(
                select(DeviceEvent).where(
                    DeviceEvent.device_id == device_id,
                    DeviceEvent.category == "power",
                    or_(
                        DeviceEvent.source_key == key,
                        DeviceEvent.event_identifier == str(event.event_identifier),
                    ),
                )
            )
        ).all()
    )
    for row in existing:
        original = PowerEventV1.model_validate(row.details["event"])
        if original.event_identifier != event.event_identifier or _stable(
            original
        ) != _stable(event):
            raise PowerEventRejected("event_conflict")
    if existing:
        return
    details = {
        "event": event.model_dump(mode="json", exclude_none=True),
        "received_at": when.isoformat(),
    }
    if len(json.dumps(details, ensure_ascii=True).encode()) > 2048:
        raise PowerEventRejected("event_metadata_too_large")
    session.add(
        DeviceEvent(
            device_id=device_id,
            event_identifier=str(event.event_identifier),
            event_kind=event.event_kind,
            category="power",
            profile="power_v1",
            occurred_at=event.occurred_at,
            source_key=key,
            summary_code=event.event_kind,
            details=details,
        )
    )
    await session.flush()


async def ingest_gateway_power_events(
    session: AsyncSession,
    device_id: UUID,
    batch: PowerEventBatchV1,
    *,
    received_at: datetime | None = None,
) -> PowerEventAckV1:
    """Stage exact dispositions; caller owns outer transaction and must commit."""
    when = utc(received_at or datetime.now(UTC))
    # Serialize per-device identity checks and the current source row on PostgreSQL.
    await session.scalar(
        select(Device.id).where(Device.id == device_id).with_for_update()
    )
    status = batch.source_status
    if when - POWER_RETENTION <= utc(status.reported_at) <= when + timedelta(minutes=5):
        state = await session.scalar(
            select(PowerSourceState).where(PowerSourceState.device_id == device_id)
        )
        if state is None:
            state = PowerSourceState(device_id=device_id)
            session.add(state)
        if state.reported_at is None or utc(status.reported_at) >= utc(
            state.reported_at
        ):
            for name in (
                "source",
                "availability",
                "reported_at",
                "coverage_started_at",
                "loss_count",
                "reset_count",
            ):
                setattr(state, name, getattr(status, name))
            state.received_at = when
        await session.flush()
    results = []
    for event in batch.events:
        try:
            async with session.begin_nested():
                await _ingest_event(session, device_id, event, when)
        except PowerEventRejected as error:
            results.append(
                PowerEventDispositionV1(
                    event_identifier=event.event_identifier,
                    disposition="rejected",
                    reason_code=str(error),
                )
            )
        else:
            results.append(
                PowerEventDispositionV1(
                    event_identifier=event.event_identifier,
                    disposition="accepted",
                    reason_code="persisted",
                )
            )
    return PowerEventAckV1(
        schema_version="power_event_ack_v1",
        batch_id=batch.batch_id,
        persisted_at=when,
        results=results,
    )


async def commit_and_ack_power_events(
    session_provider: async_sessionmaker[AsyncSession],
    device_id: UUID,
    batch: PowerEventBatchV1,
    *,
    sequence: int,
    send: Callable[[PowerEventAckEnvelopeV1], Awaitable[None]],
    received_at: datetime | None = None,
) -> None:
    async with session_provider() as session:
        if session.get_bind().dialect.name == "sqlite":
            await session.execute(text("BEGIN"))
        ack = await ingest_gateway_power_events(
            session, device_id, batch, received_at=received_at
        )
        await session.commit()
    await send(
        PowerEventAckEnvelopeV1(
            schema_version="gateway_ws_envelope_v1",
            kind="power_event_ack",
            sequence=sequence,
            payload=ack,
        )
    )
