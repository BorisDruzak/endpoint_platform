"""Power evidence never establishes hardware state or changes activity metrics."""

from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from endpoint_contracts.power_events import PowerEventV1, PowerSourceStatusV1
from endpoint_server.context.models import DeviceEvent
from .models import PowerSourceState


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _power_evidence_order():
    """Match project_power's entire max key before limiting either SQL reader."""
    return (
        DeviceEvent.occurred_at.desc(),
        DeviceEvent.event_kind.in_(("OS_STARTED", "OS_RESUMED")).desc(),
        (DeviceEvent.details["event"]["evidence"].as_string() != "transition").desc(),
        DeviceEvent.event_identifier.desc(),
        DeviceEvent.id.desc(),
    )


class PowerSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Literal["online", "unknown", "sleep", "shutdown"]
    online: bool
    last_seen_at: datetime | None
    source_status: PowerSourceStatusV1 | None
    source_fresh: bool
    history_available_from: datetime
    latest_event: PowerEventV1 | None


def project_power(
    *,
    online: bool,
    last_seen_at: datetime | None,
    source_status: PowerSourceStatusV1 | None,
    events: list[PowerEventV1],
    now: datetime | None = None,
) -> PowerSummary:
    when = utc(now or datetime.now(UTC))
    horizon = when - timedelta(days=30)
    facts = [e for e in events if horizon <= utc(e.occurred_at) <= when]
    # A tied startup/resume or request suppresses uncertain transition labels.
    latest = max(
        facts,
        key=lambda e: (
            utc(e.occurred_at),
            e.event_kind in {"OS_STARTED", "OS_RESUMED"},
            e.evidence != "transition",
            str(e.event_identifier),
        ),
        default=None,
    )
    fresh = bool(
        source_status
        and timedelta(0)
        <= when - utc(source_status.reported_at)
        <= timedelta(seconds=90)
    )
    status = "online" if online else "unknown"
    if (
        not online
        and latest
        and source_status
        and source_status.availability in {"READY", "DEGRADED"}
        and latest.evidence == "transition"
        and (last_seen_at is None or utc(last_seen_at) <= utc(latest.occurred_at))
    ):
        status = {"OS_SLEEP_STARTED": "sleep", "OS_SHUTDOWN_STARTED": "shutdown"}.get(
            latest.event_kind, "unknown"
        )
    start = (
        max(horizon, utc(source_status.coverage_started_at))
        if source_status and source_status.coverage_started_at
        else horizon
    )
    return PowerSummary(
        status=status,
        online=online,
        last_seen_at=last_seen_at,
        source_status=source_status,
        source_fresh=fresh,
        history_available_from=start,
        latest_event=latest,
    )


def source_projection(row: PowerSourceState | None) -> PowerSourceStatusV1 | None:
    if row is None:
        return None
    return PowerSourceStatusV1(
        schema_version="power_source_status_v1",
        source=row.source,
        availability=row.availability,
        reported_at=utc(row.reported_at),
        coverage_started_at=utc(row.coverage_started_at)
        if row.coverage_started_at
        else None,
        loss_count=row.loss_count,
        reset_count=row.reset_count,
    )


async def power_summary(
    session: AsyncSession,
    device_id: UUID,
    *,
    online: bool,
    last_seen_at: datetime | None,
    now: datetime | None = None,
) -> PowerSummary:
    when = utc(now or datetime.now(UTC))
    row = await session.scalar(
        select(PowerSourceState).where(PowerSourceState.device_id == device_id)
    )
    facts = list(
        (
            await session.scalars(
                select(DeviceEvent)
                .where(
                    DeviceEvent.device_id == device_id,
                    DeviceEvent.category == "power",
                    DeviceEvent.occurred_at >= when - timedelta(days=30),
                    DeviceEvent.occurred_at <= when,
                )
                .order_by(*_power_evidence_order())
                .limit(128)
            )
        ).all()
    )
    return project_power(
        online=online,
        last_seen_at=last_seen_at,
        source_status=source_projection(row),
        events=[PowerEventV1.model_validate(f.details["event"]) for f in facts],
        now=when,
    )


async def enrich_power_summaries(
    session: AsyncSession, data: list[dict], *, now: datetime | None = None
) -> None:
    """Two bounded queries per fleet page, independent of device count."""
    if not data:
        return
    when = utc(now or datetime.now(UTC))
    ids = [UUID(str(item["id"])) for item in data]
    sources = {
        row.device_id: source_projection(row)
        for row in (
            await session.scalars(
                select(PowerSourceState).where(PowerSourceState.device_id.in_(ids))
            )
        ).all()
    }
    ranked = (
        select(
            DeviceEvent.id.label("id"),
            func.row_number()
            .over(
                partition_by=DeviceEvent.device_id,
                order_by=_power_evidence_order(),
            )
            .label("rank"),
        )
        .where(
            DeviceEvent.device_id.in_(ids),
            DeviceEvent.category == "power",
            DeviceEvent.occurred_at >= when - timedelta(days=30),
            DeviceEvent.occurred_at <= when,
        )
        .subquery()
    )
    facts = {device_id: [] for device_id in ids}
    for row in (
        await session.scalars(
            select(DeviceEvent)
            .join(ranked, ranked.c.id == DeviceEvent.id)
            .where(ranked.c.rank <= 128)
        )
    ).all():
        facts[row.device_id].append(PowerEventV1.model_validate(row.details["event"]))
    for item, device_id in zip(data, ids):
        item["power"] = project_power(
            online=item["online"],
            last_seen_at=item["last_seen_at"],
            source_status=sources.get(device_id),
            events=facts[device_id],
            now=when,
        ).model_dump(mode="json")


async def power_timeline_markers(
    session: AsyncSession,
    device_ids: set[UUID],
    start: datetime,
    end: datetime,
    *,
    now: datetime | None = None,
) -> tuple[list[dict], bool]:
    if not device_ids:
        return [], False
    when = utc(now or datetime.now(UTC))
    rows = list(
        (
            await session.scalars(
                select(DeviceEvent)
                .where(
                    DeviceEvent.device_id.in_(device_ids),
                    DeviceEvent.category == "power",
                    DeviceEvent.profile == "power_v1",
                    DeviceEvent.occurred_at
                    >= max(utc(start), when - timedelta(days=30)),
                    DeviceEvent.occurred_at < end,
                )
                .order_by(DeviceEvent.occurred_at, DeviceEvent.id)
                .limit(2001)
            )
        ).all()
    )
    return [
        dict(
            device_id=str(row.device_id),
            event=PowerEventV1.model_validate(row.details["event"]),
        )
        for row in rows[:2000]
    ], len(rows) > 2000
