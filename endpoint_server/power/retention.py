from datetime import UTC, datetime, timedelta
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from endpoint_server.context.models import DeviceEvent
from endpoint_server.db.retention import EventRetentionBatch


async def retain_power_events(
    session: AsyncSession, *, now: datetime | None = None, limit: int = 100
) -> int:
    return (await retain_power_events_with_backlog(session, now=now, limit=limit)).deleted


async def retain_power_events_with_backlog(
    session: AsyncSession, *, now: datetime | None = None, limit: int = 100,
) -> EventRetentionBatch:
    if not 1 <= limit <= 1000:
        raise ValueError("retention limit must be 1..1000")
    cutoff = (now or datetime.now(UTC)) - timedelta(days=30)
    ids = list(
        (
            await session.scalars(
                select(DeviceEvent.id)
                .where(
                    DeviceEvent.category == "power",
                    DeviceEvent.profile == "power_v1",
                    DeviceEvent.occurred_at < cutoff,
                )
                .order_by(DeviceEvent.occurred_at, DeviceEvent.id)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        ).all()
    )
    if not ids:
        return EventRetentionBatch(0, 0.0)
    deleted = await session.scalars(
        delete(DeviceEvent).where(DeviceEvent.id.in_(ids)).returning(DeviceEvent.occurred_at)
    )
    return EventRetentionBatch.from_deleted(list(deleted), cutoff=cutoff)
