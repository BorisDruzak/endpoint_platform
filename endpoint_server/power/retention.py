from datetime import UTC, datetime, timedelta
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from endpoint_server.context.models import DeviceEvent


async def retain_power_events(
    session: AsyncSession, *, now: datetime | None = None, limit: int = 100
) -> int:
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
    if ids:
        await session.execute(delete(DeviceEvent).where(DeviceEvent.id.in_(ids)))
    return len(ids)
