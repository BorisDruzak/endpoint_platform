"""Bounded, fixed-profile periodic Device Context requests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_server.db.models import Device

from .models import ContextCollection
from .repository import request_collection_outcome


@dataclass(frozen=True, slots=True)
class ContextScheduleRule:
    """One server-owned periodic profile rule."""

    profile: str
    interval: timedelta


SCHEDULE_RULES: tuple[ContextScheduleRule, ...] = (
    ContextScheduleRule("baseline_v1", timedelta(hours=24)),
    ContextScheduleRule("health_v1", timedelta(minutes=5)),
    ContextScheduleRule("network_v1", timedelta(minutes=15)),
)
"""The complete periodic allowlist; diagnostic_v1 is deliberately absent."""

_ACTIVE_STATUSES = frozenset(
    {"requested", "queued", "delivered", "collecting", "result_received", "validated"}
)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        # SQLite's DateTime storage drops tzinfo. All writes in this ownership
        # zone are UTC, so restore it only at this persistence boundary.
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _now(value: datetime | None) -> datetime:
    timestamp = value or datetime.now(UTC)
    if timestamp.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return timestamp.astimezone(UTC)


async def _advisory_lock(session: AsyncSession, key: str) -> None:
    """Serialize an absent active row on PostgreSQL without weakening SQLite tests."""
    if session.get_bind().dialect.name == "postgresql":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": key},
        )


async def _expire_overdue_scheduled_collections(
    session: AsyncSession, *, now: datetime
) -> None:
    """Release bounded periodic work that could not reach an offline device."""
    overdue = (await session.scalars(
        select(ContextCollection)
        .where(
            ContextCollection.requested_by == "scheduler",
            ContextCollection.status.in_(_ACTIVE_STATUSES),
            ContextCollection.expires_at.is_not(None),
            ContextCollection.expires_at <= now,
        )
        .with_for_update(skip_locked=True)
    )).all()
    for collection in overdue:
        collection.status = "expired"
        collection.failed_at = now
        collection.failure_code = "schedule_expired"


async def schedule_due_collections(
    session: AsyncSession,
    *,
    now: datetime | None = None,
) -> int:
    """Create at most one active fixed-profile request for every active device.

    A device/profile advisory lock protects the no-row case that a normal row
    lock cannot cover.  Each request gets an interval-bounded expiry, so an
    offline agent cannot leave the periodic scheduler blocked indefinitely.
    """
    scheduled_at = _now(now)
    await _expire_overdue_scheduled_collections(session, now=scheduled_at)
    devices = (await session.scalars(
        select(Device).where(Device.retired_at.is_(None)).order_by(Device.id)
    )).all()
    created = 0
    for device in devices:
        for rule in SCHEDULE_RULES:
            await _advisory_lock(
                session, f"context.schedule:{device.id}:{rule.profile}"
            )
            active = await session.scalar(
                select(ContextCollection)
                .where(
                    ContextCollection.device_id == device.id,
                    ContextCollection.profile == rule.profile,
                    ContextCollection.status.in_(_ACTIVE_STATUSES),
                )
                .order_by(ContextCollection.requested_at, ContextCollection.id)
                .with_for_update(skip_locked=True)
            )
            if active is not None:
                continue
            latest = await session.scalar(
                select(ContextCollection)
                .where(
                    ContextCollection.device_id == device.id,
                    ContextCollection.profile == rule.profile,
                )
                .order_by(ContextCollection.requested_at.desc(), ContextCollection.id.desc())
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if latest is not None and scheduled_at - _utc(latest.requested_at) < rule.interval:
                continue
            bucket = int(scheduled_at.timestamp() // rule.interval.total_seconds())
            collection, inserted = await request_collection_outcome(
                session,
                device.id,
                rule.profile,
                "scheduler",
                f"scheduler:{rule.profile}:{bucket}",
                now=scheduled_at,
            )
            if inserted:
                collection.expires_at = scheduled_at + rule.interval
                created += 1
    await session.flush()
    return created


__all__ = ["ContextScheduleRule", "SCHEDULE_RULES", "schedule_due_collections"]
