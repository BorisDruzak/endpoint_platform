"""Bounded, fixed-profile periodic Device Context requests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import case, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_server.db.models import Device

from .models import ContextCollection
from .repository import request_collection_outcome


@dataclass(frozen=True, slots=True)
class ContextScheduleRule:
    """One server-owned periodic profile rule."""

    profile: str
    capability: str
    interval: timedelta


@dataclass(frozen=True, slots=True)
class ContextScheduleBatch:
    created: int
    oldest_due_age_seconds: float
    next_device_id: UUID | None = None


SCHEDULE_RULES: tuple[ContextScheduleRule, ...] = (
    ContextScheduleRule("baseline_v1", "context.baseline.collect", timedelta(hours=24)),
    ContextScheduleRule("health_v1", "context.health.collect", timedelta(minutes=5)),
    ContextScheduleRule("network_v1", "context.network.collect", timedelta(minutes=15)),
    ContextScheduleRule("inventory_v1", "context.inventory.collect", timedelta(hours=24)),
    ContextScheduleRule("session_v1", "context.session.collect", timedelta(minutes=5)),
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
    session: AsyncSession, *, now: datetime, device_id
) -> None:
    """Release bounded periodic work that could not reach an offline device."""
    overdue = (await session.scalars(
        select(ContextCollection)
        .where(
            ContextCollection.requested_by == "scheduler",
            ContextCollection.device_id == device_id,
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


async def _schedule_history(
    session: AsyncSession, device_id: UUID, profile: str,
) -> tuple[bool, datetime | None]:
    history = select(ContextCollection.requested_at).where(
        ContextCollection.device_id == device_id,
        ContextCollection.profile == profile,
    )
    active = (
        history.where(ContextCollection.status.in_(_ACTIVE_STATUSES))
        .order_by(ContextCollection.requested_at, ContextCollection.id)
        .limit(1)
        .with_for_update(skip_locked=True)
        .cte()
    )
    has_active = select(active.c.requested_at).exists()
    latest = (
        history.order_by(ContextCollection.requested_at.desc(), ContextCollection.id.desc())
        .limit(1)
        .with_for_update(skip_locked=True)
        .scalar_subquery()
    )
    # Use the same active probe for both outputs and only read history if it is empty.
    found_active, latest_requested_at = (
        await session.execute(select(has_active, case((has_active, None), else_=latest)))
    ).one()
    return found_active, latest_requested_at


async def schedule_due_collections(
    session: AsyncSession,
    *,
    now: datetime | None = None,
) -> int:
    """Return the count of newly scheduled collections."""
    return (await schedule_due_collections_with_backlog(session, now=now)).created


async def schedule_due_collections_with_backlog(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    after_device_id: UUID | None = None,
    page_size: int | None = None,
) -> ContextScheduleBatch:
    """Create at most one active request per fixed profile for the selected devices.

    A device/profile advisory lock protects the no-row case that a normal row
    lock cannot cover.  Each request gets an interval-bounded expiry, so an
    offline agent cannot leave the periodic scheduler blocked indefinitely.
    """
    if page_size is not None and page_size < 1:
        raise ValueError("context schedule page size must be positive")
    scheduled_at = _now(now)
    candidate_ids = select(Device.id).where(Device.retired_at.is_(None)).order_by(Device.id)
    if after_device_id is not None:
        candidate_ids = candidate_ids.where(Device.id > after_device_id)
    if page_size is not None:
        candidate_ids = candidate_ids.limit(page_size + 1)
    device_ids = (await session.scalars(candidate_ids)).all()
    next_device_id = None
    if page_size is not None and len(device_ids) > page_size:
        device_ids = device_ids[:page_size]
        next_device_id = device_ids[-1]
    created = 0
    oldest_due_age = 0.0
    for device_id in device_ids:
        from endpoint_server.installation_lifecycle.service import removed
        device = await session.scalar(
            select(Device)
            .where(Device.id == device_id, Device.retired_at.is_(None))
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if device is None:
            continue
        await _expire_overdue_scheduled_collections(session, now=scheduled_at, device_id=device.id)
        if await removed(session, device.id):
            continue
        profiles = device.scheduled_context_profiles
        for rule in SCHEDULE_RULES:
            if profiles is not None and rule.profile not in profiles:
                continue
            await _advisory_lock(
                session, f"context.schedule:{device.id}:{rule.profile}"
            )
            active, last_requested_at = await _schedule_history(session, device.id, rule.profile)
            if active:
                continue
            overdue = (
                scheduled_at - _utc(last_requested_at) - rule.interval
                if last_requested_at is not None else scheduled_at - _utc(device.created_at)
            )
            if last_requested_at is not None and overdue < timedelta(0):
                continue
            bucket = int(scheduled_at.timestamp() // rule.interval.total_seconds())
            _, inserted = await request_collection_outcome(
                session,
                device.id,
                rule.profile,
                "scheduler",
                f"scheduler:{rule.profile}:{bucket}",
                now=scheduled_at,
                expires_at=scheduled_at + rule.interval,
            )
            if inserted:
                created += 1
                oldest_due_age = max(oldest_due_age, overdue.total_seconds())
    await session.flush()
    return ContextScheduleBatch(created, oldest_due_age, next_device_id)


__all__ = ["ContextScheduleRule", "SCHEDULE_RULES", "schedule_due_collections"]
