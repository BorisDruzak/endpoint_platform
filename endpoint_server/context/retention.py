"""Bounded retention for immutable Device Context snapshots."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ContextCollection, ContextCurrent, ContextSnapshot
from .policy import CONTEXT_RETENTION_POLICIES, RAW_CONTEXT_TTL
from .service import ContextNotFound, ContextValidationError, require_uuid


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def _advisory_lock(session: AsyncSession, key: str) -> None:
    """Serialize a device/profile decision with current-pointer mutation."""
    if session.get_bind().dialect.name == "postgresql":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": key},
        )


async def pin_context_snapshot(
    session: AsyncSession,
    snapshot_id: UUID | str,
    *,
    pinned_at: datetime | None = None,
) -> ContextSnapshot:
    """Persist an explicit retention pin without exposing raw snapshot content."""
    checked_id = require_uuid(snapshot_id, "snapshot id")
    when = pinned_at or datetime.now(UTC)
    if when.tzinfo is None:
        raise ContextValidationError("pinned_at must be timezone-aware")
    observed = await session.scalar(
        select(ContextSnapshot)
        .where(ContextSnapshot.id == checked_id)
    )
    if observed is None:
        raise ContextNotFound("context snapshot was not found")
    await _advisory_lock(
        session, f"context.current:{observed.device_id}:{observed.profile}"
    )
    snapshot = await session.scalar(
        select(ContextSnapshot)
        .where(ContextSnapshot.id == checked_id)
        .with_for_update()
    )
    if snapshot is None:
        # A retention transaction may have completed before this operation
        # acquired its profile lock; never pin a stale in-memory row.
        raise ContextNotFound("context snapshot was not found")
    snapshot.pinned_at = when.astimezone(UTC)
    await session.flush()
    return snapshot


async def retain_context_snapshots(
    session: AsyncSession,
    *,
    limit: int = 100,
    now: datetime | None = None,
) -> int:
    """Delete one bounded batch according to profile, preserving current state."""
    if not 1 <= limit <= 100:
        raise ValueError("retention limit must be between 1 and 100")
    when = _utc(now or datetime.now(UTC))
    hot_profiles = tuple(profile for profile, policy in CONTEXT_RETENTION_POLICIES.items() if policy.mode == "hot")
    cutoff = when - CONTEXT_RETENTION_POLICIES["health_v1"].ttl
    hot_rows = (await session.execute(
        select(ContextSnapshot.id, ContextSnapshot.device_id, ContextSnapshot.profile)
        .where(ContextSnapshot.profile.in_(hot_profiles), ContextSnapshot.collected_at < cutoff,
               ContextSnapshot.pinned_at.is_(None))
        .order_by(ContextSnapshot.collected_at, ContextSnapshot.id).limit(limit * 4)
    )).all()
    ranked = select(
        ContextSnapshot.id.label("id"), ContextSnapshot.device_id.label("device_id"),
        ContextSnapshot.profile.label("profile"),
        func.row_number().over(
            partition_by=(ContextSnapshot.device_id, ContextSnapshot.profile),
            order_by=(ContextSnapshot.collected_at.desc(), ContextSnapshot.id.desc()),
        ).label("position"),
    ).where(ContextSnapshot.profile.in_(("baseline_v1", "inventory_v1"))).subquery()
    stable_rows = (await session.execute(
        select(ranked.c.id, ranked.c.device_id, ranked.c.profile)
        .join(ContextSnapshot, ContextSnapshot.id == ranked.c.id)
        .where(ranked.c.position > 2, ContextSnapshot.pinned_at.is_(None))
        .order_by(ContextSnapshot.collected_at, ContextSnapshot.id).limit(limit * 4)
    )).all()
    diagnostic_cutoff = when - CONTEXT_RETENTION_POLICIES["diagnostic_v1"].ttl
    diagnostic_rows = (await session.execute(
        select(ContextSnapshot.id, ContextSnapshot.device_id, ContextSnapshot.profile)
        .where(ContextSnapshot.profile == "diagnostic_v1", ContextSnapshot.collected_at < diagnostic_cutoff,
               ContextSnapshot.pinned_at.is_(None))
        .order_by(ContextSnapshot.collected_at, ContextSnapshot.id).limit(limit * 4)
    )).all()
    deleted = 0
    for snapshot_id, device_id, profile in (*hot_rows, *stable_rows, *diagnostic_rows):
        await _advisory_lock(session, f"context.current:{device_id}:{profile}")
        snapshot = await session.scalar(select(ContextSnapshot).where(ContextSnapshot.id == snapshot_id).with_for_update())
        if snapshot is None or snapshot.pinned_at is not None:
            continue
        current = await session.scalar(select(ContextCurrent).where(
            ContextCurrent.device_id == device_id, ContextCurrent.profile == profile,
        ).with_for_update())
        if current is not None and current.snapshot_id == snapshot_id and profile != "diagnostic_v1":
            continue
        if profile in {"baseline_v1", "inventory_v1"}:
            if current is not None:
                current_snapshot = await session.get(ContextSnapshot, current.snapshot_id)
                if current_snapshot is not None:
                    previous_id = await session.scalar(select(ContextSnapshot.id).where(
                        ContextSnapshot.device_id == device_id, ContextSnapshot.profile == profile,
                        (ContextSnapshot.collected_at < current_snapshot.collected_at) |
                        ((ContextSnapshot.collected_at == current_snapshot.collected_at) & (ContextSnapshot.id < current_snapshot.id)),
                    ).order_by(ContextSnapshot.collected_at.desc(), ContextSnapshot.id.desc()).limit(1))
                    if snapshot_id == previous_id:
                        continue
        elif _utc(snapshot.collected_at) >= when - CONTEXT_RETENTION_POLICIES[profile].ttl:
            continue
        if profile == "diagnostic_v1" and current is not None and current.snapshot_id == snapshot_id:
            await session.delete(current)
            await session.flush()
        await session.delete(snapshot)
        deleted += 1
        if deleted >= limit:
            break
    await session.flush()
    return deleted


async def cleanup_raw_context_payloads(
    session: AsyncSession, *, now: datetime | None = None, limit: int = 100,
) -> tuple[int, int]:
    """Scrub old transport JSON in separate bounded table batches."""
    if not 1 <= limit <= 1000:
        raise ValueError("cleanup limit must be between 1 and 1000")
    cutoff = _utc(now or datetime.now(UTC)) - RAW_CONTEXT_TTL
    collections = (await session.scalars(select(ContextCollection).where(
        ContextCollection.result_received_at < cutoff,
        ContextCollection.raw_result_payload.is_not(None),
    ).order_by(ContextCollection.result_received_at, ContextCollection.id).limit(limit).with_for_update(skip_locked=True))).all()
    for collection in collections:
        collection.raw_result_payload = None
    snapshots = (await session.scalars(select(ContextSnapshot)
        .join(ContextCollection, ContextCollection.id == ContextSnapshot.collection_id)
        .where(ContextCollection.result_received_at < cutoff, ContextSnapshot.raw_payload.is_not(None))
        .order_by(ContextCollection.result_received_at, ContextSnapshot.id)
        .limit(limit).with_for_update(skip_locked=True, of=ContextSnapshot))).all()
    for snapshot in snapshots:
        snapshot.raw_payload = None
    await session.flush()
    return len(collections), len(snapshots)


async def cleanup_context_collections(
    session: AsyncSession, *, now: datetime | None = None, limit: int = 100,
) -> int:
    """Remove old scheduler bookkeeping with no retained state or operation link."""
    if not 1 <= limit <= 1000:
        raise ValueError("cleanup limit must be between 1 and 1000")
    cutoff = _utc(now or datetime.now(UTC)) - CONTEXT_RETENTION_POLICIES["health_v1"].ttl
    snapshot_exists = select(ContextSnapshot.id).where(ContextSnapshot.collection_id == ContextCollection.id).exists()
    rows = (await session.scalars(select(ContextCollection).where(
        ContextCollection.requested_by.in_(("scheduler", "activity-sensor")),
        ContextCollection.status.in_(("completed", "failed", "expired")),
        ContextCollection.requested_at < cutoff,
        ContextCollection.operation_id.is_(None),
        ~snapshot_exists,
    ).order_by(ContextCollection.requested_at, ContextCollection.id)
        .limit(limit).with_for_update(skip_locked=True))).all()
    for collection in rows:
        await session.delete(collection)
    await session.flush()
    return len(rows)


__all__ = ["pin_context_snapshot", "retain_context_snapshots", "cleanup_raw_context_payloads", "cleanup_context_collections"]
