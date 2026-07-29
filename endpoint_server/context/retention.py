"""Bounded retention for immutable Device Context snapshots."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ContextCurrent, ContextSnapshot
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
) -> int:
    """Delete at most ``limit`` snapshots while preserving current/previous/pinned.

    The current pointer is preserved even in the unlikely delayed-result case
    where it is not one of the two newest timestamps.  The immediately older
    snapshot is retained for a safe baseline comparison.  Snapshot foreign-key
    cascades remove only dependent diffs/findings; collection audit records
    remain intact.
    """
    if not 1 <= limit <= 100:
        raise ValueError("retention limit must be between 1 and 100")
    deleted = 0
    profile_rows = await session.execute(
        select(ContextSnapshot.device_id, ContextSnapshot.profile)
        .distinct()
        .order_by(ContextSnapshot.device_id, ContextSnapshot.profile)
    )
    for device_id, profile in profile_rows.tuples():
        # This is deliberately the same transaction-scoped lock used by
        # ingestion to move ContextCurrent.  Do not use SKIP LOCKED here: a
        # skipped current, predecessor, or pin is unknown, not absent.
        await _advisory_lock(session, f"context.current:{device_id}:{profile}")
        current = await session.scalar(
            select(ContextCurrent)
            .where(
                ContextCurrent.device_id == device_id,
                ContextCurrent.profile == profile,
            )
            .with_for_update()
        )
        group = (await session.scalars(
            select(ContextSnapshot)
            .where(
                ContextSnapshot.device_id == device_id,
                ContextSnapshot.profile == profile,
            )
            .order_by(ContextSnapshot.collected_at.desc(), ContextSnapshot.id.desc())
            .with_for_update()
        )).all()
        current_id = current.snapshot_id if current is not None else None
        keep_ids = {snapshot.id for snapshot in group if snapshot.pinned_at is not None}
        if current_id is not None:
            keep_ids.add(current_id)
            current = next((snapshot for snapshot in group if snapshot.id == current_id), None)
            if current is not None:
                current_at = _utc(current.collected_at)
                previous = next(
                    (
                        snapshot
                        for snapshot in group
                        if (_utc(snapshot.collected_at), snapshot.id)
                        < (current_at, current.id)
                    ),
                    None,
                )
                if previous is not None:
                    keep_ids.add(previous.id)
        else:
            keep_ids.update(snapshot.id for snapshot in group[:2])
        for snapshot in group:
            if snapshot.id in keep_ids:
                continue
            await session.delete(snapshot)
            deleted += 1
            if deleted == limit:
                await session.flush()
                return deleted
    await session.flush()
    return deleted


__all__ = ["pin_context_snapshot", "retain_context_snapshots"]
