"""Bounded server-owned expiry for validated SecurityEvents."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_server.db.retention import EventRetentionBatch

from .models import SecurityEvent


async def retain_security_events(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> int:
    return (await retain_security_events_with_backlog(session, now=now, limit=limit)).deleted


async def retain_security_events_with_backlog(
    session: AsyncSession, *, now: datetime | None = None, limit: int = 100,
) -> EventRetentionBatch:
    """Delete at most one small indexed batch; caller commits the transaction."""
    if isinstance(limit, bool) or not 1 <= limit <= 1000:
        raise ValueError("security event retention limit must be between 1 and 1000")
    when = now or datetime.now(UTC)
    if when.tzinfo is None:
        raise ValueError("security event retention time must be timezone aware")
    identifiers = list(
        await session.scalars(
            select(SecurityEvent.id)
            .where(SecurityEvent.expires_at <= when)
            .order_by(SecurityEvent.expires_at, SecurityEvent.id)
            .limit(limit)
        )
    )
    if not identifiers:
        return EventRetentionBatch(0, 0.0)
    deleted = await session.scalars(
        delete(SecurityEvent)
        .where(SecurityEvent.id.in_(identifiers), SecurityEvent.expires_at <= when)
        .returning(SecurityEvent.expires_at)
    )
    return EventRetentionBatch.from_deleted(list(deleted), cutoff=when)


__all__ = ["retain_security_events"]
