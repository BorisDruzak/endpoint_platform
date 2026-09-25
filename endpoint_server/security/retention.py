"""Bounded server-owned expiry for validated SecurityEvents."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import SecurityEvent


async def retain_security_events(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> int:
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
    if identifiers:
        await session.execute(
            delete(SecurityEvent).where(SecurityEvent.id.in_(identifiers))
        )
    return len(identifiers)


__all__ = ["retain_security_events"]
