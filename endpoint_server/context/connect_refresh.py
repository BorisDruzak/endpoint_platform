"""Capability-aware safe-profile refreshes at agent connection time."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import AbstractSet
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ContextCollection, ContextSnapshot
from .repository import request_collection_outcome


@dataclass(frozen=True, slots=True)
class ConnectRefreshRule:
    profile: str
    capability: str
    freshness: timedelta


CONNECT_REFRESH_RULES: tuple[ConnectRefreshRule, ...] = (
    ConnectRefreshRule("baseline_v1", "context.baseline.collect", timedelta(hours=24)),
    ConnectRefreshRule("inventory_v1", "context.inventory.collect", timedelta(hours=24)),
    ConnectRefreshRule("network_v1", "context.network.collect", timedelta(minutes=15)),
)
"""Only capability-backed safe profiles qualify for connection refresh."""

_ACTIVE_STATUSES = frozenset(
    {"requested", "queued", "delivered", "collecting", "result_received", "validated"}
)
_DELIVERY_WINDOW = timedelta(minutes=15)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def _advisory_lock(session: AsyncSession, key: str) -> None:
    if session.get_bind().dialect.name == "postgresql":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": key},
        )


async def queue_connect_refreshes(
    session: AsyncSession,
    device_id: UUID,
    capabilities: AbstractSet[str],
    *,
    now: datetime | None = None,
) -> int:
    """Queue missing or stale supported observations without duplicate active work."""
    observed_at = _utc(now or datetime.now(UTC))
    created = 0
    for rule in CONNECT_REFRESH_RULES:
        if rule.capability not in capabilities:
            continue
        await _advisory_lock(session, f"context.connect-refresh:{device_id}:{rule.profile}")
        active = await session.scalar(
            select(ContextCollection)
            .where(
                ContextCollection.device_id == device_id,
                ContextCollection.profile == rule.profile,
                ContextCollection.status.in_(_ACTIVE_STATUSES),
            )
            .with_for_update()
        )
        if active is not None:
            continue
        latest = await session.scalar(
            select(ContextSnapshot)
            .where(
                ContextSnapshot.device_id == device_id,
                ContextSnapshot.profile == rule.profile,
            )
            .order_by(ContextSnapshot.collected_at.desc(), ContextSnapshot.id.desc())
            .limit(1)
            .with_for_update()
        )
        if latest is not None and observed_at - _utc(latest.collected_at) < rule.freshness:
            continue
        bucket = int(observed_at.timestamp() // rule.freshness.total_seconds())
        collection, inserted = await request_collection_outcome(
            session,
            device_id,
            rule.profile,
            "connect-refresh",
            f"connect-refresh:{rule.profile}:{bucket}",
            now=observed_at,
        )
        if inserted:
            collection.expires_at = observed_at + _DELIVERY_WINDOW
            created += 1
    await session.flush()
    return created


__all__ = ["CONNECT_REFRESH_RULES", "ConnectRefreshRule", "queue_connect_refreshes"]
