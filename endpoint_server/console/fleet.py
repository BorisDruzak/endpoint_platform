"""Bounded safe device projections for interactive administrators."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from endpoint_contracts import DeviceContextEnvelopeV1
from endpoint_server.context.models import ContextCurrent, ContextSnapshot
from endpoint_server.db.models import (
    Device, DeviceInstance, DeviceSession, EndpointOperation, EnrollmentRequest, UpdateTarget,
)


PRESENCE_TTL = timedelta(seconds=90)
CONTEXT_TTL = timedelta(hours=24)


def _latest_sessions():
    observed = func.coalesce(DeviceSession.last_seen_at, DeviceSession.created_at)
    return select(
        DeviceSession.device_id.label("device_id"),
        observed.label("last_seen_at"),
        DeviceSession.closed_at.label("closed_at"),
        func.row_number().over(
            partition_by=DeviceSession.device_id,
            order_by=(observed.desc(), DeviceSession.id.desc()),
        ).label("rank"),
    ).subquery()


def _latest_instances():
    return select(
        DeviceInstance.device_id.label("device_id"),
        DeviceInstance.agent_version.label("agent_version"),
        func.row_number().over(
            partition_by=DeviceInstance.device_id,
            order_by=(DeviceInstance.last_seen_at.desc(), DeviceInstance.created_at.desc(), DeviceInstance.id.desc()),
        ).label("rank"),
    ).subquery()


def _latest_updates():
    return select(
        UpdateTarget.device_id.label("device_id"),
        UpdateTarget.status.label("status"),
        func.row_number().over(
            partition_by=UpdateTarget.device_id,
            order_by=(UpdateTarget.assigned_at.desc(), UpdateTarget.id.desc()),
        ).label("rank"),
    ).subquery()


def _safe_sections(payload: dict[str, object] | None, profile: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    try:
        envelope = DeviceContextEnvelopeV1.model_validate(payload)
    except Exception:
        return {}
    if envelope.profile != profile:
        return {}
    return envelope.sections.model_dump(mode="json")


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


async def list_fleet(
    session: AsyncSession,
    *,
    limit: int = 50,
    offset: int = 0,
    search: str | None = None,
    online: bool | None = None,
    platform: str | None = None,
    agent_version: str | None = None,
    context: str | None = None,
    update: str | None = None,
) -> dict[str, object]:
    """Read one bounded page and its count with two SQL statements, without raw JSON."""
    if not 1 <= limit <= 100 or not 0 <= offset <= 100_000:
        raise ValueError("Invalid fleet pagination")
    now = datetime.now(UTC)
    sessions = _latest_sessions()
    instances = _latest_instances()
    updates = _latest_updates()
    inventory_current = aliased(ContextCurrent)
    inventory = aliased(ContextSnapshot)
    session_current = aliased(ContextCurrent)
    session_snapshot = aliased(ContextSnapshot)
    base = (
        select(Device)
        .outerjoin(sessions, and_(sessions.c.device_id == Device.id, sessions.c.rank == 1))
        .outerjoin(instances, and_(instances.c.device_id == Device.id, instances.c.rank == 1))
        .outerjoin(updates, and_(updates.c.device_id == Device.id, updates.c.rank == 1))
        .outerjoin(inventory_current, and_(inventory_current.device_id == Device.id, inventory_current.profile == "inventory_v1"))
        .outerjoin(inventory, inventory.id == inventory_current.snapshot_id)
        .outerjoin(session_current, and_(session_current.device_id == Device.id, session_current.profile == "session_v1"))
        .outerjoin(session_snapshot, session_snapshot.id == session_current.snapshot_id)
        .where(Device.retired_at.is_(None))
    )
    if search:
        term = f"%{search.strip()[:128]}%"
        base = base.where(or_(Device.display_name.ilike(term), Device.device_identifier.ilike(term)))
    presence = and_(
        sessions.c.closed_at.is_(None),
        sessions.c.last_seen_at >= now - PRESENCE_TTL,
        sessions.c.last_seen_at <= now,
    )
    if online is not None:
        base = base.where(presence if online else ~presence)
    if platform:
        base = base.where(inventory.normalized_projection["sections"]["system"]["platform"].as_string() == platform)
    if agent_version:
        base = base.where(instances.c.agent_version == agent_version)
    if context == "fresh":
        base = base.where(inventory.collected_at >= now - CONTEXT_TTL)
    elif context == "stale":
        base = base.where(or_(inventory.collected_at.is_(None), inventory.collected_at < now - CONTEXT_TTL))
    if update == "none":
        base = base.where(updates.c.status.is_(None))
    elif update == "active":
        base = base.where(updates.c.status.in_(("assigned", "requested", "scheduled")))
    elif update == "failed":
        base = base.where(updates.c.status == "failed")
    total = (await session.scalar(select(func.count()).select_from(base.with_only_columns(Device.id).subquery()))) or 0
    rows = (await session.execute(
        base.with_only_columns(
            Device.id, Device.device_identifier, Device.display_name,
            sessions.c.last_seen_at, sessions.c.closed_at,
            instances.c.agent_version, updates.c.status,
            inventory.collected_at, inventory.normalized_projection,
            session_snapshot.normalized_projection,
        ).order_by(Device.device_identifier, Device.id).limit(limit).offset(offset)
    )).all()
    data: list[dict[str, object]] = []
    for device_id, identifier, display_name, seen, closed, version, update_status, collected, inventory_json, session_json in rows:
        system = _safe_sections(inventory_json, "inventory_v1")
        current_session = _safe_sections(session_json, "session_v1")
        system_info = system.get("system") or {}
        hardware = system.get("hardware") or {}
        memory = system.get("memory") or {}
        session_info = current_session if isinstance(current_session, dict) else {}
        observed = _aware(seen)
        collected_aware = _aware(collected)
        data.append({
            "id": str(device_id),
            "device_identifier": identifier,
            "display_name": display_name or identifier,
            "online": bool(observed and closed is None and now - PRESENCE_TTL <= observed <= now),
            "last_seen_at": observed,
            "agent_version": version,
            "hostname": system_info.get("hostname"),
            "platform": system_info.get("platform"),
            "os_name": system_info.get("os_name"),
            "os_version": system_info.get("os_version"),
            "cpu_model": hardware.get("cpu_model"),
            "ram_bytes": memory.get("total_bytes"),
            "current_user": session_info.get("current_user_login"),
            "context_collected_at": collected_aware,
            "context_fresh": bool(collected_aware and collected_aware >= now - CONTEXT_TTL),
            "update_status": update_status,
        })
    return {"data": data, "total": total, "limit": limit, "offset": offset}


async def device_presence(session: AsyncSession, device_id: object) -> dict[str, object]:
    """One current session and agent instance for a device header."""
    sessions = _latest_sessions()
    instances = _latest_instances()
    row = (await session.execute(
        select(sessions.c.last_seen_at, sessions.c.closed_at, instances.c.agent_version)
        .select_from(Device)
        .outerjoin(sessions, and_(sessions.c.device_id == Device.id, sessions.c.rank == 1))
        .outerjoin(instances, and_(instances.c.device_id == Device.id, instances.c.rank == 1))
        .where(Device.id == device_id)
    )).one_or_none()
    if row is None:
        return {"online": False, "last_seen_at": None, "agent_version": None}
    seen = _aware(row.last_seen_at)
    now = datetime.now(UTC)
    return {
        "online": bool(seen and row.closed_at is None and now - PRESENCE_TTL <= seen <= now),
        "last_seen_at": seen,
        "agent_version": row.agent_version,
    }


async def dashboard_fleet(session: AsyncSession) -> dict[str, object]:
    """Aggregate fleet state in SQL; keep attention rows bounded."""
    now = datetime.now(UTC)
    active = Device.retired_at.is_(None)
    sessions = _latest_sessions()
    instances = _latest_instances()
    updates = _latest_updates()
    total = await session.scalar(select(func.count()).select_from(Device).where(active)) or 0
    online_condition = and_(
        sessions.c.closed_at.is_(None),
        sessions.c.last_seen_at >= now - PRESENCE_TTL,
        sessions.c.last_seen_at <= now,
    )
    online = await session.scalar(
        select(func.count()).select_from(Device)
        .join(sessions, and_(sessions.c.device_id == Device.id, sessions.c.rank == 1))
        .where(active, online_condition)
    ) or 0
    current = aliased(ContextCurrent)
    inventory = aliased(ContextSnapshot)
    stale = await session.scalar(
        select(func.count()).select_from(Device)
        .outerjoin(current, and_(current.device_id == Device.id, current.profile == "inventory_v1"))
        .outerjoin(inventory, inventory.id == current.snapshot_id)
        .where(active, or_(inventory.collected_at.is_(None), inventory.collected_at < now - CONTEXT_TTL))
    ) or 0
    pending = await session.scalar(
        select(func.count()).select_from(EnrollmentRequest)
        .where(EnrollmentRequest.status.in_(("waiting_approval", "review_required")))
    ) or 0
    update_active = await session.scalar(
        select(func.count()).select_from(updates)
        .where(updates.c.rank == 1, updates.c.status.in_(("assigned", "requested", "scheduled")))
    ) or 0
    update_failed = await session.scalar(
        select(func.count()).select_from(updates)
        .where(updates.c.rank == 1, updates.c.status == "failed")
    ) or 0
    operations_active = await session.scalar(
        select(func.count()).select_from(EndpointOperation)
        .where(EndpointOperation.status.in_(("queued", "delivered", "acknowledged", "running")))
    ) or 0
    version_rows = (await session.execute(
        select(instances.c.agent_version, func.count())
        .select_from(Device)
        .outerjoin(instances, and_(instances.c.device_id == Device.id, instances.c.rank == 1))
        .where(active)
        .group_by(instances.c.agent_version)
        .order_by(func.count().desc(), instances.c.agent_version)
        .limit(20)
    )).all()
    failed_rows = (await session.execute(
        select(Device.id, Device.display_name, Device.device_identifier)
        .join(updates, and_(updates.c.device_id == Device.id, updates.c.rank == 1))
        .where(active, updates.c.status == "failed")
        .order_by(Device.device_identifier).limit(5)
    )).all()
    stale_rows = (await session.execute(
        select(Device.id, Device.display_name, Device.device_identifier)
        .outerjoin(current, and_(current.device_id == Device.id, current.profile == "inventory_v1"))
        .outerjoin(inventory, inventory.id == current.snapshot_id)
        .where(active, or_(inventory.collected_at.is_(None), inventory.collected_at < now - CONTEXT_TTL))
        .order_by(Device.device_identifier).limit(5)
    )).all()
    attention = [
        {"kind": "update_failed", "device_id": str(row.id), "label": row.display_name or row.device_identifier}
        for row in failed_rows
    ] + [
        {"kind": "context_stale", "device_id": str(row.id), "label": row.display_name or row.device_identifier}
        for row in stale_rows
    ]
    return {
        "total": total, "online": online, "offline": total - online,
        "context_stale": stale, "enrollment_pending": pending,
        "updates_active": update_active, "updates_failed": update_failed,
        "operations_active": operations_active,
        "versions": [{"version": version, "count": count} for version, count in version_rows],
        "attention": attention[:8],
    }
