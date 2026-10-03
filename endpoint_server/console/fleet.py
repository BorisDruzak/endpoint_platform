"""Bounded safe device projections for interactive administrators."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import TypeAdapter, ValidationError
from sqlalchemy import String, and_, func, or_, select
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql.functions import FunctionElement
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from endpoint_contracts import DeviceContextEnvelopeV1
from endpoint_contracts.updates import SemanticVersionV1, _SEMVER_PATTERN
from endpoint_server.db.instance_order import latest_instance_order
from endpoint_server.context.models import ContextCurrent, ContextSnapshot
from endpoint_server.db.models import (
    Device, DeviceInstance, DeviceSession, EndpointOperation, EnrollmentRequest, UpdateTarget,
)


PRESENCE_TTL = timedelta(seconds=90)
CONTEXT_TTL = timedelta(hours=24)
_VERSION = TypeAdapter(SemanticVersionV1)


def _version_or_unknown(value: str | None) -> str | None:
    try:
        return _VERSION.validate_python(value)
    except ValidationError:
        return None


class _SemverKey(FunctionElement):
    """Bounded SemVer text key: no numeric casts, database functions or locale ordering."""

    type = String()
    inherit_cache = True


@compiles(_SemverKey, "sqlite")
@compiles(_SemverKey, "postgresql")
def _compile_semver_key(element, compiler, **kwargs):
    value = compiler.process(list(element.clauses)[0], **kwargs)
    postgres = compiler.dialect.name == "postgresql"

    def position(text, delimiter):
        return f"{'strpos' if postgres else 'instr'}({text}, '{delimiter}')"

    def matches(text, pattern):
        literal = compiler.render_literal_value(pattern, String())
        return f"({text} {'~' if postgres else 'REGEXP'} {literal})"

    def before(text, delimiter):
        at = position(text, delimiter)
        return f"CASE WHEN {at} > 0 THEN substr({text}, 1, {at}-1) ELSE {text} END"

    def after(text, delimiter):
        at = position(text, delimiter)
        return f"CASE WHEN {at} > 0 THEN substr({text}, {at}+1) ELSE '' END"

    def numeric_key(text):
        # Two decimal length digits cover every component of the 64-character contract.
        size = f"('00' || CAST(length({text}) AS TEXT))"
        return f"substr({size}, length({size})-1, 2) || {text} || '!'"

    pattern = _SEMVER_PATTERN.removesuffix(r"\z") + "$"
    valid = f"length(v) BETWEEN 5 AND 64 AND {matches('v', pattern)} AND NOT {matches('v', '[^0-9A-Za-z.+-]')}"
    token = before("rest", ".")
    token_key = f"CASE WHEN {matches(token, '^[0-9]+$')} THEN '0' || {numeric_key(token)} ELSE '1' || {token} || '!' END"
    collation = '"C"' if postgres else 'BINARY'
    return f"""(WITH RECURSIVE
        version_input(v) AS (SELECT CASE WHEN length({value}) <= 64 THEN {value} ELSE NULL END),
        version_without_build(v, bare) AS (SELECT v, {before('v', '+')} FROM version_input),
        version_parts(v, core, pre) AS (
            SELECT v, {before('bare', '-')}, {after('bare', '-')} FROM version_without_build),
        core_parts(v, a, tail, pre) AS (
            SELECT v, {before('core', '.')}, {after('core', '.')}, pre FROM version_parts),
        pre_parts(rest, key) AS (
            SELECT pre, CAST('' AS TEXT) FROM version_parts
            UNION ALL SELECT {after('rest', '.')}, key || ({token_key}) FROM pre_parts WHERE rest <> '')
        SELECT CASE WHEN {valid} THEN
            {numeric_key('a')} || {numeric_key(before('tail', '.'))} || {numeric_key(after('tail', '.'))} ||
            CASE WHEN pre = '' THEN '1' ELSE '0' || (SELECT key FROM pre_parts WHERE rest = '') END
            ELSE NULL END FROM core_parts) COLLATE {collation}"""


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
        DeviceInstance.launcher_version.label("launcher_version"),
        func.row_number().over(
            partition_by=DeviceInstance.device_id,
            order_by=latest_instance_order(),
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
    core_outdated: str | None = None,
    foundation_outdated: str | None = None,
    core_newer_than_foundation: bool | None = None,
    foundation_unknown: bool | None = None,
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
    core_key = _SemverKey(instances.c.agent_version)
    foundation_key = _SemverKey(instances.c.launcher_version)
    newer = func.coalesce(core_key > foundation_key, False)
    if core_outdated:
        base = base.where(core_key < _SemverKey(core_outdated))
    if foundation_outdated:
        base = base.where(foundation_key < _SemverKey(foundation_outdated))
    if core_newer_than_foundation is not None:
        base = base.where(newer == core_newer_than_foundation)
    if foundation_unknown is not None:
        base = base.where(foundation_key.is_(None) if foundation_unknown else foundation_key.is_not(None))
    if context == "fresh":
        base = base.where(func.coalesce(inventory_current.last_observed_at, inventory_current.updated_at) >= now - CONTEXT_TTL)
    elif context == "stale":
        base = base.where(or_(inventory_current.id.is_(None), func.coalesce(inventory_current.last_observed_at, inventory_current.updated_at) < now - CONTEXT_TTL))
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
            instances.c.agent_version, instances.c.launcher_version, newer, updates.c.status,
            func.coalesce(inventory_current.last_observed_at, inventory_current.updated_at), inventory.normalized_projection,
            session_snapshot.normalized_projection,
        ).order_by(Device.device_identifier, Device.id).limit(limit).offset(offset)
    )).all()
    data: list[dict[str, object]] = []
    for device_id, identifier, display_name, seen, closed, version, launcher, core_newer, update_status, collected, inventory_json, session_json in rows:
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
            "agent_version": _version_or_unknown(version),
            "launcher_version": _version_or_unknown(launcher),
            "core_newer_than_foundation": bool(core_newer),
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
        select(sessions.c.last_seen_at, sessions.c.closed_at, instances.c.agent_version, instances.c.launcher_version,
            func.coalesce(_SemverKey(instances.c.agent_version) > _SemverKey(instances.c.launcher_version), False).label("core_newer_than_foundation"))
        .select_from(Device)
        .outerjoin(sessions, and_(sessions.c.device_id == Device.id, sessions.c.rank == 1))
        .outerjoin(instances, and_(instances.c.device_id == Device.id, instances.c.rank == 1))
        .where(Device.id == device_id)
    )).one_or_none()
    if row is None:
        return {"online": False, "last_seen_at": None, "agent_version": None, "launcher_version": None, "core_newer_than_foundation": False}
    seen = _aware(row.last_seen_at)
    now = datetime.now(UTC)
    return {
        "online": bool(seen and row.closed_at is None and now - PRESENCE_TTL <= seen <= now),
        "last_seen_at": seen,
        "agent_version": _version_or_unknown(row.agent_version),
        "launcher_version": _version_or_unknown(row.launcher_version),
        "core_newer_than_foundation": bool(row.core_newer_than_foundation),
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
        .where(active, or_(current.id.is_(None), func.coalesce(current.last_observed_at, current.updated_at) < now - CONTEXT_TTL))
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
        .where(active, or_(current.id.is_(None), func.coalesce(current.last_observed_at, current.updated_at) < now - CONTEXT_TTL))
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
