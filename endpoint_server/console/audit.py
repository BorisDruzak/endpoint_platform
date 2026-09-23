"""Read-only, bounded administrative projection of immutable audit events."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select

from endpoint_server.audit.redaction import redact_audit_details
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.db.models import AuditEvent


router = APIRouter(prefix="/api/admin/audit", tags=["admin-audit"])


@router.get("/events")
async def list_audit_events(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    since: datetime | None = None,
    until: datetime | None = None,
    actor: Annotated[str | None, Query(max_length=128)] = None,
    action: Annotated[str | None, Query(max_length=128)] = None,
    object_kind: Annotated[str | None, Query(max_length=64)] = None,
    object_id: Annotated[str | None, Query(max_length=128)] = None,
    request_id: Annotated[str | None, Query(max_length=128)] = None,
) -> dict[str, object]:
    if (since is not None and since.utcoffset() is None) or (until is not None and until.utcoffset() is None):
        raise HTTPException(status_code=422, detail="Укажите часовой пояс периода")
    if since is not None and until is not None and since > until:
        raise HTTPException(status_code=422, detail="Начало периода позже окончания")
    filters = []
    if since is not None:
        filters.append(AuditEvent.created_at >= since)
    if until is not None:
        filters.append(AuditEvent.created_at <= until)
    if actor:
        filters.append(or_(AuditEvent.actor_identifier == actor, AuditEvent.actor_kind == actor))
    if action:
        filters.append(AuditEvent.action == action)
    if object_kind:
        filters.append(AuditEvent.object_kind == object_kind)
    if object_id:
        filters.append(AuditEvent.object_identifier == object_id)
    if request_id:
        filters.append(AuditEvent.request_id == request_id)
    async with request.app.state.session_provider() as session:
        total = await session.scalar(select(func.count()).select_from(AuditEvent).where(*filters)) or 0
        rows = (await session.execute(
            select(AuditEvent).where(*filters)
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .offset(offset).limit(limit)
        )).scalars().all()
    return {
        "data": [{
            "id": str(item.id), "created_at": item.created_at,
            "actor_kind": item.actor_kind, "actor_identifier": item.actor_identifier,
            "action": item.action, "object_kind": item.object_kind,
            "object_identifier": item.object_identifier,
            "request_id": item.request_id,
            "details": redact_audit_details(item.details),
        } for item in rows],
        "total": total, "limit": limit, "offset": offset,
    }
