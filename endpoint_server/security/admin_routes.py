"""Bounded, read-only Console projection of validated SecurityEvents."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, JsonValue, TypeAdapter, ValidationError
from sqlalchemy import func, select

from endpoint_contracts.security_events import SecurityEventV1
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.db.models import Device

from .models import SecurityEvent


router = APIRouter(prefix="/api/admin/console/security/events", tags=["admin-console-security"])
_event_adapter = TypeAdapter(SecurityEventV1)
_event_types = Literal[
    "USB_DEVICE_CONNECTED", "USB_DEVICE_DISCONNECTED", "PRINT_JOB",
    "BROWSER_UPLOAD", "BROWSER_PASTE",
]


class ConsoleSecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    device_id: UUID
    device_name: str
    event_type: _event_types
    channel: Literal["USB", "PRINT", "BROWSER"]
    severity: Literal["INFO"]
    occurred_at: datetime
    received_at: datetime
    user_login: str | None
    policy_id: UUID
    policy_version: int
    domain: str | None
    metadata_valid: bool


class ConsoleSecurityEventDetail(ConsoleSecurityEvent):
    safe_metadata: dict[str, JsonValue]


class ConsoleSecurityEventPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: list[ConsoleSecurityEvent]
    total: int
    limit: int
    offset: int


class ConsoleSecurityEventDetailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: ConsoleSecurityEventDetail


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _project(row: SecurityEvent, device: Device) -> ConsoleSecurityEventDetail:
    """Revalidate stored metadata; a malformed row cannot disclose extra keys."""
    valid = True
    try:
        event = _event_adapter.validate_python({
            "schema_version": "security_event_v1",
            "event_identifier": row.event_identifier,
            "event_type": row.event_type,
            "channel": row.channel,
            "severity": row.severity,
            "occurred_at": _aware(row.occurred_at),
            "user_login": row.user_login,
            "policy_id": row.policy_id,
            "policy_version": row.policy_version,
            "safe_metadata": row.safe_metadata,
        })
        safe_metadata = event.safe_metadata.model_dump(mode="json", exclude_none=True)
    except ValidationError:
        valid = False
        safe_metadata = {}
    domain = safe_metadata.get("domain")
    return ConsoleSecurityEventDetail(
        id=row.id,
        device_id=row.device_id,
        device_name=device.display_name or device.device_identifier,
        event_type=row.event_type,
        channel=row.channel,
        severity=row.severity,
        occurred_at=_aware(row.occurred_at),
        received_at=_aware(row.received_at),
        user_login=row.user_login if valid else None,
        policy_id=row.policy_id,
        policy_version=row.policy_version,
        domain=domain if isinstance(domain, str) else None,
        metadata_valid=valid,
        safe_metadata=safe_metadata,
    )


@router.get("", response_model=ConsoleSecurityEventPage)
async def list_security_events(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    since: datetime | None = None,
    until: datetime | None = None,
    device_id: UUID | None = None,
    user_login: Annotated[str | None, Query(max_length=256)] = None,
    channel: Literal["USB", "PRINT", "BROWSER"] | None = None,
    event_type: _event_types | None = None,
    severity: Literal["INFO"] | None = None,
    domain: Annotated[str | None, Query(max_length=253)] = None,
) -> ConsoleSecurityEventPage:
    now = datetime.now(UTC)
    if (since is not None and since.utcoffset() is None) or (until is not None and until.utcoffset() is None):
        raise HTTPException(status_code=422, detail="Укажите часовой пояс периода")
    if since is None:
        since = (until or now) - timedelta(days=30)
    if until is None:
        until = now
    if since > until or until - since > timedelta(days=365):
        raise HTTPException(status_code=422, detail="Период должен быть от 0 до 365 дней")
    filters = [SecurityEvent.occurred_at >= since, SecurityEvent.occurred_at <= until]
    if device_id is not None:
        filters.append(SecurityEvent.device_id == device_id)
    if user_login:
        filters.append(SecurityEvent.user_login == user_login)
    if channel:
        filters.append(SecurityEvent.channel == channel)
    if event_type:
        filters.append(SecurityEvent.event_type == event_type)
    if severity:
        filters.append(SecurityEvent.severity == severity)
    if domain:
        filters.append(SecurityEvent.safe_metadata["domain"].as_string() == domain)
    async with request.app.state.session_provider() as session:
        total = await session.scalar(select(func.count()).select_from(SecurityEvent).where(*filters)) or 0
        rows = (await session.execute(
            select(SecurityEvent, Device).join(Device, Device.id == SecurityEvent.device_id)
            .where(*filters)
            .order_by(SecurityEvent.occurred_at.desc(), SecurityEvent.id.desc())
            .offset(offset).limit(limit)
        )).all()
    return ConsoleSecurityEventPage(
        data=[ConsoleSecurityEvent.model_validate(_project(row, device)) for row, device in rows],
        total=total, limit=limit, offset=offset,
    )


@router.get("/{event_id}", response_model=ConsoleSecurityEventDetailResponse)
async def security_event_detail(
    event_id: UUID,
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> ConsoleSecurityEventDetailResponse:
    async with request.app.state.session_provider() as session:
        row = (await session.execute(
            select(SecurityEvent, Device).join(Device, Device.id == SecurityEvent.device_id)
            .where(SecurityEvent.id == event_id)
        )).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Событие безопасности не найдено")
    return ConsoleSecurityEventDetailResponse(data=_project(*row))
