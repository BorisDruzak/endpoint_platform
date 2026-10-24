"""Session-protected console history; deliberately separate from SDK APIs."""

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from endpoint_contracts.power_events import PowerEventV1
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.console.fleet import device_presence
from endpoint_server.context.models import DeviceEvent
from endpoint_server.db.models import Device
from .projection import PowerSummary, power_summary

router = APIRouter(tags=["admin-console-power"])


class ConsolePowerResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    summary: PowerSummary
    data: list[PowerEventV1]
    total: int
    limit: int
    offset: int
    has_more: bool


@router.get(
    "/api/admin/console/devices/{device_id}/power", response_model=ConsolePowerResponse
)
async def console_device_power(
    request: Request,
    response: Response,
    device_id: UUID,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> ConsolePowerResponse:
    response.headers["Cache-Control"] = "no-store"
    now = datetime.now(UTC)
    async with request.app.state.session_provider() as session:
        device = await session.scalar(
            select(Device.id).where(Device.id == device_id, Device.retired_at.is_(None))
        )
        if device is None:
            raise HTTPException(404, "Устройство не найдено")
        presence = await device_presence(session, device_id)
        summary = await power_summary(
            session,
            device_id,
            online=presence["online"],
            last_seen_at=presence["last_seen_at"],
            now=now,
        )
        filters = (
            DeviceEvent.device_id == device_id,
            DeviceEvent.category == "power",
            DeviceEvent.profile == "power_v1",
            DeviceEvent.occurred_at >= now - timedelta(days=30),
        )
        total = (
            await session.scalar(
                select(func.count()).select_from(DeviceEvent).where(*filters)
            )
            or 0
        )
        rows = list(
            (
                await session.scalars(
                    select(DeviceEvent)
                    .where(*filters)
                    .order_by(DeviceEvent.occurred_at.desc(), DeviceEvent.id.desc())
                    .offset(offset)
                    .limit(limit)
                )
            ).all()
        )
    return ConsolePowerResponse(
        summary=summary,
        data=[PowerEventV1.model_validate(r.details["event"]) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
        has_more=offset + len(rows) < total,
    )
