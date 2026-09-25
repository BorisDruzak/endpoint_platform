"""Bounded administrator projection of the latest user Activity observation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import AwareDatetime, BaseModel, ConfigDict
from sqlalchemy import select

from endpoint_contracts.activity import ActivitySectionsV1
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.console.fleet import device_presence
from endpoint_server.context.models import ContextCurrent
from endpoint_server.context.projection import activity_current_projection
from endpoint_server.db.models import Device


router = APIRouter(tags=["admin-console-activity"])
_ACTIVITY_FRESHNESS = timedelta(minutes=2)


class ConsoleActivity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    collected_at: AwareDatetime
    last_observed_at: AwareDatetime
    sections: ActivitySectionsV1
    online: bool
    fresh: bool


class ConsoleActivityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data: ConsoleActivity | None


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@router.get(
    "/api/admin/console/devices/{device_id}/activity",
    response_model=ConsoleActivityResponse,
)
async def console_device_activity(
    request: Request,
    device_id: UUID,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> ConsoleActivityResponse:
    async with request.app.state.session_provider() as session:
        device = await session.scalar(select(Device.id).where(
            Device.id == device_id, Device.retired_at.is_(None),
        ))
        if device is None:
            raise HTTPException(status_code=404, detail="Устройство не найдено")
        current = await session.scalar(select(ContextCurrent).where(
            ContextCurrent.device_id == device_id,
            ContextCurrent.profile == "activity_v1",
        ))
        projection = activity_current_projection(current) if current is not None else None
        if projection is None:
            return ConsoleActivityResponse(data=None)
        presence = await device_presence(session, device_id)

    observed_at = _aware(projection["last_observed_at"])
    now = datetime.now(UTC)
    online = bool(presence["online"])
    return ConsoleActivityResponse(data=ConsoleActivity.model_validate({
        "collected_at": _aware(projection["collected_at"]),
        "last_observed_at": observed_at,
        "sections": projection["sections"],
        "online": online,
        "fresh": online and timedelta(0) <= now - observed_at <= _ACTIVITY_FRESHNESS,
    }))
