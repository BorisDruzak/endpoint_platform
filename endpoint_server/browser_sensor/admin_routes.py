"""Session-protected Browser Sensor release identity for Endpoint Console."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.browser_sensor.models import BrowserSensorRelease


router = APIRouter(prefix="/api/admin/console/browser-sensor", tags=["admin-console-browser-sensor"])


class BrowserReleaseProjection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    extension_version: str
    extension_id: str
    protocol_version: int
    source_revision: str
    artifact_sha256: str
    minimum_agent_version: str
    built_at: datetime
    published_at: datetime
    update_url: str
    artifact_url: str


@router.get("/release", response_model=BrowserReleaseProjection)
async def current_browser_release(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> BrowserReleaseProjection:
    async with request.app.state.session_provider() as session:
        release = await session.scalar(
            select(BrowserSensorRelease)
            .where(BrowserSensorRelease.retired_at.is_(None))
            .order_by(BrowserSensorRelease.created_at.desc(), BrowserSensorRelease.id.desc())
            .limit(1)
        )
    if release is None:
        raise HTTPException(status_code=404, detail="Релиз Browser Sensor не опубликован")
    return BrowserReleaseProjection(
        extension_version=release.extension_version,
        extension_id=release.extension_id,
        protocol_version=release.protocol_version,
        source_revision=release.source_revision,
        artifact_sha256=release.artifact_sha256,
        minimum_agent_version=release.minimum_agent_version,
        built_at=release.built_at,
        published_at=release.created_at,
        update_url="/api/v1/browser-sensor/update.xml",
        artifact_url=f"/api/v1/browser-sensor/releases/{release.extension_version}/sensor.crx",
    )
