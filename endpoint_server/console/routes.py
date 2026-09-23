"""Session-protected Console shell and safe browser bootstrap."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from endpoint_server.auth.admin_sessions import (
    ADMIN_SESSION_COOKIE,
    AdminPrincipal,
    normalize_admin_scopes,
    require_admin,
)
from endpoint_server.auth.csrf import csrf_token_for_session
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.console.fleet import dashboard_fleet, device_presence, list_fleet
from endpoint_server.context.diff import compare_snapshots
from endpoint_server.context.models import ContextCollection, ContextCurrent, ContextSnapshot
from endpoint_server.context.projection import snapshot_projection
from endpoint_server.context.projection import collection_projection
from endpoint_server.context.repository import request_collection_outcome
from endpoint_server.context.service import ContextError
from endpoint_server.db.models import Device, EnrollmentRequest
from endpoint_server.enrollment.admin_routes import CampaignCreateRequest, create_campaign
from sqlalchemy import select


ASSET_ROOT = Path(__file__).resolve().parents[2] / "webapp" / "dist"
router = APIRouter(tags=["admin-console"])
_INDEX_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    ),
}


class ConsoleSessionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    username: str
    scopes: list[str]
    csrf_token: str


class ConsoleCollectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: str


@router.post("/api/admin/console/campaigns", status_code=201)
async def console_create_campaign(
    body: CampaignCreateRequest,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> dict[str, object]:
    """Use the canonical campaign path while keeping its show-once bearer server-side."""
    created = await create_campaign(body, request, principal)
    return {"id": str(created.id)}


@router.get("/api/admin/console/enrollment/requests/{request_id}")
async def console_enrollment_request_detail(
    request: Request,
    request_id: UUID,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> dict[str, object]:
    async with request.app.state.session_provider() as session:
        record = await session.scalar(select(EnrollmentRequest).where(EnrollmentRequest.id == request_id))
        if record is None:
            raise HTTPException(status_code=404, detail="Запрос регистрации не найден")
        return {"data": {
            "id": str(record.id), "status": record.status,
            "reason": record.decision_reason, "platform": record.platform,
            "hostname": record.hostname, "manufacturer": record.manufacturer,
            "model": record.model, "serial": record.serial,
            "macs": record.macs, "source_address": record.source_address,
            "installer_release_id": record.installer_release_id,
            "selected_campaign_id": str(record.selected_campaign_id) if record.selected_campaign_id else None,
            "device_id": str(record.device_id) if record.device_id else None,
            "created_at": record.created_at, "updated_at": record.updated_at,
            "expires_at": record.expires_at, "decided_at": record.decided_at,
        }}


@router.post("/api/admin/console/devices/{device_id}/context/collections", status_code=201)
async def console_request_context(
    request: Request,
    response: Response,
    device_id: UUID,
    body: ConsoleCollectionRequest,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, object]:
    if body.profile not in {"baseline_v1", "health_v1", "network_v1", "inventory_v1", "session_v1"}:
        raise HTTPException(status_code=422, detail="Недопустимый профиль Context")
    if (not idempotency_key or len(idempotency_key) > 128 or
        not idempotency_key.isascii() or idempotency_key != idempotency_key.strip() or
        any(not 32 <= ord(character) <= 126 for character in idempotency_key)):
        raise HTTPException(status_code=422, detail="Недопустимый ключ запроса")
    async with request.app.state.session_provider() as session:
        try:
            collection, created = await request_collection_outcome(
                session, device_id, body.profile, f"admin:{principal.user.id}", idempotency_key,
            )
        except ContextError as error:
            await session.rollback()
            raise HTTPException(status_code=404, detail="Устройство не найдено") from error
        projected = collection_projection(collection)
        if created:
            await append_audit_event(
                session, actor_kind="admin", actor_identifier=str(principal.user.id),
                action="context.collection_requested", object_kind="context_collection",
                object_identifier=str(collection.id), request_id=audit_request_id(request),
                details={"device_id": str(device_id), "profile": body.profile},
            )
            await session.commit()
        else:
            await session.rollback()
            response.status_code = 200
    return {"data": projected}


@router.get("/api/admin/console/context/collections/{collection_id}")
async def console_collection_status(
    request: Request,
    collection_id: UUID,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> dict[str, object]:
    async with request.app.state.session_provider() as session:
        collection = await session.scalar(
            select(ContextCollection).where(
                ContextCollection.id == collection_id,
                ContextCollection.profile.in_(("baseline_v1", "health_v1", "network_v1", "inventory_v1", "session_v1")),
            )
        )
        if collection is None:
            raise HTTPException(status_code=404, detail="Сбор Context не найден")
        return {"data": collection_projection(collection)}


@router.get("/api/admin/console/dashboard")
async def console_dashboard(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> dict[str, object]:
    async with request.app.state.session_provider() as session:
        return await dashboard_fleet(session)


@router.get("/api/admin/console/devices")
async def console_devices(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    search: Annotated[str | None, Query(max_length=128)] = None,
    online: bool | None = None,
    platform: Annotated[str | None, Query(pattern="^(windows|linux)$")] = None,
    agent_version: Annotated[str | None, Query(max_length=128)] = None,
    context: Annotated[str | None, Query(pattern="^(fresh|stale)$")] = None,
    update: Annotated[str | None, Query(pattern="^(none|active|failed)$")] = None,
) -> dict[str, object]:
    async with request.app.state.session_provider() as session:
        result = await list_fleet(
            session, limit=limit, offset=offset, search=search, online=online,
            platform=platform, agent_version=agent_version, context=context, update=update,
        )
    return result


@router.get("/api/admin/console/devices/{device_id}")
async def console_device_detail(
    request: Request,
    device_id: UUID,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> dict[str, object]:
    async with request.app.state.session_provider() as session:
        device = await session.scalar(select(Device).where(Device.id == device_id, Device.retired_at.is_(None)))
        if device is None:
            raise HTTPException(status_code=404, detail="Устройство не найдено")
        rows = (await session.execute(
            select(ContextSnapshot)
            .join(ContextCurrent, ContextCurrent.snapshot_id == ContextSnapshot.id)
            .where(ContextCurrent.device_id == device_id)
            .order_by(ContextSnapshot.profile)
        )).scalars().all()
        snapshots = [safe for row in rows if (safe := snapshot_projection(row)) is not None]
        presence = await device_presence(session, device_id)
        return {
            "device": {
                "id": str(device.id),
                "device_identifier": device.device_identifier,
                "display_name": device.display_name or device.device_identifier,
                **presence,
            },
            "snapshots": snapshots,
        }


@router.get("/api/admin/console/devices/{device_id}/changes")
async def console_device_changes(
    request: Request,
    device_id: UUID,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> dict[str, object]:
    async with request.app.state.session_provider() as session:
        exists = await session.scalar(select(Device.id).where(Device.id == device_id, Device.retired_at.is_(None)))
        if exists is None:
            raise HTTPException(status_code=404, detail="Устройство не найдено")
        rows: list[ContextSnapshot] = []
        for profile in ("baseline_v1", "inventory_v1"):
            rows.extend((await session.execute(
                select(ContextSnapshot)
                .where(ContextSnapshot.device_id == device_id, ContextSnapshot.profile == profile)
                .order_by(ContextSnapshot.collected_at.desc(), ContextSnapshot.id.desc())
                .limit(20)
            )).scalars().all())
    changes: list[dict[str, object]] = []
    by_profile: dict[str, list[ContextSnapshot]] = {"baseline_v1": [], "inventory_v1": []}
    for row in rows:
        by_profile[row.profile].append(row)
    for profile_rows in by_profile.values():
        for after, before in zip(profile_rows, profile_rows[1:]):
            after_safe = snapshot_projection(after)
            before_safe = snapshot_projection(before)
            if after_safe is None or before_safe is None:
                continue
            try:
                diff = compare_snapshots(before_safe, after_safe)
            except (TypeError, ValueError):
                continue
            for change in diff.changes:
                before_sections = before_safe["sections"]
                after_sections = after_safe["sections"]
                field_path = {
                    "RAM_CHANGED": ("memory", "total_bytes"),
                    "HOSTNAME_CHANGED": ("system", "hostname"),
                    "OS_CHANGED": ("system", "os_name"),
                }.get(change.code)
                old_value = new_value = None
                if field_path is not None:
                    before_part = before_sections.get(field_path[0], {})
                    after_part = after_sections.get(field_path[0], {})
                    if isinstance(before_part, dict) and isinstance(after_part, dict):
                        old_value = before_part.get(field_path[1])
                        new_value = after_part.get(field_path[1])
                changes.append({
                    "code": change.code,
                    "profile": after.profile,
                    "collected_at": after.collected_at,
                    "before_snapshot_id": str(before.id),
                    "after_snapshot_id": str(after.id),
                    "before_value": old_value,
                    "after_value": new_value,
                })
    changes.sort(key=lambda row: row["collected_at"], reverse=True)
    return {"data": changes[:50]}


def install_console_assets(app: FastAPI) -> None:
    """Register only public, built assets; page and API routes remain protected."""
    app.mount(
        "/admin/assets",
        StaticFiles(directory=ASSET_ROOT / "assets", check_dir=False),
        name="admin-console-assets",
    )


def _index() -> FileResponse:
    path = ASSET_ROOT / "index.html"
    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Console bundle is not installed",
        )
    return FileResponse(path, media_type="text/html", headers=_INDEX_HEADERS)


@router.get("/api/admin/console/session", response_model=ConsoleSessionResponse)
async def console_session(
    request: Request,
    response: Response,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> ConsoleSessionResponse:
    """Return the interactive user's safe identity and session-bound CSRF token."""
    session_token = request.cookies.get(ADMIN_SESSION_COOKIE, "")
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    try:
        scopes = normalize_admin_scopes(principal.user.scopes)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN) from error
    return ConsoleSessionResponse(
        username=principal.user.username,
        scopes=scopes,
        csrf_token=csrf_token_for_session(
            session_token, request.app.state.settings.session_secret
        ),
    )


@router.get("/admin/login", include_in_schema=False)
async def console_login_page() -> FileResponse:
    return _index()


@router.get("/admin", include_in_schema=False)
async def console_dashboard_page(
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> FileResponse:
    return _index()


@router.get("/admin/{path:path}", include_in_schema=False)
async def console_deep_link_page(
    path: str,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> FileResponse:
    if path.startswith("assets/"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return _index()
