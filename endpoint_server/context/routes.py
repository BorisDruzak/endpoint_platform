"""Scoped service API for normalized Device Context data."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts import ContextProfileV1
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.scopes import (
    CONTEXT_COLLECT_SCOPE,
    CONTEXT_READ_SCOPE,
    DEVICES_READ_SCOPE,
    ServicePrincipal,
    require_service_scope,
)
from endpoint_server.db.models import Device, DeviceSession

from .diff import compare_snapshots
from .models import ContextCollection, ContextCurrent, ContextSnapshot
from .projection import collection_projection, snapshot_projection
from .repository import request_collection_outcome
from .service import ContextError


router = APIRouter(prefix="/api/v1", tags=["device-context"])

_SAFE_SERVICE_PROFILES = ("baseline_v1", "health_v1", "network_v1")
_BASELINE_HISTORY_LIMIT = 50
_MAX_BASELINE_HISTORY_LIMIT = 100


class CollectionRequest(BaseModel):
    """The only caller-selected collection input is one fixed profile."""

    model_config = ConfigDict(extra="forbid")

    profile: ContextProfileV1


def _not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="Device context was not found"
    )


def _invalid_request() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="Invalid Device Context request",
    )


def _valid_idempotency_key(value: str | None) -> str:
    if (
        value is None
        or not value
        or len(value) > 128
        or value != value.strip()
        or not value.isascii()
        or any(not 32 <= ord(character) <= 126 for character in value)
    ):
        raise _invalid_request()
    return value


def _device_projection(
    device: Device, last_seen_at: datetime | None
) -> dict[str, object]:
    """Expose device identity and a preselected session timestamp only."""
    return {
        "id": str(device.id),
        "device_identifier": device.device_identifier,
        "display_name": device.display_name,
        "retired_at": device.retired_at,
        "last_seen_at": last_seen_at,
    }


async def _single_device_projection(
    session: AsyncSession, device: Device
) -> dict[str, object]:
    """Project one device, using the same deterministic session ordering as listings."""
    last_seen_at = await session.scalar(
        select(DeviceSession.created_at)
        .where(DeviceSession.device_id == device.id)
        .order_by(DeviceSession.created_at.desc(), DeviceSession.id.desc())
        .limit(1)
    )
    return _device_projection(device, last_seen_at)


@router.get("/devices")
async def list_devices(
    request: Request,
    _: Annotated[ServicePrincipal, Depends(require_service_scope(DEVICES_READ_SCOPE))],
) -> dict[str, object]:
    """List service-visible device identities without context or credentials."""
    async with request.app.state.session_provider() as session:
        session_rank = (
            func.row_number()
            .over(
                partition_by=DeviceSession.device_id,
                order_by=(DeviceSession.created_at.desc(), DeviceSession.id.desc()),
            )
            .label("session_rank")
        )
        latest_sessions = select(
            DeviceSession.device_id.label("device_id"),
            DeviceSession.created_at.label("last_seen_at"),
            session_rank,
        ).subquery()
        rows = (
            await session.execute(
                select(Device, latest_sessions.c.last_seen_at)
                .outerjoin(
                    latest_sessions,
                    and_(
                        Device.id == latest_sessions.c.device_id,
                        latest_sessions.c.session_rank == 1,
                    ),
                )
                .order_by(Device.device_identifier)
            )
        ).all()
        projections = [
            _device_projection(device, last_seen_at) for device, last_seen_at in rows
        ]
    return {"data": projections}


@router.get("/devices/{device_id}/context")
async def read_device_context(
    device_id: UUID,
    request: Request,
    _: Annotated[ServicePrincipal, Depends(require_service_scope(CONTEXT_READ_SCOPE))],
) -> dict[str, object]:
    """Read current normalized, non-diagnostic observations for one device."""
    async with request.app.state.session_provider() as session:
        device = await session.scalar(select(Device).where(Device.id == device_id))
        if device is None:
            raise _not_found()
        currents = (
            await session.scalars(
                select(ContextCurrent)
                .where(
                    ContextCurrent.device_id == device_id,
                    ContextCurrent.profile.in_(_SAFE_SERVICE_PROFILES),
                )
                .order_by(
                    ContextCurrent.profile, ContextCurrent.updated_at, ContextCurrent.id
                )
            )
        ).all()
        collections = (
            await session.scalars(
                select(ContextCollection)
                .where(
                    ContextCollection.device_id == device_id,
                    ContextCollection.profile.in_(_SAFE_SERVICE_PROFILES),
                )
                .order_by(
                    ContextCollection.requested_at.desc(), ContextCollection.id.desc()
                )
            )
        ).all()
        snapshots = []
        for current in currents:
            snapshot = await session.scalar(
                select(ContextSnapshot).where(ContextSnapshot.id == current.snapshot_id)
            )
            if snapshot is not None:
                safe = snapshot_projection(snapshot)
                if safe is not None:
                    snapshots.append(safe)
    snapshots.sort(
        key=lambda item: (
            str(item["profile"]),
            str(item["collected_at"]),
            str(item["id"]),
        )
    )
    availability: dict[str, dict[str, object]] = {}
    for collection in collections:
        availability.setdefault(
            collection.profile,
            {
                "profile": collection.profile,
                "status": collection.status,
                "last_collected_at": collection.completed_at,
            },
        )
    return {
        "data": {
            "device": await _single_device_projection(session, device),
            "profiles": [availability[profile] for profile in sorted(availability)],
            "snapshots": snapshots,
        }
    }


@router.get("/devices/{device_id}/context/snapshots")
async def list_baseline_context_history(
    device_id: UUID,
    request: Request,
    _: Annotated[ServicePrincipal, Depends(require_service_scope(CONTEXT_READ_SCOPE))],
    profile: ContextProfileV1 = "baseline_v1",
    limit: Annotated[
        int, Query(ge=1, le=_MAX_BASELINE_HISTORY_LIMIT)
    ] = _BASELINE_HISTORY_LIMIT,
) -> dict[str, object]:
    """List a deterministic, bounded baseline-only history for one device."""
    if profile != "baseline_v1":
        raise _invalid_request()
    async with request.app.state.session_provider() as session:
        device = await session.scalar(select(Device.id).where(Device.id == device_id))
        if device is None:
            raise _not_found()
        snapshots = (
            await session.scalars(
                select(ContextSnapshot)
                .where(
                    ContextSnapshot.device_id == device_id,
                    ContextSnapshot.profile == "baseline_v1",
                )
                .order_by(
                    ContextSnapshot.collected_at.desc(), ContextSnapshot.id.desc()
                )
                .limit(limit)
            )
        ).all()
    return {
        "data": {
            "snapshots": [
                projection
                for snapshot in snapshots
                if (projection := snapshot_projection(snapshot)) is not None
            ]
        }
    }


@router.post(
    "/devices/{device_id}/context/collections", status_code=status.HTTP_201_CREATED
)
async def request_device_context_collection(
    device_id: UUID,
    body: CollectionRequest,
    request: Request,
    response: Response,
    principal: Annotated[
        ServicePrincipal, Depends(require_service_scope(CONTEXT_COLLECT_SCOPE))
    ],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, object]:
    """Create or replay one audited collection request with a bounded key."""
    key = _valid_idempotency_key(idempotency_key)
    if body.profile not in _SAFE_SERVICE_PROFILES:
        raise _invalid_request()
    async with request.app.state.session_provider() as session:
        try:
            collection, created = await request_collection_outcome(
                session,
                device_id,
                body.profile,
                str(principal.client.id),
                key,
            )
        except ContextError as error:
            await session.rollback()
            raise _not_found() from error
        if created:
            try:
                await append_audit_event(
                    session,
                    actor_kind="service",
                    actor_identifier=str(principal.client.id),
                    action="context.collection_requested",
                    object_kind="context_collection",
                    object_identifier=str(collection.id),
                    request_id=audit_request_id(request),
                    details={"device_id": str(device_id), "profile": body.profile},
                )
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            return {"data": collection_projection(collection)}
        replay = collection_projection(collection)
        await session.rollback()
        response.status_code = status.HTTP_200_OK
        return {"data": replay}


@router.get("/context/collections/{collection_id}")
async def read_collection(
    collection_id: UUID,
    request: Request,
    _: Annotated[ServicePrincipal, Depends(require_service_scope(CONTEXT_READ_SCOPE))],
) -> dict[str, object]:
    """Read lifecycle metadata and an optional safe normalized snapshot."""
    async with request.app.state.session_provider() as session:
        collection = await session.scalar(
            select(ContextCollection).where(ContextCollection.id == collection_id)
        )
        if collection is None or collection.profile not in _SAFE_SERVICE_PROFILES:
            raise _not_found()
        snapshot = await session.scalar(
            select(ContextSnapshot).where(
                ContextSnapshot.collection_id == collection.id
            )
        )
        safe_snapshot = snapshot_projection(snapshot) if snapshot is not None else None
    return {
        "data": {
            "collection": collection_projection(collection),
            "snapshot": safe_snapshot,
        }
    }


@router.get("/devices/{device_id}/context/snapshots/compare")
async def compare_device_context_snapshots(
    device_id: UUID,
    before_snapshot_id: UUID,
    after_snapshot_id: UUID,
    request: Request,
    _: Annotated[ServicePrincipal, Depends(require_service_scope(CONTEXT_READ_SCOPE))],
) -> dict[str, object]:
    """Compare two baseline snapshots owned by the specified device."""
    if before_snapshot_id == after_snapshot_id:
        raise _invalid_request()
    async with request.app.state.session_provider() as session:
        snapshots = (
            await session.scalars(
                select(ContextSnapshot).where(
                    ContextSnapshot.id.in_((before_snapshot_id, after_snapshot_id)),
                    ContextSnapshot.device_id == device_id,
                    ContextSnapshot.profile == "baseline_v1",
                )
            )
        ).all()
    indexed = {snapshot.id: snapshot for snapshot in snapshots}
    before = indexed.get(before_snapshot_id)
    after = indexed.get(after_snapshot_id)
    if before is None or after is None:
        raise _not_found()
    return {
        "data": compare_snapshots(
            before.normalized_projection, after.normalized_projection
        ).model_dump(mode="json")
    }


__all__ = ["router"]
