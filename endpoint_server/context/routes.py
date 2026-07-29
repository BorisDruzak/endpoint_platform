"""Scoped service API for normalized Device Context data."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

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
from endpoint_server.db.models import Device

from .diff import compare_snapshots
from .models import ContextCollection, ContextCurrent, ContextSnapshot
from .projection import collection_projection, snapshot_projection
from .repository import request_collection_outcome
from .service import ContextError


router = APIRouter(prefix="/api/v1", tags=["device-context"])


class CollectionRequest(BaseModel):
    """The only caller-selected collection input is one fixed profile."""

    model_config = ConfigDict(extra="forbid")

    profile: ContextProfileV1


def _not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device context was not found")


def _invalid_request() -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid Device Context request")


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


def _device_projection(device: Device) -> dict[str, object]:
    return {
        "id": str(device.id),
        "device_identifier": device.device_identifier,
        "display_name": device.display_name,
        "retired_at": device.retired_at,
    }


@router.get("/devices")
async def list_devices(
    request: Request,
    _: Annotated[ServicePrincipal, Depends(require_service_scope(DEVICES_READ_SCOPE))],
) -> dict[str, object]:
    """List service-visible device identities without context or credentials."""
    async with request.app.state.session_provider() as session:
        devices = (await session.scalars(select(Device).order_by(Device.device_identifier))).all()
    return {"data": [_device_projection(device) for device in devices]}


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
        currents = (await session.scalars(
            select(ContextCurrent).where(ContextCurrent.device_id == device_id)
        )).all()
        collections = (await session.scalars(
            select(ContextCollection)
            .where(ContextCollection.device_id == device_id)
            .order_by(ContextCollection.requested_at.desc())
        )).all()
        snapshots = []
        for current in currents:
            snapshot = await session.scalar(
                select(ContextSnapshot).where(ContextSnapshot.id == current.snapshot_id)
            )
            if snapshot is not None:
                safe = snapshot_projection(snapshot)
                if safe is not None:
                    snapshots.append(safe)
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
            "device": _device_projection(device),
            "profiles": [availability[profile] for profile in sorted(availability)],
            "snapshots": snapshots,
        }
    }


@router.post("/devices/{device_id}/context/collections", status_code=status.HTTP_201_CREATED)
async def request_device_context_collection(
    device_id: UUID,
    body: CollectionRequest,
    request: Request,
    response: Response,
    principal: Annotated[ServicePrincipal, Depends(require_service_scope(CONTEXT_COLLECT_SCOPE))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, object]:
    """Create or replay one audited collection request with a bounded key."""
    key = _valid_idempotency_key(idempotency_key)
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
        if collection is None:
            raise _not_found()
        snapshot = await session.scalar(
            select(ContextSnapshot).where(ContextSnapshot.collection_id == collection.id)
        )
        safe_snapshot = snapshot_projection(snapshot) if snapshot is not None else None
    return {"data": {"collection": collection_projection(collection), "snapshot": safe_snapshot}}


@router.get("/devices/{device_id}/context/snapshots/compare")
async def compare_device_context_snapshots(
    device_id: UUID,
    before_snapshot_id: UUID,
    after_snapshot_id: UUID,
    request: Request,
    _: Annotated[ServicePrincipal, Depends(require_service_scope(CONTEXT_READ_SCOPE))],
) -> dict[str, object]:
    """Compare two baseline snapshots owned by the specified device."""
    async with request.app.state.session_provider() as session:
        snapshots = (await session.scalars(
            select(ContextSnapshot).where(
                ContextSnapshot.id.in_((before_snapshot_id, after_snapshot_id)),
                ContextSnapshot.device_id == device_id,
                ContextSnapshot.profile == "baseline_v1",
            )
        )).all()
    indexed = {snapshot.id: snapshot for snapshot in snapshots}
    before = indexed.get(before_snapshot_id)
    after = indexed.get(after_snapshot_id)
    if before is None or after is None:
        raise _not_found()
    return {"data": compare_snapshots(before.normalized_projection, after.normalized_projection).model_dump(mode="json")}


__all__ = ["router"]
