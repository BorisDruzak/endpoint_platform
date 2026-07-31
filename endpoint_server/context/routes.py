"""Scoped service API for normalized Device Context data."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal
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
from pydantic import BaseModel, ConfigDict, Field
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
from .projection import (
    baseline_interface_mac_keys,
    collection_projection,
    snapshot_projection,
)
from .repository import request_collection_outcome
from .service import ContextError


router = APIRouter(prefix="/api/v1", tags=["device-context"])

_SAFE_SERVICE_PROFILES = ("baseline_v1", "health_v1", "network_v1")
_BASELINE_HISTORY_LIMIT = 50
_MAX_BASELINE_HISTORY_LIMIT = 100
_NETWORK_IDENTITY_LIMIT = 250
_NETWORK_IDENTITY_CHUNK_SIZE = 250
SafeServiceProfile = Literal["baseline_v1", "health_v1", "network_v1"]


class CollectionRequest(BaseModel):
    """The only caller-selected collection input is one fixed profile."""

    model_config = ConfigDict(extra="forbid")

    profile: ContextProfileV1


class AgentNetworkProfile(BaseModel):
    """Current safe profile availability needed by the network panel."""

    model_config = ConfigDict(extra="forbid")

    profile: SafeServiceProfile
    collected_at: datetime


class AgentNetworkIdentity(BaseModel):
    """Minimal service-only identity material for exact MAC correlation."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    device_identifier: str = Field(min_length=1, max_length=256)
    display_name: str = Field(min_length=1, max_length=256)
    last_seen_at: datetime | None
    baseline_collected_at: datetime
    profiles: list[AgentNetworkProfile] = Field(max_length=3)
    baseline_mac_keys: list[
        Annotated[str, Field(pattern=r"^mac-[0-9a-f]{12}$")]
    ] = Field(min_length=1, max_length=64)


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


def _aware_timestamp(value: datetime | None) -> datetime | None:
    """Normalize SQLite fixture timestamps without changing aware production values."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


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


@router.get("/devices/network-identities")
async def list_network_identities(
    request: Request,
    _: Annotated[ServicePrincipal, Depends(require_service_scope(DEVICES_READ_SCOPE))],
    __: Annotated[ServicePrincipal, Depends(require_service_scope(CONTEXT_READ_SCOPE))],
    limit: Annotated[int, Query(ge=1, le=_NETWORK_IDENTITY_LIMIT)] = _NETWORK_IDENTITY_LIMIT,
    cursor: UUID | None = None,
) -> dict[str, object]:
    """Return bounded current baseline MAC identities for a trusted service peer."""
    candidates: list[AgentNetworkIdentity] = []
    after_id = cursor
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
        while len(candidates) <= limit:
            filters = [Device.retired_at.is_(None)]
            if after_id is not None:
                filters.append(Device.id > after_id)
            device_rows = (
                await session.execute(
                    select(Device, latest_sessions.c.last_seen_at)
                    .outerjoin(
                        latest_sessions,
                        and_(
                            Device.id == latest_sessions.c.device_id,
                            latest_sessions.c.session_rank == 1,
                        ),
                    )
                    .where(*filters)
                    .order_by(Device.id)
                    .limit(_NETWORK_IDENTITY_CHUNK_SIZE)
                )
            ).all()
            if not device_rows:
                break
            device_ids = [device.id for device, _ in device_rows]
            current_rows = (
                await session.execute(
                    select(ContextCurrent.device_id, ContextSnapshot)
                    .join(ContextSnapshot, ContextSnapshot.id == ContextCurrent.snapshot_id)
                    .where(
                        ContextCurrent.device_id.in_(device_ids),
                        ContextCurrent.profile.in_(_SAFE_SERVICE_PROFILES),
                    )
                )
            ).all()
            current_by_device: dict[UUID, dict[str, ContextSnapshot]] = {}
            for device_id, snapshot in current_rows:
                current_by_device.setdefault(device_id, {})[snapshot.profile] = snapshot
            for device, last_seen_at in device_rows:
                snapshots = current_by_device.get(device.id, {})
                safe_snapshots = {
                    profile: snapshot
                    for profile, snapshot in snapshots.items()
                    if snapshot_projection(snapshot) is not None
                }
                baseline = safe_snapshots.get("baseline_v1")
                if baseline is None:
                    continue
                mac_keys = baseline_interface_mac_keys(baseline)
                if not mac_keys:
                    continue
                candidates.append(
                    AgentNetworkIdentity(
                        id=device.id,
                        device_identifier=device.device_identifier,
                        display_name=device.display_name or device.device_identifier,
                        last_seen_at=_aware_timestamp(last_seen_at),
                        baseline_collected_at=_aware_timestamp(baseline.collected_at),
                        profiles=[
                            AgentNetworkProfile(
                                profile=profile,
                                collected_at=_aware_timestamp(snapshot.collected_at),
                            )
                            for profile, snapshot in sorted(safe_snapshots.items())
                        ],
                        baseline_mac_keys=list(mac_keys),
                    )
                )
                if len(candidates) > limit:
                    break
            if len(candidates) > limit or len(device_rows) < _NETWORK_IDENTITY_CHUNK_SIZE:
                break
            after_id = device_rows[-1][0].id
    next_cursor = str(candidates[limit - 1].id) if len(candidates) > limit else None
    return {
        "data": [candidate.model_dump(mode="json") for candidate in candidates[:limit]],
        "next_cursor": next_cursor,
    }


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
