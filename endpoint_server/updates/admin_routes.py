"""Authenticated administrator routes for immutable update rollouts."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select

from endpoint_contracts import UpdateBuildManifestV1, UpdateRolloutCreateV1
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.auth.admin_sessions import (
    AdminPrincipal,
    require_admin,
    require_admin_update_scope,
)
from endpoint_server.db.models import Device, UpdateBuild, UpdateRollout, UpdateTarget

from .errors import (
    UpdateConflict,
    UpdateError,
    UpdateNotFound,
    UpdateStateError,
    UpdateValidationError,
)
from .service import (
    activate_rollout,
    complete_rollout,
    create_rollback_rollout,
    create_rollout,
    pause_rollout,
    register_build,
)


router = APIRouter(prefix="/api/admin/updates", tags=["admin-updates"])


class UpdateBuildResponse(BaseModel):
    """Public identity of one registered immutable build."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    build_identifier: str
    version: str
    platform: Literal["linux_amd64", "windows_amd64"]
    channel: Literal["stable", "canary"]


class UpdateRolloutResponse(BaseModel):
    """Bounded lifecycle summary returned by administrator mutations."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    rollout_identifier: str
    build_id: UUID
    mode: Literal["canary", "bulk", "rollback"]
    reason: str | None
    status: Literal["draft", "active", "paused", "completed", "cancelled"]
    started_at: datetime | None
    paused_at: datetime | None
    completed_at: datetime | None


def _build_response(build: UpdateBuild) -> UpdateBuildResponse:
    return UpdateBuildResponse(
        id=build.id,
        build_identifier=build.build_identifier,
        version=build.version,
        platform=build.platform,
        channel=build.channel,
    )


def _rollout_response(rollout: UpdateRollout) -> UpdateRolloutResponse:
    return UpdateRolloutResponse(
        id=rollout.id,
        rollout_identifier=rollout.rollout_identifier,
        build_id=rollout.build_id,
        mode=rollout.mode,
        reason=rollout.reason,
        status=rollout.status,
        started_at=rollout.started_at,
        paused_at=rollout.paused_at,
        completed_at=rollout.completed_at,
    )


def _safe_build(build: UpdateBuild) -> dict[str, object]:
    return {
        "id": str(build.id), "build_identifier": build.build_identifier,
        "version": build.version, "platform": build.platform, "channel": build.channel,
        "sha256": build.sha256_digest, "size": build.size,
        "artifact_name": build.artifact_name, "release_notes": build.release_notes,
        "created_at": build.created_at,
    }


def _safe_rollout(
    rollout: UpdateRollout, build: UpdateBuild, counts: dict[str, int]
) -> dict[str, object]:
    return {
        "id": str(rollout.id), "rollout_identifier": rollout.rollout_identifier,
        "build_id": str(build.id), "build_identifier": build.build_identifier,
        "version": build.version, "platform": build.platform,
        "mode": rollout.mode, "status": rollout.status, "reason": rollout.reason,
        "created_at": rollout.created_at, "started_at": rollout.started_at,
        "paused_at": rollout.paused_at, "completed_at": rollout.completed_at,
        "cancelled_at": rollout.cancelled_at, "counts": counts,
    }


async def _target_counts(session, rollout_ids: list[UUID]) -> dict[UUID, dict[str, int]]:
    if not rollout_ids:
        return {}
    rows = (await session.execute(
        select(UpdateTarget.rollout_id, UpdateTarget.status, func.count())
        .where(UpdateTarget.rollout_id.in_(rollout_ids))
        .group_by(UpdateTarget.rollout_id, UpdateTarget.status)
    )).all()
    counts: dict[UUID, dict[str, int]] = {rollout_id: {} for rollout_id in rollout_ids}
    for rollout_id, target_status, count in rows:
        counts[rollout_id][target_status] = count
    return counts


@router.get("/builds")
async def list_update_builds(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> dict[str, object]:
    async with request.app.state.session_provider() as session:
        total = await session.scalar(select(func.count()).select_from(UpdateBuild)) or 0
        builds = (await session.execute(
            select(UpdateBuild)
            .order_by(UpdateBuild.created_at.desc(), UpdateBuild.id.desc())
            .limit(limit).offset(offset)
        )).scalars().all()
    return {"data": [_safe_build(build) for build in builds], "total": total, "limit": limit, "offset": offset}


@router.get("/builds/{build_id}")
async def read_update_build(
    build_id: UUID,
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> dict[str, object]:
    async with request.app.state.session_provider() as session:
        build = await session.scalar(select(UpdateBuild).where(UpdateBuild.id == build_id))
    if build is None:
        raise HTTPException(status_code=404, detail="Релиз не найден")
    return {"data": _safe_build(build)}


@router.get("/rollouts")
async def list_update_rollouts(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    terminal: bool = False,
) -> dict[str, object]:
    filters = (UpdateRollout.status.in_(("completed", "cancelled")),) if terminal else ()
    async with request.app.state.session_provider() as session:
        total = await session.scalar(select(func.count()).select_from(UpdateRollout).where(*filters)) or 0
        rows = (await session.execute(
            select(UpdateRollout, UpdateBuild)
            .join(UpdateBuild, UpdateBuild.id == UpdateRollout.build_id)
            .where(*filters)
            .order_by(UpdateRollout.created_at.desc(), UpdateRollout.id.desc())
            .limit(limit).offset(offset)
        )).all()
        counts = await _target_counts(session, [rollout.id for rollout, _ in rows])
    return {
        "data": [_safe_rollout(rollout, build, counts.get(rollout.id, {})) for rollout, build in rows],
        "total": total, "limit": limit, "offset": offset,
    }


@router.get("/rollouts/{rollout_id}")
async def read_update_rollout(
    rollout_id: UUID,
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> dict[str, object]:
    async with request.app.state.session_provider() as session:
        row = (await session.execute(
            select(UpdateRollout, UpdateBuild)
            .join(UpdateBuild, UpdateBuild.id == UpdateRollout.build_id)
            .where(UpdateRollout.id == rollout_id)
        )).one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="Развёртывание не найдено")
        rollout, build = row
        counts = (await _target_counts(session, [rollout_id])).get(rollout_id, {})
        targets = (await session.execute(
            select(UpdateTarget, Device.display_name, Device.device_identifier)
            .join(Device, Device.id == UpdateTarget.device_id)
            .where(UpdateTarget.rollout_id == rollout_id)
            .order_by(UpdateTarget.assigned_at, UpdateTarget.id)
            .limit(limit).offset(offset)
        )).all()
    return {
        **_safe_rollout(rollout, build, counts),
        "targets_total": sum(counts.values()), "target_limit": limit, "target_offset": offset,
        "targets": [{
            "device_id": str(target.device_id),
            "device_name": name or identifier,
            "status": target.status, "assigned_at": target.assigned_at,
            "terminal_at": target.terminal_at, "safe_reason": target.safe_reason,
        } for target, name, identifier in targets],
    }


def _admin_error(error: UpdateError) -> HTTPException:
    if isinstance(error, UpdateNotFound):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Update resource not found",
        )
    if isinstance(error, UpdateValidationError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid update request",
        )
    if isinstance(error, (UpdateConflict, UpdateStateError)):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Update request conflicts with current state",
        )
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Update request rejected",
    )


async def _commit_mutation(session, operation):
    try:
        result = await operation
        await session.commit()
        return result
    except UpdateError as error:
        await session.rollback()
        raise _admin_error(error) from error
    except Exception:
        await session.rollback()
        raise


async def _build_id_by_identifier(session, build_identifier: str) -> UUID:
    build_id = await session.scalar(
        select(UpdateBuild.id).where(UpdateBuild.build_identifier == build_identifier)
    )
    if build_id is None:
        raise UpdateNotFound("update build not found")
    return build_id


@router.post(
    "/builds",
    status_code=status.HTTP_201_CREATED,
    response_model=UpdateBuildResponse,
)
async def create_update_build(
    body: UpdateBuildManifestV1,
    request: Request,
    principal: Annotated[
        AdminPrincipal,
        Depends(require_admin_update_scope),
    ],
) -> UpdateBuildResponse:
    """Register one immutable build under an explicitly scoped admin session."""
    async with request.app.state.session_provider() as session:
        build = await _commit_mutation(
            session,
            register_build(
                session,
                body,
                principal.user.id,
                audit_request_id(request),
            ),
        )
    return _build_response(build)


@router.post(
    "/rollouts",
    status_code=status.HTTP_201_CREATED,
    response_model=UpdateRolloutResponse,
)
async def create_update_rollout(
    body: UpdateRolloutCreateV1,
    request: Request,
    principal: Annotated[
        AdminPrincipal,
        Depends(require_admin_update_scope),
    ],
) -> UpdateRolloutResponse:
    """Create one active canary or bulk rollout."""
    async with request.app.state.session_provider() as session:
        try:
            build_id = await _build_id_by_identifier(
                session,
                body.build_identifier,
            )
            rollout = await _commit_mutation(
                session,
                create_rollout(
                    session,
                    build_id,
                    body.mode,
                    body.device_ids,
                    body.reason,
                    principal.user.id,
                    audit_request_id(request),
                ),
            )
        except UpdateError as error:
            await session.rollback()
            raise _admin_error(error) from error
    return _rollout_response(rollout)


async def _transition_rollout(
    rollout_id: UUID,
    request: Request,
    principal: AdminPrincipal,
    transition,
) -> UpdateRolloutResponse:
    if await request.body():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid update request",
        )
    async with request.app.state.session_provider() as session:
        rollout = await _commit_mutation(
            session,
            transition(
                session,
                rollout_id,
                principal.user.id,
                audit_request_id(request),
            ),
        )
    return _rollout_response(rollout)


@router.post(
    "/rollouts/{rollout_id}/activate",
    response_model=UpdateRolloutResponse,
)
async def activate_update_rollout(
    rollout_id: UUID,
    request: Request,
    principal: Annotated[
        AdminPrincipal,
        Depends(require_admin_update_scope),
    ],
) -> UpdateRolloutResponse:
    return await _transition_rollout(
        rollout_id,
        request,
        principal,
        activate_rollout,
    )


@router.post(
    "/rollouts/{rollout_id}/pause",
    response_model=UpdateRolloutResponse,
)
async def pause_update_rollout(
    rollout_id: UUID,
    request: Request,
    principal: Annotated[
        AdminPrincipal,
        Depends(require_admin_update_scope),
    ],
) -> UpdateRolloutResponse:
    return await _transition_rollout(
        rollout_id,
        request,
        principal,
        pause_rollout,
    )


@router.post(
    "/rollouts/{rollout_id}/complete",
    response_model=UpdateRolloutResponse,
)
async def complete_update_rollout(
    rollout_id: UUID,
    request: Request,
    principal: Annotated[
        AdminPrincipal,
        Depends(require_admin_update_scope),
    ],
) -> UpdateRolloutResponse:
    return await _transition_rollout(
        rollout_id,
        request,
        principal,
        complete_rollout,
    )


@router.post(
    "/rollouts/{triggering_rollout_id}/rollback",
    status_code=status.HTTP_201_CREATED,
    response_model=UpdateRolloutResponse,
)
async def create_update_rollback(
    triggering_rollout_id: UUID,
    body: UpdateRolloutCreateV1,
    request: Request,
    principal: Annotated[
        AdminPrincipal,
        Depends(require_admin_update_scope),
    ],
) -> UpdateRolloutResponse:
    """Create a new rollback rollout linked to one triggering rollout."""
    if body.mode != "rollback":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid update request",
        )
    async with request.app.state.session_provider() as session:
        try:
            build_id = await _build_id_by_identifier(
                session,
                body.build_identifier,
            )
            rollout = await _commit_mutation(
                session,
                create_rollback_rollout(
                    session,
                    triggering_rollout_id,
                    build_id,
                    body.device_ids,
                    body.reason or "",
                    principal.user.id,
                    audit_request_id(request),
                ),
            )
        except UpdateError as error:
            await session.rollback()
            raise _admin_error(error) from error
    return _rollout_response(rollout)


__all__ = ["router"]
