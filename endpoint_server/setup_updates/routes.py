"""Authenticated, device-bound full Setup API; no arbitrary execution parameters."""
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse
from sqlalchemy import select, text

from endpoint_contracts.setup_updates import (
    ACTIVE_SETUP_PHASES, SetupReleaseManifestV1, SetupAssignmentRequestV1,
    SetupClientHelloV1, SetupProgressV1, SetupRecommendationV1,
)
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.auth.admin_sessions import (
    AdminPrincipal, require_admin, require_admin_update_scope, load_update_admin_in_transaction,
)
from endpoint_server.db.models import AdminUser, AdminSession
from endpoint_server.updates.agent_routes import _authenticate_device, _artifact_path, _revalidate_device_principal
from .models import SetupRelease, SetupAssignment, SetupClientPresence, SetupPreparation
from .preparation import request_setup, cancel_preparation
from .service import (SetupConflict, register_release, assign_setup, cancel_assignment,
                      record_presence, record_progress, release_manifest, qualified_presence)

admin_router = APIRouter(prefix='/api/admin/setup-updates', tags=['admin-setup-updates'])
agent_router = APIRouter(prefix='/agent/v1/setup-updates', tags=['agent-setup-updates'])


def assignment_data(job):
    if isinstance(job, SetupPreparation):
        return {key: getattr(job, key) for key in ('id', 'device_id', 'release_id', 'status', 'reason',
            'updated_at', 'safe_code', 'bridge_rollout_id', 'return_rollout_id', 'assignment_id')}
    return {key: getattr(job, key) for key in (
        'id', 'device_id', 'release_id', 'status', 'reason', 'assigned_at', 'updated_at',
        'started_at', 'finished_at', 'safe_code', 'last_report')}


async def revalidate_admin(request, session, principal):
    # Refresh and lock the same persisted identity after any device/domain wait.
    await session.scalar(select(AdminUser).where(AdminUser.id == principal.user.id)
                         .with_for_update().execution_options(populate_existing=True))
    await session.scalar(select(AdminSession).where(AdminSession.id == principal.session.id)
                         .with_for_update().execution_options(populate_existing=True))
    fresh = await load_update_admin_in_transaction(request, session)
    if fresh.user.id != principal.user.id or fresh.session.id != principal.session.id:
        raise HTTPException(403, 'Update administrator changed')


async def mutate_admin(request, principal, operation):
    async with request.app.state.session_provider() as session:
        try:
            if session.bind.dialect.name == 'postgresql':
                await session.execute(text("SET LOCAL lock_timeout = '5s'"))
                await session.execute(text("SET LOCAL statement_timeout = '10s'"))
            result = await operation(session)
            await revalidate_admin(request, session, principal)
            await session.commit()
            return result
        except SetupConflict as error:
            await session.rollback()
            raise HTTPException(409, 'Full Setup operation conflicts with current state') from error
        except ValueError as error:
            await session.rollback()
            raise HTTPException(422, 'Invalid full Setup operation') from error
        except Exception:
            await session.rollback()
            raise


@admin_router.get('/releases')
async def releases(request: Request, _: Annotated[AdminPrincipal, Depends(require_admin)]):
    async with request.app.state.session_provider() as session:
        rows = (await session.scalars(select(SetupRelease).order_by(SetupRelease.created_at.desc()).limit(100))).all()
        return {'data': [{'id': row.id, **release_manifest(row).model_dump()} for row in rows]}


@admin_router.post('/releases', status_code=201)
async def publish_release(body: SetupReleaseManifestV1, request: Request,
                          principal: Annotated[AdminPrincipal, Depends(require_admin_update_scope)]):
    async def operation(session):
        row = await register_release(session, body, artifact_root=request.app.state.settings.artifact_root,
                                     actor=principal.user.id, request_id=audit_request_id(request))
        return {'data': {'id': row.id, **release_manifest(row).model_dump()}}
    return await mutate_admin(request, principal, operation)


@admin_router.get('/devices/{device_id}')
async def device_updates(device_id: UUID, request: Request,
                         _: Annotated[AdminPrincipal, Depends(require_admin)]):
    async with request.app.state.session_provider() as session:
        presence = await session.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == device_id))
        jobs = (await session.scalars(select(SetupAssignment).where(SetupAssignment.device_id == device_id)
                   .order_by(SetupAssignment.assigned_at.desc()).limit(50))).all()
        preps = (await session.scalars(select(SetupPreparation).where(SetupPreparation.device_id == device_id,
            SetupPreparation.status != 'completed').order_by(SetupPreparation.created_at.desc()).limit(50))).all()
        return {'client': None if presence is None else {key: getattr(presence, key) for key in (
            'client_version', 'foundation_version', 'core_version', 'ready', 'safe_code', 'last_seen_at')},
            'data': [assignment_data(row) for row in preps + list(jobs)]}


@admin_router.post('/assignments', status_code=201)
async def assign(body: SetupAssignmentRequestV1, request: Request,
                 principal: Annotated[AdminPrincipal, Depends(require_admin_update_scope)]):
    async def operation(session):
        job = await request_setup(session, body.device_id, body.release_id, body.reason,
                                  actor=principal.user.id, request_id=audit_request_id(request))
        return {'data': assignment_data(job)}
    return await mutate_admin(request, principal, operation)


@admin_router.post('/assignments/{assignment_id}/cancel')
async def cancel(assignment_id: UUID, request: Request,
                 principal: Annotated[AdminPrincipal, Depends(require_admin_update_scope)]):
    async def operation(session):
        actual = await session.get(SetupAssignment, assignment_id)
        cancel_fn = cancel_assignment if actual else cancel_preparation
        job = await cancel_fn(session, assignment_id, actor=principal.user.id, request_id=audit_request_id(request))
        return {'data': assignment_data(job)}
    return await mutate_admin(request, principal, operation)


@agent_router.post('/hello')
async def hello(body: SetupClientHelloV1, request: Request):
    async with request.app.state.session_provider() as session:
        principal = await _authenticate_device(session, request)
        await record_presence(session, principal.device.id, body)
        await _revalidate_device_principal(session, request, principal)
        await session.commit()
        return {'device_id': principal.device.id, 'client_version': body.client_version}


@agent_router.get('/recommendation', response_model=None)
async def recommendation(request: Request):
    async with request.app.state.session_provider() as session:
        principal = await _authenticate_device(session, request)
        presence = await session.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == principal.device.id))
        if not qualified_presence(presence, datetime.now(UTC)):
            return Response(status_code=204)
        row = (await session.execute(select(SetupAssignment, SetupRelease)
            .join(SetupRelease, SetupRelease.id == SetupAssignment.release_id)
            .where(SetupAssignment.device_id == principal.device.id, SetupAssignment.status.in_(ACTIVE_SETUP_PHASES))
            .order_by(SetupAssignment.assigned_at).limit(1))).first()
        if row is None:
            return Response(status_code=204)
        job, release = row
        return SetupRecommendationV1(assignment_id=job.id, device_id=principal.device.id,
                                      release=release_manifest(release))


@agent_router.get('/assignments/{assignment_id}/artifact', response_model=None)
async def artifact(assignment_id: UUID, request: Request):
    async with request.app.state.session_provider() as session:
        principal = await _authenticate_device(session, request)
        row = (await session.execute(select(SetupAssignment, SetupRelease)
            .join(SetupRelease, SetupRelease.id == SetupAssignment.release_id)
            .where(SetupAssignment.id == assignment_id, SetupAssignment.device_id == principal.device.id,
                   SetupAssignment.status.in_(['assigned', 'downloading', 'verified'])))).first()
        if row is None:
            raise HTTPException(404, 'Setup operation unavailable')
        _, release = row
        path = _artifact_path(request.app.state.settings.artifact_root, release.artifact_name)
        if path is None or path.stat().st_size != release.size:
            raise HTTPException(404, 'Setup artifact unavailable')
    return FileResponse(path, media_type='application/octet-stream')


@agent_router.post('/assignments/{assignment_id}/progress')
async def progress(assignment_id: UUID, body: SetupProgressV1, request: Request):
    async with request.app.state.session_provider() as session:
        principal = await _authenticate_device(session, request)
        try:
            job = await record_progress(session, principal.device.id, assignment_id, body)
            await _revalidate_device_principal(session, request, principal)
            await session.commit()
        except SetupConflict as error:
            await session.rollback()
            raise HTTPException(409, 'Setup progress conflicts with current state') from error
        except Exception:
            await session.rollback()
            raise
        return {'assignment_id': job.id, 'phase': job.status, 'attempt_id': job.attempt_id}


@agent_router.get('/assignments/{assignment_id}/status')
async def assignment_status(assignment_id: UUID, request: Request):
    async with request.app.state.session_provider() as session:
        principal = await _authenticate_device(session, request)
        job = await session.scalar(select(SetupAssignment).where(
            SetupAssignment.id == assignment_id, SetupAssignment.device_id == principal.device.id))
        if job is None:
            raise HTTPException(404, 'Setup operation unavailable')
        return {'assignment_id': job.id, 'phase': job.status, 'attempt_id': job.attempt_id}
