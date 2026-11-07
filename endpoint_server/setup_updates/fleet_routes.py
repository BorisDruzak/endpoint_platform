"""Console-only full Setup fleet policy, preview and persisted safe decisions."""
from collections import Counter
from types import SimpleNamespace
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import select

from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin, require_admin_update_scope
from endpoint_server.db.models import Device
from .models import SetupFleetPolicy, SetupFleetDecision, SetupRelease
from .policy import (FleetPolicyUpdate, update_policy, qualifications, qualify_release, active_chain_devices,
                     load_device_facts, evaluate_device)
from .routes import mutate_admin
from .service import now_utc

router = APIRouter(prefix='/api/admin/setup-updates/fleet', tags=['admin-setup-updates'])


class FleetQualificationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    release_id: UUID
    evidence_assignment_id: UUID


@router.post('/qualifications')
async def qualify(body: FleetQualificationRequest, request: Request,
                  principal: Annotated[AdminPrincipal, Depends(require_admin_update_scope)]):
    async def operation(session):
        row = await qualify_release(session, body.release_id, body.evidence_assignment_id,
            actor=principal.user.id, request_id=audit_request_id(request))
        return {'data': {key: getattr(row, key) for key in ('id', 'release_id', 'source_foundation',
            'evidence_assignment_id', 'qualified_at', 'expires_at')}}
    return await mutate_admin(request, principal, operation)


def policy_data(row):
    if row is None:
        return dict(revision=0, enabled=False, release_id=None, scope='all_active', device_ids=[],
            max_parallel=1, reason='', updated_at=None, safe_code=None)
    return {key: getattr(row, key) for key in ('revision', 'enabled', 'release_id', 'scope', 'device_ids',
        'max_parallel', 'reason', 'updated_at', 'safe_code')}


@router.get('')
async def fleet_status(request: Request, _: Annotated[AdminPrincipal, Depends(require_admin)]):
    now = now_utc()
    async with request.app.state.session_provider() as session:
        row = await session.scalar(select(SetupFleetPolicy))
        releases = (await session.scalars(select(SetupRelease).order_by(SetupRelease.created_at.desc()).limit(100))).all()
        qualified = {}
        for release in releases:
            items = await qualifications(session, release.id, now=now)
            qualified[str(release.id)] = [dict(source_foundation=q.source_foundation,
                expires_at=q.expires_at, evidence_assignment_id=q.evidence_assignment_id) for q in items]
        decisions = []
        if row:
            decisions = (await session.execute(select(SetupFleetDecision, Device.display_name)
                .join(Device, Device.id == SetupFleetDecision.device_id)
                .where(SetupFleetDecision.policy_id == row.id)
                .order_by(SetupFleetDecision.evaluated_at.desc()).limit(100))).all()
        return dict(data=policy_data(row), qualifications=qualified, active_chains=len(await active_chain_devices(session)),
            decisions=[dict(device_id=d.device_id, display_name=name, policy_revision=d.policy_revision,
                release_id=d.release_id, status=d.status, safe_code=d.safe_code, job_id=d.job_id,
                evaluated_at=d.evaluated_at) for d, name in decisions])


@router.put('')
async def change_policy(body: FleetPolicyUpdate, request: Request,
                        principal: Annotated[AdminPrincipal, Depends(require_admin_update_scope)]):
    async def operation(session):
        row = await update_policy(session, body, actor=principal.user.id, request_id=audit_request_id(request))
        return {'data': policy_data(row)}
    return await mutate_admin(request, principal, operation)


class FleetPreviewRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    release_id: UUID
    scope: str = Field(pattern='^(all_active|selected)$', default='all_active')
    device_ids: list[UUID] = Field(default_factory=list, max_length=500)
    max_parallel: int = Field(default=1, ge=1, le=2)


@router.post('/preview')
async def preview(body: FleetPreviewRequest, request: Request,
                  _: Annotated[AdminPrincipal, Depends(require_admin)]):
    # POST carries a bounded draft, with existing cookie/CSRF protection. It is
    # read-only and does not insert a policy, qualification, decision or job.
    now = now_utc()
    async with request.app.state.session_provider() as session:
        release = await session.get(SetupRelease, body.release_id)
        policy = SimpleNamespace(enabled=True, scope=body.scope, device_ids=[str(i) for i in body.device_ids])
        query = select(Device).where(Device.retired_at.is_(None)).order_by(Device.id)
        if body.scope == 'selected':
            query = query.where(Device.id.in_(body.device_ids))
        devices = (await session.scalars(query.limit(501))).all()
        data, counts = [], Counter()
        for device in devices[:500]:
            facts = await load_device_facts(session, device.id, body.release_id, now=now)
            result = evaluate_device(policy, release, facts, now=now)
            counts[result.status] += 1
            data.append(dict(device_id=device.id, display_name=device.display_name,
                status=result.status, safe_code=result.code))
        active = len(await active_chain_devices(session))
        return dict(read_only=True, counts=counts, evaluated_count=len(data), truncated=len(devices)>500,
            active_chains=active, available_slots=max(0, body.max_parallel-active), data=data)
