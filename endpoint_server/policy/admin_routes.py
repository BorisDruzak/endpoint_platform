"""Bounded Console authoring and assignment of Endpoint Policy versions."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.db.models import Device

from .models import PolicyDefinition, PolicyVersion
from .service import (
    PolicyNotFound,
    assign_default_policy,
    assign_device_policy,
    create_policy_version,
)


router = APIRouter(prefix="/api/admin/console/policies", tags=["admin-console-policy"])


class PolicyCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    policy: EndpointPolicyV1


class PolicyVersionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy: EndpointPolicyV1


class PolicyAssignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_version_id: UUID


class PolicySummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    name: str
    created_at: datetime
    versions_total: int


class PolicyPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: list[PolicySummary]
    total: int
    limit: int
    offset: int


class PolicyVersionCreated(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: UUID
    version_id: UUID
    policy_version: int
    digest: str


class PolicyVersionCreatedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: PolicyVersionCreated


class PolicyAssignmentView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: str
    device_id: UUID | None
    policy_version_id: UUID
    assigned_at: datetime


class PolicyAssignmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: PolicyAssignmentView


def _require_enabled(request: Request) -> None:
    if not request.app.state.settings.endpoint_policy_enabled:
        raise HTTPException(status_code=404, detail="Политики Endpoint отключены")


def _version_response(version: PolicyVersion) -> PolicyVersionCreatedResponse:
    return PolicyVersionCreatedResponse(data=PolicyVersionCreated(
        policy_id=version.definition_id,
        version_id=version.id,
        policy_version=version.version,
        digest=version.digest,
    ))


async def _audit(
    session, request: Request, principal: AdminPrincipal, *,
    action: str, object_kind: str, object_id: UUID, details: dict[str, object],
) -> None:
    await append_audit_event(
        session,
        actor_kind="admin",
        actor_identifier=str(principal.user.id),
        action=action,
        object_kind=object_kind,
        object_identifier=str(object_id),
        request_id=audit_request_id(request),
        details=details,
    )


@router.get("", response_model=PolicyPageResponse)
async def list_policies(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> PolicyPageResponse:
    _require_enabled(request)
    async with request.app.state.session_provider() as session:
        total = await session.scalar(select(func.count()).select_from(PolicyDefinition)) or 0
        rows = (await session.scalars(
            select(PolicyDefinition)
            .order_by(PolicyDefinition.created_at.desc(), PolicyDefinition.id.desc())
            .limit(limit).offset(offset)
        )).all()
        counts = {
            definition_id: count for definition_id, count in (await session.execute(
                select(PolicyVersion.definition_id, func.count())
                .where(PolicyVersion.definition_id.in_([row.id for row in rows]))
                .group_by(PolicyVersion.definition_id)
            )).all()
        } if rows else {}
    return PolicyPageResponse(
        data=[PolicySummary(
            id=row.id, name=row.name, created_at=row.created_at,
            versions_total=counts.get(row.id, 0),
        ) for row in rows],
        total=total, limit=limit, offset=offset,
    )


@router.post("", response_model=PolicyVersionCreatedResponse, status_code=201)
async def create_policy(
    body: PolicyCreateRequest,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> PolicyVersionCreatedResponse:
    _require_enabled(request)
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Название политики не задано")
    try:
        async with request.app.state.session_provider() as session:
            async with session.begin():
                definition = PolicyDefinition(id=body.policy.policy_id, name=name)
                session.add(definition)
                await session.flush()
                version = await create_policy_version(
                    session, definition.id, body.policy, actor_id=principal.user.id,
                )
                await _audit(
                    session, request, principal, action="policy.version.created",
                    object_kind="policy_version", object_id=version.id,
                    details={"policy_id": str(definition.id), "version": version.version},
                )
            return _version_response(version)
    except IntegrityError as error:
        raise HTTPException(status_code=409, detail="Политика уже существует") from error


@router.post("/{policy_id}/versions", response_model=PolicyVersionCreatedResponse, status_code=201)
async def add_policy_version(
    policy_id: UUID,
    body: PolicyVersionCreateRequest,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> PolicyVersionCreatedResponse:
    _require_enabled(request)
    try:
        async with request.app.state.session_provider() as session:
            async with session.begin():
                version = await create_policy_version(
                    session, policy_id, body.policy, actor_id=principal.user.id,
                )
                await _audit(
                    session, request, principal, action="policy.version.created",
                    object_kind="policy_version", object_id=version.id,
                    details={"policy_id": str(policy_id), "version": version.version},
                )
            return _version_response(version)
    except PolicyNotFound as error:
        raise HTTPException(status_code=404, detail="Политика не найдена") from error
    except (ValueError, IntegrityError) as error:
        raise HTTPException(status_code=409, detail="Версия политики недопустима") from error


async def _assign(
    request: Request, principal: AdminPrincipal, version_id: UUID,
    device_id: UUID | None,
) -> PolicyAssignmentResponse:
    _require_enabled(request)
    try:
        async with request.app.state.session_provider() as session:
            async with session.begin():
                if device_id is not None:
                    device = await session.get(Device, device_id)
                    if device is None:
                        raise HTTPException(status_code=404, detail="Устройство не найдено")
                    assignment = await assign_device_policy(
                        session, device_id, version_id, actor_id=principal.user.id,
                    )
                else:
                    assignment = await assign_default_policy(
                        session, version_id, actor_id=principal.user.id,
                    )
                await _audit(
                    session, request, principal,
                    action="policy.device.assigned" if device_id else "policy.default.assigned",
                    object_kind="device" if device_id else "policy_default",
                    object_id=device_id or version_id,
                    details={"policy_version_id": str(version_id)},
                )
            return PolicyAssignmentResponse(data=PolicyAssignmentView(
                scope=assignment.scope, device_id=assignment.device_id,
                policy_version_id=assignment.policy_version_id,
                assigned_at=assignment.assigned_at,
            ))
    except PolicyNotFound as error:
        raise HTTPException(status_code=404, detail="Версия политики не найдена") from error
    except IntegrityError as error:
        raise HTTPException(status_code=409, detail="Назначение политики конфликтует") from error


@router.put("/assignments/default", response_model=PolicyAssignmentResponse)
async def assign_default(
    body: PolicyAssignRequest,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> PolicyAssignmentResponse:
    return await _assign(request, principal, body.policy_version_id, None)


@router.put("/assignments/devices/{device_id}", response_model=PolicyAssignmentResponse)
async def assign_device(
    device_id: UUID,
    body: PolicyAssignRequest,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> PolicyAssignmentResponse:
    return await _assign(request, principal, body.policy_version_id, device_id)
