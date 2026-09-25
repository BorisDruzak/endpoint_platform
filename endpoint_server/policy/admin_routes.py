"""Bounded Console authoring and assignment of Endpoint Policy versions."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_contracts.browser_status import BrowserFamilyStatusV1
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.db.models import Device

from .browser_status import load_browser_status
from .compliance import derive_browser_compliance
from .models import PolicyAssignment, PolicyDefinition, PolicyDeviceState, PolicyVersion
from .service import (
    PolicyNotFound,
    assign_default_policy,
    assign_device_policy,
    create_policy_version,
    resolve_effective_policy,
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


class PolicySummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: PolicySummary


class PolicyVersionCreated(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: UUID
    version_id: UUID
    policy_version: int
    digest: str


class PolicyVersionCreatedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: PolicyVersionCreated


class PolicyVersionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version_id: UUID
    policy_version: int
    digest: str
    created_at: datetime


class PolicyVersionPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: list[PolicyVersionSummary]
    total: int
    limit: int
    offset: int


class PolicyVersionDetail(PolicyVersionSummary):
    policy: EndpointPolicyV1


class PolicyVersionDetailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: PolicyVersionDetail


class PolicyAssignmentView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: str
    device_id: UUID | None
    policy_version_id: UUID
    assigned_at: datetime


class PolicyAssignmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: PolicyAssignmentView


class PolicyAssignmentCurrentView(PolicyAssignmentView):
    policy_id: UUID
    policy_version: int
    policy_name: str


class PolicyAssignmentCurrentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: PolicyAssignmentCurrentView | None


class ConsoleBrowserStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    browser_family: Literal["chrome", "yandex"]
    browser_state: Literal["DETECTED", "ABSENT", "UNKNOWN"] | None
    running_state: Literal["RUNNING", "CLOSED", "UNKNOWN"] | None
    policy_owner: Literal["ENDPOINT", "EXTERNAL", "NONE", "CONFLICT", "UNKNOWN"] | None
    installation_policy_state: Literal["APPLIED", "NOT_APPLIED", "CONFLICT", "UNKNOWN"] | None
    effective_policy_state: Literal["APPLIED", "NOT_APPLIED", "UNKNOWN"]
    native_host_state: Literal["READY", "MISSING", "UNKNOWN"] | None
    extension_version: str | None
    extension_install_type: Literal["ADMIN", "OTHER", "UNKNOWN"] | None
    extension_last_seen_at: datetime | None
    last_running_at: datetime | None
    compliance_state: Literal["NOT_APPLICABLE", "UNKNOWN", "NEVER_SEEN", "ACTIVE", "STALE", "ERROR"]
    reason: str | None


class ConsolePolicyDeviceStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: UUID
    policy_version: int
    policy_version_id: UUID
    browser_required: bool
    deployment_mode: Literal["agent_managed", "external_managed"]
    delivery_status: Literal["PENDING", "APPLIED", "STALE", "UNSUPPORTED", "ERROR"]
    acknowledged_at: datetime | None
    browser_compliance: Literal["COMPLIANT", "PARTIAL", "NON_COMPLIANT", "STALE", "UNSUPPORTED"]
    observed_at: datetime | None
    browsers: list[ConsoleBrowserStatus] = Field(min_length=2, max_length=2)


class ConsolePolicyDeviceStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: ConsolePolicyDeviceStatus | None


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


@router.get("/{policy_id}", response_model=PolicySummaryResponse)
async def read_policy_summary(
    policy_id: UUID,
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> PolicySummaryResponse:
    _require_enabled(request)
    async with request.app.state.session_provider() as session:
        row = await session.get(PolicyDefinition, policy_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Политика не найдена")
        count = await session.scalar(select(func.count()).select_from(PolicyVersion).where(
            PolicyVersion.definition_id == policy_id,
        )) or 0
        return PolicySummaryResponse(data=PolicySummary(
            id=row.id, name=row.name, created_at=row.created_at,
            versions_total=count,
        ))


@router.get("/{policy_id}/versions", response_model=PolicyVersionPageResponse)
async def list_policy_versions(
    policy_id: UUID,
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> PolicyVersionPageResponse:
    _require_enabled(request)
    async with request.app.state.session_provider() as session:
        if await session.get(PolicyDefinition, policy_id) is None:
            raise HTTPException(status_code=404, detail="Политика не найдена")
        total = await session.scalar(select(func.count()).select_from(PolicyVersion).where(
            PolicyVersion.definition_id == policy_id,
        )) or 0
        rows = (await session.scalars(
            select(PolicyVersion).where(PolicyVersion.definition_id == policy_id)
            .order_by(PolicyVersion.version.desc()).limit(limit).offset(offset)
        )).all()
    return PolicyVersionPageResponse(
        data=[PolicyVersionSummary(
            version_id=row.id, policy_version=row.version,
            digest=row.digest, created_at=row.created_at,
        ) for row in rows],
        total=total, limit=limit, offset=offset,
    )


@router.get("/{policy_id}/versions/{version_id}", response_model=PolicyVersionDetailResponse)
async def read_policy_version(
    policy_id: UUID,
    version_id: UUID,
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> PolicyVersionDetailResponse:
    _require_enabled(request)
    async with request.app.state.session_provider() as session:
        row = await session.get(PolicyVersion, version_id)
        if row is None or row.definition_id != policy_id:
            raise HTTPException(status_code=404, detail="Версия политики не найдена")
        return PolicyVersionDetailResponse(data=PolicyVersionDetail(
            version_id=row.id, policy_version=row.version,
            digest=row.digest, created_at=row.created_at,
            policy=EndpointPolicyV1.model_validate(row.document),
        ))


@router.get("/assignments/default", response_model=PolicyAssignmentCurrentResponse)
async def read_default_assignment(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> PolicyAssignmentCurrentResponse:
    _require_enabled(request)
    async with request.app.state.session_provider() as session:
        current = (await session.execute(
            select(PolicyAssignment, PolicyVersion, PolicyDefinition)
            .join(PolicyVersion, PolicyAssignment.policy_version_id == PolicyVersion.id)
            .join(PolicyDefinition, PolicyVersion.definition_id == PolicyDefinition.id)
            .where(PolicyAssignment.scope == "default")
        )).one_or_none()
        if current is None:
            return PolicyAssignmentCurrentResponse(data=None)
        assignment, version, definition = current
        return PolicyAssignmentCurrentResponse(data=PolicyAssignmentCurrentView(
            scope=assignment.scope, device_id=assignment.device_id,
            policy_version_id=assignment.policy_version_id,
            assigned_at=assignment.assigned_at,
            policy_id=definition.id, policy_version=version.version,
            policy_name=definition.name,
        ))


@router.get("/devices/{device_id}/status", response_model=ConsolePolicyDeviceStatusResponse)
async def device_policy_status(
    device_id: UUID,
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> ConsolePolicyDeviceStatusResponse:
    """Project current policy and browser facts without trusting Agent compliance."""
    _require_enabled(request)
    async with request.app.state.session_provider() as session:
        device = await session.get(Device, device_id)
        if device is None or device.retired_at is not None:
            raise HTTPException(status_code=404, detail="Устройство не найдено")
        version = await resolve_effective_policy(session, device_id)
        if version is None:
            return ConsolePolicyDeviceStatusResponse(data=None)
        policy = EndpointPolicyV1.model_validate(version.document)
        state = await session.scalar(select(PolicyDeviceState).where(
            PolicyDeviceState.device_id == device_id,
        ))
        report = await load_browser_status(session, device_id)
    connection = await request.app.state.gateway_connection_registry.get(device_id)
    delivery_status: Literal["PENDING", "APPLIED", "STALE", "UNSUPPORTED", "ERROR"] = "PENDING"
    acknowledged_at = None
    if state is not None:
        delivery_status = state.status
        acknowledged_at = state.acknowledged_at
        if state.policy_version_id != version.id or state.policy_digest != version.digest:
            delivery_status = "STALE"
    browser_status = delivery_status
    if connection is None and browser_status == "APPLIED":
        browser_status = "STALE"
    elif connection is not None and "endpoint.browser-status.v1" not in connection.protocol_features:
        browser_status = "UNSUPPORTED"
    compliance = derive_browser_compliance(policy, browser_status, report, now=datetime.now(UTC))
    facts: dict[str, BrowserFamilyStatusV1] = (
        {item.browser_family: item for item in report.browsers} if report is not None else {}
    )
    browsers = []
    for item in compliance.browsers:
        fact = facts.get(item.browser_family)
        browsers.append(ConsoleBrowserStatus(
            browser_family=item.browser_family,
            browser_state=fact.browser_state if fact else None,
            running_state=fact.running_state if fact else None,
            policy_owner=fact.policy_owner if fact else None,
            installation_policy_state=fact.installation_policy_state if fact else None,
            effective_policy_state=item.effective_policy_state,
            native_host_state=fact.native_host_state if fact else None,
            extension_version=fact.extension_version if fact else None,
            extension_install_type=fact.extension_install_type if fact else None,
            extension_last_seen_at=fact.extension_last_seen_at if fact else None,
            last_running_at=fact.last_running_at if fact else None,
            compliance_state=item.state,
            reason=item.reason,
        ))
    return ConsolePolicyDeviceStatusResponse(data=ConsolePolicyDeviceStatus(
        policy_id=policy.policy_id, policy_version=policy.policy_version,
        policy_version_id=version.id,
        browser_required=policy.browser_sensor.required,
        deployment_mode=policy.browser_sensor.deployment_mode,
        delivery_status=delivery_status,
        acknowledged_at=acknowledged_at,
        browser_compliance=compliance.overall,
        observed_at=report.observed_at if report else None,
        browsers=browsers,
    ))


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
