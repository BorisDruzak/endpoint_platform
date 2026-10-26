"""Independent, explicitly authorized DLP views over the existing ledgers."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import func, select
from endpoint_contracts.endpoint_policy import BrowserSensorPolicyV1, DlpPolicyV1, EndpointPolicyV1, EventRetentionPolicyV1

from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.employee_sessions import EmployeePrincipal, require_scoped_role
from endpoint_server.db.models import Device
from endpoint_server.policy.models import PolicyDefinition, PolicySensorHealthCurrent, PolicyVersion
from .admin_routes import (
    ConsoleSecurityEventDetailResponse, ConsoleSecurityEventPage,
    list_security_events, security_event_detail,
)


router = APIRouter(prefix="/api/dlp", tags=["dlp"])
_officer = require_scoped_role("dlp_officer")
Officer = Annotated[EmployeePrincipal, Depends(_officer)]


async def _audit(request: Request, principal: EmployeePrincipal, resource: str, count: int) -> None:
    async with request.app.state.session_provider() as session:
        await append_audit_event(
            session, actor_kind="employee", actor_identifier=str(principal.identity.person_id),
            action="dlp.read", object_kind=resource, object_identifier=None,
            request_id=audit_request_id(request), details={"returned_count": count},
        )
        await session.commit()


def _headers(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"


@router.get("/events", response_model=ConsoleSecurityEventPage)
async def events(
    request: Request, response: Response, principal: Officer,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    since: datetime | None = None, until: datetime | None = None,
    device_id: UUID | None = None,
    user_login: Annotated[str | None, Query(max_length=256)] = None,
    channel: Literal["USB", "PRINT", "BROWSER"] | None = None,
    event_type: Literal["USB_DEVICE_CONNECTED", "USB_DEVICE_DISCONNECTED", "PRINT_JOB", "BROWSER_UPLOAD", "BROWSER_PASTE"] | None = None,
    severity: Literal["INFO"] | None = None,
    domain: Annotated[str | None, Query(max_length=253)] = None,
) -> ConsoleSecurityEventPage:
    # The projections are shared; each HTTP realm supplies its own authority.
    page = await list_security_events(
        request, limit=limit, offset=offset, since=since, until=until,
        device_id=device_id, user_login=user_login, channel=channel,
        event_type=event_type, severity=severity, domain=domain,
    )
    await _audit(request, principal, "security_events", len(page.data))
    _headers(response)
    return page


@router.get("/events/{event_id}", response_model=ConsoleSecurityEventDetailResponse)
async def event_detail(event_id: UUID, request: Request, response: Response, principal: Officer):
    result = await security_event_detail(event_id, request)
    await _audit(request, principal, "security_event", 1)
    _headers(response)
    return result


class DLPPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    name: str
    created_at: datetime
    versions_total: int


class DLPPolicyPage(BaseModel):
    data: list[DLPPolicy]
    total: int
    limit: int
    offset: int


@router.get("/policies", response_model=DLPPolicyPage)
async def policies(
    request: Request, response: Response, principal: Officer,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
):
    if not request.app.state.settings.endpoint_policy_enabled:
        raise HTTPException(404, "Policy service is disabled")
    async with request.app.state.session_provider() as session:
        total = await session.scalar(select(func.count()).select_from(PolicyDefinition)) or 0
        rows = (await session.scalars(select(PolicyDefinition).order_by(
            PolicyDefinition.created_at.desc(), PolicyDefinition.id.desc(),
        ).limit(limit).offset(offset))).all()
        counts = dict((await session.execute(select(
            PolicyVersion.definition_id, func.count(),
        ).where(PolicyVersion.definition_id.in_([row.id for row in rows])).group_by(
            PolicyVersion.definition_id,
        ))).all()) if rows else {}
    result = DLPPolicyPage(data=[DLPPolicy(
        id=row.id, name=row.name, created_at=row.created_at, versions_total=counts.get(row.id, 0),
    ) for row in rows], total=total, limit=limit, offset=offset)
    await _audit(request, principal, "dlp_policies", len(rows))
    _headers(response)
    return result


class DLPVersionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version_id: UUID
    policy_version: int
    digest: str
    created_at: datetime


class DLPVersionPage(BaseModel):
    data: list[DLPVersionSummary]
    total: int
    limit: int
    offset: int


class DLPPolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["endpoint_policy_v1"]
    policy_id: UUID
    policy_version: int
    dlp: DlpPolicyV1
    browser_sensor: BrowserSensorPolicyV1
    event_retention: EventRetentionPolicyV1


class DLPVersionDetail(DLPVersionSummary):
    policy: DLPPolicyDocument


class DLPVersionResponse(BaseModel):
    data: DLPVersionDetail


def _version(row: PolicyVersion) -> dict:
    return dict(version_id=row.id, policy_version=row.version, digest=row.digest, created_at=row.created_at)


@router.get("/policies/{policy_id}/versions", response_model=DLPVersionPage)
async def policy_versions(
    policy_id: UUID, request: Request, response: Response, principal: Officer,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
):
    async with request.app.state.session_provider() as session:
        if await session.get(PolicyDefinition, policy_id) is None:
            raise HTTPException(404, "Policy not found")
        total = await session.scalar(select(func.count()).select_from(PolicyVersion).where(PolicyVersion.definition_id == policy_id)) or 0
        rows = (await session.scalars(select(PolicyVersion).where(PolicyVersion.definition_id == policy_id).order_by(PolicyVersion.version.desc()).limit(limit).offset(offset))).all()
    await _audit(request, principal, "dlp_policy_versions", len(rows))
    _headers(response)
    return DLPVersionPage(data=[DLPVersionSummary(**_version(row)) for row in rows], total=total, limit=limit, offset=offset)


@router.get("/policies/{policy_id}/versions/{version_id}", response_model=DLPVersionResponse)
async def policy_version_detail(policy_id: UUID, version_id: UUID, request: Request, response: Response, principal: Officer):
    async with request.app.state.session_provider() as session:
        row = await session.get(PolicyVersion, version_id)
        if row is None or row.definition_id != policy_id:
            raise HTTPException(404, "Policy version not found")
        try:
            validated = EndpointPolicyV1.model_validate(row.document)
        except ValidationError:
            raise HTTPException(409, "Stored policy validation failed") from None
        document = DLPPolicyDocument(
            schema_version=validated.schema_version, policy_id=validated.policy_id,
            policy_version=validated.policy_version, dlp=validated.dlp,
            browser_sensor=validated.browser_sensor, event_retention=validated.event_retention,
        )
        result = DLPVersionResponse(data=DLPVersionDetail(**_version(row), policy=document))
    await _audit(request, principal, "dlp_policy_version", 1)
    _headers(response)
    return result


class DLPSensor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: UUID
    device_name: str
    observed_at: datetime
    activity_listener_state: str
    security_spool_state: str
    usb_source_state: str
    print_source_state: str


class DLPSensorPage(BaseModel):
    data: list[DLPSensor]
    total: int
    limit: int
    offset: int


@router.get("/sensors", response_model=DLPSensorPage)
async def sensors(
    request: Request, response: Response, principal: Officer,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
):
    async with request.app.state.session_provider() as session:
        base = select(PolicySensorHealthCurrent, Device).join(Device, Device.id == PolicySensorHealthCurrent.device_id).where(Device.retired_at.is_(None))
        total = await session.scalar(select(func.count()).select_from(base.subquery())) or 0
        rows = (await session.execute(base.order_by(PolicySensorHealthCurrent.device_id).limit(limit).offset(offset))).all()
    result = DLPSensorPage(data=[DLPSensor(
        device_id=device.id, device_name=device.display_name or device.device_identifier,
        observed_at=health.observed_at, activity_listener_state=health.activity_listener_state,
        security_spool_state=health.security_spool_state, usb_source_state=health.usb_source_state,
        print_source_state=health.print_source_state,
    ) for health, device in rows], total=total, limit=limit, offset=offset)
    await _audit(request, principal, "dlp_sensors", len(rows))
    _headers(response)
    return result
