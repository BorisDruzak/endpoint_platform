"""Scoped assignment issuance and enrollment evidence for inventory."""

from datetime import UTC, datetime, timedelta
import hmac
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Security
from fastapi.security import HTTPBearer
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.scopes import (
    INVENTORY_INSTALLATION_ASSIGNMENTS_ISSUE_SCOPE,
    INVENTORY_INSTALLATION_RECEIPTS_READ_SCOPE,
    ServicePrincipal,
    require_service_scope,
)
from endpoint_server.db.models import (
    Device, DeviceInstance, DeviceSession, EnrollmentClaim, EnrollmentRequest, InventoryInstallationAssignment,
)

from .campaigns import hardware_fingerprint_digest, install_claim_session_digest
from .inventory_assignments import ASSIGNMENT_LIFETIME, INSTALLATION_ID_PATTERN, utc
from .requests import installation_id_digest


router = APIRouter(prefix="/api/v1/enrollment", tags=["inventory-installation"])
service_bearer = HTTPBearer(auto_error=False, scheme_name="ServiceBearer")
_SCOPE = INVENTORY_INSTALLATION_RECEIPTS_READ_SCOPE
_ISSUE_SCOPE = INVENTORY_INSTALLATION_ASSIGNMENTS_ISSUE_SCOPE
_PRESENCE_TTL = timedelta(seconds=90)
_NO_STORE = {"Cache-Control": "no-store"}


class InventoryInstallationLookup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    installation_id: SecretStr = Field(
        min_length=1,
        max_length=128,
        description="Private inventory installation ID containing the asset UUID, machine UUID and nonce.",
        json_schema_extra={"pattern": INSTALLATION_ID_PATTERN.pattern},
    )


class InventoryInstallationIssue(InventoryInstallationLookup):
    hardware_fingerprint: SecretStr = Field(min_length=1, max_length=256)
    platform: Literal["linux", "windows"]


class InventoryInstallationWindow(BaseModel):
    issued_at: AwareDatetime
    expires_at: AwareDatetime


class PendingInventoryInstallationReceipt(BaseModel):
    state: Literal["waiting_registration", "waiting_connection", "expired"]


class ConnectedInventoryInstallationReceipt(BaseModel):
    state: Literal["connected"]
    device_id: UUID
    registered_at: AwareDatetime
    heartbeat_at: AwareDatetime


class InvalidInventoryInstallationAssignment(BaseModel):
    detail: Literal["Invalid inventory installation assignment"]


def _conflict() -> HTTPException:
    return HTTPException(409, "Conflicting installation evidence", headers=_NO_STORE)


def _invalid() -> HTTPException:
    return HTTPException(422, "Invalid inventory installation assignment", headers=_NO_STORE)


def _installation_id(body: InventoryInstallationLookup) -> str:
    installation_id = body.installation_id.get_secret_value()
    if not INSTALLATION_ID_PATTERN.fullmatch(installation_id):
        raise _invalid()
    return installation_id


@router.post(
    "/installation-assignments",
    response_model=InventoryInstallationWindow,
    dependencies=[Security(service_bearer, scopes=[_ISSUE_SCOPE])],
    responses={
        401: {"description": "Service authentication failed"},
        403: {"description": "Service scope is insufficient"},
        409: {"description": "Installation assignment conflicts with existing authority"},
        422: {"description": "Invalid inventory installation assignment", "model": InvalidInventoryInstallationAssignment},
    },
    openapi_extra={"x-required-scopes": [_ISSUE_SCOPE]},
)
async def issue_inventory_installation(
    body: InventoryInstallationIssue,
    request: Request,
    response: Response,
    principal: Annotated[ServicePrincipal, Depends(require_service_scope(_ISSUE_SCOPE))],
) -> InventoryInstallationWindow:
    """Persist one assignment. Exact retries by its owner reuse the original window."""
    response.headers.update(_NO_STORE)
    pepper = request.app.state.settings.device_token_pepper
    digest = installation_id_digest(_installation_id(body), pepper)
    try:
        fingerprint = hardware_fingerprint_digest(
            body.hardware_fingerprint.get_secret_value(), pepper,
        )
    except ValueError:
        raise _invalid() from None
    now = datetime.now(UTC)
    async with request.app.state.session_provider() as session:
        inserted = (await session.execute(
            insert(InventoryInstallationAssignment)
            .values(
                installation_digest=digest, service_client_id=principal.client.id,
                fingerprint_digest=fingerprint, platform=body.platform,
                issued_at=now, expires_at=now + ASSIGNMENT_LIFETIME,
            )
            .on_conflict_do_nothing(index_elements=[InventoryInstallationAssignment.installation_digest])
            .returning(InventoryInstallationAssignment.installation_digest)
        )).scalar_one_or_none()
        assignment = (await session.execute(
            select(InventoryInstallationAssignment)
            .where(InventoryInstallationAssignment.installation_digest == digest)
        )).scalar_one()
        if (
            assignment.service_client_id != principal.client.id
            or assignment.platform != body.platform
            or not hmac.compare_digest(assignment.fingerprint_digest, fingerprint)
        ):
            raise _conflict()
        result = InventoryInstallationWindow(issued_at=utc(assignment.issued_at), expires_at=utc(assignment.expires_at))
        if inserted is not None:
            await append_audit_event(
                session, actor_kind="service", actor_identifier=principal.client.client_identifier,
                action="inventory_installation_assignment.issued", object_kind="inventory_installation_assignment",
                object_identifier=None, request_id=audit_request_id(request),
                details={"platform": body.platform, "expires_at": result.expires_at},
                occurred_at=now,
            )
            await session.commit()
        return result


@router.post(
    "/installation-receipts/lookup",
    response_model=ConnectedInventoryInstallationReceipt | PendingInventoryInstallationReceipt,
    dependencies=[Security(service_bearer, scopes=[_SCOPE])],
    responses={
        401: {"description": "Service authentication failed"},
        403: {"description": "Service scope is insufficient"},
        404: {"description": "Installation assignment unavailable"},
        409: {"description": "Conflicting installation evidence"},
        422: {"description": "Invalid inventory installation assignment", "model": InvalidInventoryInstallationAssignment},
    },
    openapi_extra={"x-required-scopes": [_SCOPE]},
)
async def lookup_inventory_installation(
    body: InventoryInstallationLookup,
    request: Request,
    response: Response,
    principal: Annotated[ServicePrincipal, Depends(require_service_scope(_SCOPE))],
) -> ConnectedInventoryInstallationReceipt | PendingInventoryInstallationReceipt:
    """Verify the exact consumed claim and a subsequent live agent heartbeat."""
    response.headers.update(_NO_STORE)
    now = datetime.now(UTC)
    installation_id = _installation_id(body)
    pepper = request.app.state.settings.device_token_pepper
    digest = installation_id_digest(installation_id, pepper)
    async with request.app.state.session_provider() as session:
        assignment = (await session.execute(
            select(InventoryInstallationAssignment).where(
                InventoryInstallationAssignment.installation_digest == digest,
                InventoryInstallationAssignment.service_client_id == principal.client.id,
            )
        )).scalar_one_or_none()
        if assignment is None:
            raise HTTPException(404, "Installation assignment unavailable", headers=_NO_STORE)
        if now >= utc(assignment.expires_at):
            return PendingInventoryInstallationReceipt(state="expired")
        if assignment.enrollment_request_id is None:
            return PendingInventoryInstallationReceipt(state="waiting_registration")
        latest_heartbeat = (
            select(DeviceSession.last_seen_at)
            .join(DeviceInstance, DeviceInstance.id == DeviceSession.device_instance_id)
            .where(
                DeviceSession.device_id == EnrollmentClaim.device_id,
                DeviceInstance.device_id == EnrollmentClaim.device_id,
                DeviceInstance.platform == f"{assignment.platform}_amd64",
                DeviceSession.created_at >= EnrollmentClaim.claimed_at,
                DeviceSession.closed_at.is_(None),
                DeviceSession.expires_at > now,
                DeviceSession.last_seen_at > DeviceSession.created_at,
                DeviceSession.last_seen_at >= now - _PRESENCE_TTL,
                DeviceSession.last_seen_at <= now,
            )
            .order_by(DeviceSession.last_seen_at.desc())
            .limit(1)
            .correlate(EnrollmentClaim)
            .scalar_subquery()
        )
        evidence = (await session.execute(
            select(EnrollmentRequest, EnrollmentClaim, Device.id, Device.retired_at, latest_heartbeat)
            .select_from(EnrollmentRequest)
            .join(EnrollmentClaim, EnrollmentClaim.enrollment_request_id == EnrollmentRequest.id)
            .outerjoin(Device, Device.id == EnrollmentClaim.device_id)
            .where(
                EnrollmentRequest.id == assignment.enrollment_request_id,
                EnrollmentRequest.installation_id_digest == digest,
                EnrollmentClaim.claimed_at.is_not(None),
                EnrollmentRequest.created_at >= assignment.issued_at,
                EnrollmentClaim.claimed_at >= EnrollmentRequest.created_at,
                EnrollmentClaim.claimed_at < assignment.expires_at,
                EnrollmentClaim.claimed_at <= now,
                EnrollmentClaim.claimed_at < EnrollmentClaim.expires_at,
            )
        )).one_or_none()
        if evidence is None:
            return PendingInventoryInstallationReceipt(state="waiting_registration")
        record, claim, device_id, retired_at, heartbeat = evidence
        if (
            record.platform != assignment.platform
            or record.status not in {"device_registered", "waiting_wss", "completed"}
            or device_id is None
            or record.device_id != device_id
            or retired_at is not None
            or record.selected_campaign_id != claim.campaign_id
            or not hmac.compare_digest(claim.fingerprint_digest, assignment.fingerprint_digest)
            or not hmac.compare_digest(
                claim.installation_session_digest, install_claim_session_digest(installation_id, pepper),
            )
        ):
            raise _conflict()
        if heartbeat is None:
            return PendingInventoryInstallationReceipt(state="waiting_connection")
        return ConnectedInventoryInstallationReceipt(
            state="connected",
            device_id=device_id,
            registered_at=utc(claim.claimed_at),
            heartbeat_at=utc(heartbeat),
        )
