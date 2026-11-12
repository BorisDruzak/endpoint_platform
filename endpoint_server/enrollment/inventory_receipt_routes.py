"""Read-only enrollment evidence for a private inventory installation assignment."""

from datetime import UTC, datetime, timedelta
import re
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Security
from fastapi.security import HTTPBearer
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select

from endpoint_contracts.identity import normalize_hardware_fingerprint
from endpoint_server.auth.scopes import (
    INVENTORY_INSTALLATION_RECEIPTS_READ_SCOPE,
    ServicePrincipal,
    require_service_scope,
)
from endpoint_server.db.models import (
    Device, DeviceInstance, DeviceSession, EnrollmentClaim, EnrollmentRequest,
)

from .campaigns import install_claim_bindings_match
from .requests import installation_id_digest, request_bindings_match


router = APIRouter(prefix="/api/v1/enrollment", tags=["inventory-installation"])
service_bearer = HTTPBearer(auto_error=False, scheme_name="ServiceBearer")
_SCOPE = INVENTORY_INSTALLATION_RECEIPTS_READ_SCOPE
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_INSTALLATION_ID = re.compile(rf"^inventory-{_UUID}-{_UUID}-[0-9a-f]{{32}}$")
_MAX_ASSIGNMENT_LIFETIME = timedelta(minutes=30)
_PRESENCE_TTL = timedelta(seconds=90)
_NO_STORE = {"Cache-Control": "no-store"}


class InventoryInstallationLookup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    installation_id: SecretStr = Field(
        min_length=1,
        max_length=128,
        description="Private inventory installation ID containing the asset UUID, machine UUID and nonce.",
        json_schema_extra={"pattern": _INSTALLATION_ID.pattern},
    )
    hardware_fingerprint: SecretStr = Field(min_length=1, max_length=256)
    platform: Literal["linux", "windows"]
    issued_at: AwareDatetime = Field(description="Original assignment issue time, at or before the lookup time.")
    expires_at: AwareDatetime = Field(description="Original expiry, at most 30 minutes after issuance.")


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


@router.post(
    "/installation-receipts/lookup",
    response_model=ConnectedInventoryInstallationReceipt | PendingInventoryInstallationReceipt,
    dependencies=[Security(service_bearer, scopes=[_SCOPE])],
    responses={
        401: {"description": "Service authentication failed"},
        403: {"description": "Service scope is insufficient"},
        409: {"description": "Conflicting installation evidence"},
        422: {"description": "Invalid inventory installation assignment", "model": InvalidInventoryInstallationAssignment},
    },
    openapi_extra={"x-required-scopes": [_SCOPE]},
)
async def lookup_inventory_installation(
    body: InventoryInstallationLookup,
    request: Request,
    response: Response,
    _: Annotated[ServicePrincipal, Depends(require_service_scope(_SCOPE))],
) -> ConnectedInventoryInstallationReceipt | PendingInventoryInstallationReceipt:
    """Verify the exact consumed claim and a subsequent live agent heartbeat."""
    response.headers.update(_NO_STORE)
    now = datetime.now(UTC)
    installation_id = body.installation_id.get_secret_value()
    try:
        fingerprint = normalize_hardware_fingerprint(body.hardware_fingerprint.get_secret_value())
        if (
            not _INSTALLATION_ID.fullmatch(installation_id)
            or body.issued_at > now
            or not timedelta(0) < body.expires_at - body.issued_at <= _MAX_ASSIGNMENT_LIFETIME
        ):
            raise ValueError
    except ValueError:
        raise HTTPException(422, "Invalid inventory installation assignment", headers=_NO_STORE) from None

    if now >= body.expires_at:
        return PendingInventoryInstallationReceipt(state="expired")

    pepper = request.app.state.settings.device_token_pepper
    latest_heartbeat = (
        select(DeviceSession.last_seen_at)
        .join(DeviceInstance, DeviceInstance.id == DeviceSession.device_instance_id)
        .where(
            DeviceSession.device_id == EnrollmentClaim.device_id,
            DeviceInstance.device_id == EnrollmentClaim.device_id,
            DeviceInstance.platform == f"{body.platform}_amd64",
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
    async with request.app.state.session_provider() as session:
        matches = (await session.execute(
            select(EnrollmentRequest, EnrollmentClaim, Device.id, Device.retired_at, latest_heartbeat)
            .select_from(EnrollmentRequest)
            .join(EnrollmentClaim, EnrollmentClaim.enrollment_request_id == EnrollmentRequest.id)
            .outerjoin(Device, Device.id == EnrollmentClaim.device_id)
            .where(
                EnrollmentRequest.installation_id_digest == installation_id_digest(installation_id, pepper),
                EnrollmentClaim.claimed_at.is_not(None),
                EnrollmentRequest.created_at >= body.issued_at,
                EnrollmentClaim.claimed_at >= EnrollmentRequest.created_at,
                EnrollmentClaim.claimed_at < body.expires_at,
                EnrollmentClaim.claimed_at <= now,
                EnrollmentClaim.claimed_at < EnrollmentClaim.expires_at,
            )
            .limit(2)
        )).all()
        if not matches:
            return PendingInventoryInstallationReceipt(state="waiting_registration")
        if len(matches) != 1:
            raise _conflict()
        record, claim, device_id, retired_at, heartbeat = matches[0]
        if (
            record.platform != body.platform
            or record.status not in {"device_registered", "waiting_wss", "completed"}
            or device_id is None
            or record.device_id != device_id
            or retired_at is not None
            or record.selected_campaign_id != claim.campaign_id
            or not request_bindings_match(
                record, installation_id=installation_id, hardware_fingerprint=fingerprint, pepper=pepper,
            )
            or not install_claim_bindings_match(
                claim, pepper, installation_session=installation_id, hardware_fingerprint=fingerprint,
            )
        ):
            raise _conflict()
        if heartbeat is None:
            return PendingInventoryInstallationReceipt(state="waiting_connection")
        return ConnectedInventoryInstallationReceipt(
            state="connected",
            device_id=device_id,
            registered_at=claim.claimed_at if claim.claimed_at.tzinfo else claim.claimed_at.replace(tzinfo=UTC),
            heartbeat_at=heartbeat if heartbeat.tzinfo else heartbeat.replace(tzinfo=UTC),
        )
