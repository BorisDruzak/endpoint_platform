"""Scoped service issuance of one-time ALT install claims."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select

from endpoint_contracts.identity import (
    normalize_hardware_fingerprint,
    normalize_install_session_id,
)
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.scopes import (
    PROVISIONING_INSTALL_CLAIMS_ISSUE_SCOPE,
    ServicePrincipal,
    require_service_scope,
)
from endpoint_server.db.models import EnrollmentCampaign
from endpoint_server.provisioning.pilot_service import (
    PILOT_SERVICE_CLIENT_IDENTIFIER,
    pilot_credential_identifier,
)

from .campaigns import EnrollmentDenied, issue_install_claim


router = APIRouter(prefix="/api/v1/provisioning", tags=["provisioning"])

# A claim is intentionally short-lived.  The campaign can reduce this window,
# but callers cannot lengthen it or choose a separate expiry.
_INSTALL_CLAIM_LIFETIME = timedelta(minutes=15)
_MAX_HARDWARE_FINGERPRINT_LENGTH = 256
_MAX_INSTALL_SESSION_LENGTH = 128


class ProvisioningInstallClaimRequest(BaseModel):
    """Bounded secret inputs accepted only from the provisioning controller."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: UUID
    install_session_id: SecretStr = Field(
        min_length=1, max_length=_MAX_INSTALL_SESSION_LENGTH
    )
    hardware_fingerprint: SecretStr = Field(
        min_length=1, max_length=_MAX_HARDWARE_FINGERPRINT_LENGTH
    )


class ProvisioningInstallClaimResponse(BaseModel):
    """The sole show-once exposure of a claim to its scoped caller."""

    model_config = ConfigDict(extra="forbid")

    claim: str
    expires_at: datetime
    install_session_id: str


def _not_found() -> HTTPException:
    """Avoid distinguishing expired, revoked, or unknown campaign authority."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Enrollment campaign not found",
    )


def _invalid() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="Invalid provisioning install claim",
    )


def _bounded_binding(value: str, *, maximum: int) -> str:
    """Accept only bounded printable ASCII proof material without normalization."""
    if (
        not value
        or len(value) > maximum
        or value != value.strip()
        or not value.isascii()
        or any(not 32 <= ord(character) <= 126 for character in value)
    ):
        raise ValueError("invalid bounded claim binding")
    return value


@router.post(
    "/install-claims",
    status_code=status.HTTP_201_CREATED,
    response_model=ProvisioningInstallClaimResponse,
)
async def issue_provisioning_install_claim(
    body: ProvisioningInstallClaimRequest,
    request: Request,
    principal: Annotated[
        ServicePrincipal,
        Depends(require_service_scope(PROVISIONING_INSTALL_CLAIMS_ISSUE_SCOPE)),
    ],
) -> ProvisioningInstallClaimResponse:
    """Issue one short, hardware-bound claim without handling device credentials."""
    try:
        install_session_id = normalize_install_session_id(
            body.install_session_id.get_secret_value()
        )
        hardware_fingerprint = normalize_hardware_fingerprint(
            body.hardware_fingerprint.get_secret_value()
        )
    except ValueError as error:
        raise _invalid() from error
    if principal.client.client_identifier == PILOT_SERVICE_CLIENT_IDENTIFIER:
        try:
            expected_identifier = pilot_credential_identifier(
                service_token_pepper=request.app.state.settings.service_token_pepper,
                campaign_id=body.campaign_id,
                installation_id=install_session_id,
                hardware_fingerprint=hardware_fingerprint,
            )
        except ValueError as error:
            raise _invalid() from error
        if principal.credential.credential_identifier != expected_identifier:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Test-pilot credential binding is missing",
            )

    issued_at = datetime.now(UTC)
    async with request.app.state.session_provider() as session:
        result = await session.execute(
            select(EnrollmentCampaign)
            .where(EnrollmentCampaign.id == body.campaign_id)
            .with_for_update()
        )
        campaign = result.scalar_one_or_none()
        if campaign is None:
            await session.rollback()
            raise _not_found()
        try:
            campaign_expiry = campaign.expires_at.astimezone(UTC)
            if issued_at >= campaign_expiry:
                raise EnrollmentDenied("Enrollment denied")
            expires_at = min(issued_at + _INSTALL_CLAIM_LIFETIME, campaign_expiry)
            issued = issue_install_claim(
                campaign,
                request.app.state.settings.device_token_pepper,
                installation_session=install_session_id,
                hardware_fingerprint=hardware_fingerprint,
                expires_at=expires_at,
                now=issued_at,
            )
        except (AttributeError, EnrollmentDenied) as error:
            await session.rollback()
            raise _not_found() from error
        except ValueError as error:
            await session.rollback()
            raise _invalid() from error
        session.add(issued.record)
        try:
            await append_audit_event(
                session,
                actor_kind="service",
                actor_identifier=str(principal.client.id),
                action="provisioning_install_claim.issued",
                object_kind="enrollment_claim",
                object_identifier=str(issued.record.id),
                request_id=audit_request_id(request),
                details={
                    "campaign_id": str(campaign.id),
                    "expires_at": issued.record.expires_at,
                },
                occurred_at=issued_at,
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return ProvisioningInstallClaimResponse(
        claim=issued.token,
        expires_at=issued.record.expires_at,
        install_session_id=install_session_id,
    )


__all__ = ["router"]
