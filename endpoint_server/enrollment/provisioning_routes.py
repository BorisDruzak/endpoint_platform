"""Scoped service issuance of one-time ALT install claims."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select

from endpoint_contracts.identity import (
    normalize_hardware_fingerprint,
    normalize_install_session_id,
)
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.scopes import (
    PROVISIONING_CAMPAIGNS_CREATE_SCOPE,
    PROVISIONING_CAMPAIGNS_REVOKE_SCOPE,
    PROVISIONING_INSTALL_CLAIMS_ISSUE_SCOPE,
    ServicePrincipal,
    require_service_scope,
)
from endpoint_server.db.models import EnrollmentCampaign
from endpoint_server.provisioning.pilot_service import (
    PILOT_SERVICE_CLIENT_IDENTIFIER,
    pilot_credential_identifier,
)

from .campaigns import EnrollmentDenied, issue_campaign, issue_install_claim, revoke_campaign


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


class ProvisioningCampaignCreateRequest(BaseModel):
    """Bounded campaign authority accepted from a deployment service."""

    model_config = ConfigDict(extra="forbid")

    expires_at: datetime
    max_uses: int = Field(gt=0, le=1_000_000)
    allowed_cidrs: list[str] = Field(min_length=1, max_length=64)
    target_platform: str = Field(min_length=1, max_length=64)
    policy: dict[str, object]
    label: str | None = Field(default=None, max_length=256)
    site: str | None = Field(default=None, max_length=128)


class ProvisioningCampaignResponse(BaseModel):
    """Non-secret campaign authority returned to deployment automation."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    expires_at: datetime
    max_uses: int
    allowed_cidrs: list[str]
    target_platform: str
    policy: dict[str, object]
    label: str | None
    site: str | None


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
    "/campaigns",
    status_code=status.HTTP_201_CREATED,
    response_model=ProvisioningCampaignResponse,
)
async def create_provisioning_campaign(
    body: ProvisioningCampaignCreateRequest,
    request: Request,
    principal: Annotated[
        ServicePrincipal,
        Depends(require_service_scope(PROVISIONING_CAMPAIGNS_CREATE_SCOPE)),
    ],
) -> ProvisioningCampaignResponse:
    """Create an owner-bound campaign without exposing its enrollment bearer."""
    try:
        issued = issue_campaign(
            request.app.state.settings.device_token_pepper,
            expires_at=body.expires_at,
            max_uses=body.max_uses,
            allowed_cidrs=body.allowed_cidrs,
            target_platform=body.target_platform,
            policy=body.policy,
            label=body.label,
            site=body.site,
            owner_service_client_id=principal.client.id,
        )
    except ValueError as error:
        raise _invalid() from error
    async with request.app.state.session_provider() as session:
        session.add(issued.record)
        try:
            await append_audit_event(
                session,
                actor_kind="service",
                actor_identifier=str(principal.client.id),
                action="provisioning_campaign.created",
                object_kind="enrollment_campaign",
                object_identifier=str(issued.record.id),
                request_id=audit_request_id(request),
                details={
                    "allowed_cidrs": issued.record.allowed_cidrs,
                    "expires_at": issued.record.expires_at,
                    "label": issued.record.label,
                    "max_uses": issued.record.max_uses,
                    "site": issued.record.site,
                    "target_platform": issued.record.target_platform,
                },
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return ProvisioningCampaignResponse(
        id=issued.record.id,
        expires_at=issued.record.expires_at,
        max_uses=issued.record.max_uses,
        allowed_cidrs=issued.record.allowed_cidrs,
        target_platform=issued.record.target_platform,
        policy=issued.record.policy,
        label=issued.record.label,
        site=issued.record.site,
    )


@router.post(
    "/campaigns/{campaign_id}/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
async def revoke_provisioning_campaign(
    campaign_id: UUID,
    request: Request,
    principal: Annotated[
        ServicePrincipal,
        Depends(require_service_scope(PROVISIONING_CAMPAIGNS_REVOKE_SCOPE)),
    ],
) -> None:
    """Revoke only a campaign owned by the authenticated deployment service."""
    async with request.app.state.session_provider() as session:
        result = await session.execute(
            select(EnrollmentCampaign)
            .where(EnrollmentCampaign.id == campaign_id)
            .with_for_update()
        )
        campaign = result.scalar_one_or_none()
        if campaign is None or campaign.owner_service_client_id != principal.client.id:
            await session.rollback()
            raise _not_found()
        try:
            await revoke_campaign(
                session,
                campaign_id,
                actor_kind="service",
                actor_identifier=str(principal.client.id),
                request_id=audit_request_id(request),
            )
            await session.commit()
        except EnrollmentDenied as error:
            await session.rollback()
            raise _not_found() from error
        except Exception:
            await session.rollback()
            raise


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
        if (
            campaign.owner_service_client_id is not None
            and campaign.owner_service_client_id != principal.client.id
        ):
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
