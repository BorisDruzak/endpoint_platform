"""Authenticated administrator APIs for enrollment campaigns and claims."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select

from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.db.models import EnrollmentCampaign

from .campaigns import (
    EnrollmentDenied,
    issue_campaign,
    issue_install_claim,
    revoke_campaign,
)


router = APIRouter(
    prefix="/api/admin/enrollment",
    tags=["admin-enrollment"],
)


class CampaignCreateRequest(BaseModel):
    """Bounded administrator input for a new enrollment campaign."""

    model_config = ConfigDict(extra="forbid")

    expires_at: datetime
    max_uses: int = Field(gt=0, le=1_000_000)
    allowed_cidrs: list[str] = Field(min_length=1, max_length=64)
    target_platform: str = Field(min_length=1, max_length=64)
    policy: dict[str, object]
    label: str | None = Field(default=None, max_length=256)
    site: str | None = Field(default=None, max_length=128)


class CampaignCreateResponse(BaseModel):
    """Show-once campaign bearer response."""

    id: UUID
    campaign_identifier: str
    token: str
    expires_at: datetime
    max_uses: int


class InstallClaimCreateRequest(BaseModel):
    """Secret-bound install claim input."""

    model_config = ConfigDict(extra="forbid")

    installation_session: SecretStr
    hardware_fingerprint: SecretStr
    expires_at: datetime


class InstallClaimCreateResponse(BaseModel):
    """Show-once install claim bearer response."""

    id: UUID
    claim_identifier: str
    token: str
    expires_at: datetime


def _not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Enrollment campaign not found",
    )


def _invalid(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=detail,
    )


@router.post(
    "/campaigns",
    status_code=status.HTTP_201_CREATED,
    response_model=CampaignCreateResponse,
)
async def create_campaign(
    body: CampaignCreateRequest,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> CampaignCreateResponse:
    """Create and audit one campaign, exposing its bearer only in this response."""
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
        )
    except ValueError as error:
        raise _invalid("Invalid enrollment campaign") from error
    async with request.app.state.session_provider() as session:
        session.add(issued.record)
        try:
            await append_audit_event(
                session,
                actor_kind="admin",
                actor_identifier=str(principal.user.id),
                action="enrollment_campaign.created",
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
    return CampaignCreateResponse(
        id=issued.record.id,
        campaign_identifier=issued.record.campaign_identifier,
        token=issued.token,
        expires_at=issued.record.expires_at,
        max_uses=issued.record.max_uses,
    )


@router.post(
    "/campaigns/{campaign_id}/claims",
    status_code=status.HTTP_201_CREATED,
    response_model=InstallClaimCreateResponse,
)
async def create_install_claim(
    campaign_id: UUID,
    body: InstallClaimCreateRequest,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> InstallClaimCreateResponse:
    """Create a one-time claim under a locked active campaign."""
    async with request.app.state.session_provider() as session:
        result = await session.execute(
            select(EnrollmentCampaign)
            .where(EnrollmentCampaign.id == campaign_id)
            .with_for_update()
        )
        campaign = result.scalar_one_or_none()
        if campaign is None:
            raise _not_found()
        try:
            issued = issue_install_claim(
                campaign,
                request.app.state.settings.device_token_pepper,
                installation_session=body.installation_session.get_secret_value(),
                hardware_fingerprint=body.hardware_fingerprint.get_secret_value(),
                expires_at=body.expires_at,
            )
        except EnrollmentDenied as error:
            raise _not_found() from error
        except ValueError as error:
            raise _invalid("Invalid install claim") from error
        session.add(issued.record)
        try:
            await append_audit_event(
                session,
                actor_kind="admin",
                actor_identifier=str(principal.user.id),
                action="enrollment_claim.created",
                object_kind="enrollment_claim",
                object_identifier=str(issued.record.id),
                request_id=audit_request_id(request),
                details={
                    "campaign_id": campaign.id,
                    "expires_at": issued.record.expires_at,
                },
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return InstallClaimCreateResponse(
        id=issued.record.id,
        claim_identifier=issued.record.claim_identifier,
        token=issued.token,
        expires_at=issued.record.expires_at,
    )


@router.post(
    "/campaigns/{campaign_id}/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
async def revoke_enrollment_campaign(
    campaign_id: UUID,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> None:
    """Revoke one campaign and its future claims."""
    async with request.app.state.session_provider() as session:
        try:
            await revoke_campaign(
                session,
                campaign_id,
                actor_identifier=str(principal.user.id),
                request_id=audit_request_id(request),
            )
            await session.commit()
        except EnrollmentDenied as error:
            await session.rollback()
            raise _not_found() from error
        except Exception:
            await session.rollback()
            raise
