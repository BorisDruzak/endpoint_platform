"""Authenticated administrator APIs for enrollment campaigns and claims."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select

from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from .campaigns import (
    EnrollmentDenied,
    issue_campaign,
    parse_windows_enrollment_policy,
    revoke_campaign,
)
from endpoint_contracts.json_types import validate_bounded_json
from endpoint_server.db.models import EnrollmentCampaign


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


class CampaignProjection(BaseModel):
    """Secret-free campaign state suitable for the Endpoint Admin surface."""

    id: UUID
    expires_at: datetime
    max_uses: int
    use_count: int
    allowed_cidrs: list[str]
    target_platform: str
    policy: dict[str, object]
    label: str | None
    site: str | None
    revoked_at: datetime | None
    disabled_at: datetime | None


class CampaignListResponse(BaseModel):
    campaigns: list[CampaignProjection]


class WindowsEnrollmentSummary(BaseModel):
    """Projection only; campaign policy remains the sole configuration authority."""

    status: str
    campaign_id: UUID | None = None
    label: str | None = None
    enrollment_mode: str | None = None


class CampaignUpdateRequest(BaseModel):
    """Bounded mutable fields; bearer identifiers and use counters are immutable."""

    model_config = ConfigDict(extra="forbid")

    expires_at: datetime | None = None
    max_uses: int | None = Field(default=None, gt=0, le=1_000_000)
    allowed_cidrs: list[str] | None = Field(default=None, min_length=1, max_length=64)
    policy: dict[str, object] | None = None
    label: str | None = Field(default=None, max_length=256)
    site: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def require_one_change(self) -> "CampaignUpdateRequest":
        if not self.model_fields_set:
            raise ValueError("at least one campaign field is required")
        return self


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


def _projection(campaign: EnrollmentCampaign) -> CampaignProjection:
    return CampaignProjection(
        id=campaign.id,
        expires_at=campaign.expires_at,
        max_uses=campaign.max_uses,
        use_count=campaign.use_count,
        allowed_cidrs=list(campaign.allowed_cidrs),
        target_platform=campaign.target_platform,
        policy=dict(campaign.policy),
        label=campaign.label,
        site=campaign.site,
        revoked_at=campaign.revoked_at,
        disabled_at=campaign.disabled_at,
    )


def _active_windows_policy(campaign: EnrollmentCampaign, *, now: datetime):
    if (
        campaign.target_platform != "windows"
        or campaign.revoked_at is not None
        or campaign.disabled_at is not None
        or campaign.expires_at is None
        or campaign.expires_at <= now
        or campaign.use_count >= campaign.max_uses
    ):
        return None
    return parse_windows_enrollment_policy(campaign.policy)


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


@router.get("/campaigns", response_model=CampaignListResponse)
async def list_campaigns(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> CampaignListResponse:
    """Return configuration data only; campaign bearers are never retrievable."""
    async with request.app.state.session_provider() as session:
        result = await session.execute(
            select(EnrollmentCampaign).order_by(EnrollmentCampaign.created_at.desc())
        )
        campaigns = list(result.scalars().all())
    return CampaignListResponse(campaigns=[_projection(campaign) for campaign in campaigns])


@router.get("/windows-summary", response_model=WindowsEnrollmentSummary)
async def windows_enrollment_summary(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> WindowsEnrollmentSummary:
    """Expose a display-only summary and never a global enrollment-mode setting."""
    now = datetime.now(UTC)
    async with request.app.state.session_provider() as session:
        result = await session.execute(select(EnrollmentCampaign))
        eligible = [
            (campaign, policy)
            for campaign in result.scalars().all()
            if (policy := _active_windows_policy(campaign, now=now)) is not None
        ]
    if len(eligible) != 1:
        return WindowsEnrollmentSummary(
            status="no_active_campaign" if not eligible else "ambiguous_active_campaigns"
        )
    campaign, policy = eligible[0]
    return WindowsEnrollmentSummary(
        status="single_active_campaign",
        campaign_id=campaign.id,
        label=campaign.label,
        enrollment_mode=policy.enrollment_mode,
    )


@router.patch(
    "/campaigns/{campaign_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
async def update_campaign(
    campaign_id: UUID,
    body: CampaignUpdateRequest,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> None:
    """Change explicit campaign configuration without affecting campaign selection rules."""
    now = datetime.now(UTC)
    async with request.app.state.session_provider() as session:
        result = await session.execute(
            select(EnrollmentCampaign)
            .where(EnrollmentCampaign.id == campaign_id)
            .with_for_update()
        )
        campaign = result.scalar_one_or_none()
        if campaign is None:
            raise _not_found()
        candidate_policy = dict(body.policy) if body.policy is not None else dict(campaign.policy)
        try:
            validate_bounded_json(candidate_policy)
            if campaign.target_platform == "windows" and parse_windows_enrollment_policy(
                candidate_policy
            ) is None:
                raise ValueError("Windows enrollment policy is invalid")
            if body.expires_at is not None and body.expires_at <= now:
                raise ValueError("campaign expiry must be in the future")
            if body.max_uses is not None and body.max_uses < campaign.use_count:
                raise ValueError("campaign max uses cannot be below use count")
            if body.policy is not None:
                campaign.policy = candidate_policy
            if body.expires_at is not None:
                campaign.expires_at = body.expires_at
            if body.max_uses is not None:
                campaign.max_uses = body.max_uses
            if body.allowed_cidrs is not None:
                # Route through canonical campaign validation before assigning.
                validated = issue_campaign(
                    request.app.state.settings.device_token_pepper,
                    expires_at=campaign.expires_at,
                    max_uses=campaign.max_uses,
                    allowed_cidrs=body.allowed_cidrs,
                    target_platform=campaign.target_platform,
                    policy=candidate_policy,
                    label=campaign.label,
                    site=campaign.site,
                    now=now,
                ).record
                campaign.allowed_cidrs = validated.allowed_cidrs
            if "label" in body.model_fields_set:
                campaign.label = body.label
            if "site" in body.model_fields_set:
                campaign.site = body.site
        except ValueError as error:
            await session.rollback()
            raise _invalid("Invalid enrollment campaign") from error
        try:
            await append_audit_event(
                session,
                actor_kind="admin",
                actor_identifier=str(principal.user.id),
                action="enrollment_campaign.updated",
                object_kind="enrollment_campaign",
                object_identifier=str(campaign.id),
                request_id=audit_request_id(request),
                details={"changed_fields": sorted(body.model_fields_set)},
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise


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
