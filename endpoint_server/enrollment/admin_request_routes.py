"""Administrator review controls for frozen enrollment requests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.db.models import EnrollmentCampaign, EnrollmentRequest

from .requests import (
    RequestTransitionError,
    approve_enrollment_request,
    deny_enrollment_request,
)


router = APIRouter(prefix="/api/admin/enrollment", tags=["admin-enrollment"])


class EnrollmentRequestQueueItem(BaseModel):
    """Administrator-safe projection; it deliberately omits bindings and claims."""

    id: UUID
    status: str
    reason: str | None
    platform: str
    hostname: str | None
    manufacturer: str | None
    model: str | None
    serial: str | None
    macs: list[str]
    source_address: str
    installer_release_id: str
    selected_campaign_id: UUID | None
    created_at: datetime
    expires_at: datetime


class EnrollmentRequestQueueResponse(BaseModel):
    requests: list[EnrollmentRequestQueueItem]


class DenyEnrollmentRequestBody(BaseModel):
    """Bounded operator decision reason without arbitrary free text."""

    model_config = ConfigDict(extra="forbid")

    reason: Literal["OPERATOR_DENIED", "IDENTITY_CONFLICT", "POLICY_DENIED"] = Field(
        default="OPERATOR_DENIED"
    )


def _not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Enrollment request not found")


def _conflict() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Enrollment request cannot be approved in its current state",
    )


def project_enrollment_request(record: EnrollmentRequest) -> EnrollmentRequestQueueItem:
    return EnrollmentRequestQueueItem(
        id=record.id,
        status=record.status,
        reason=record.decision_reason,
        platform=record.platform,
        hostname=record.hostname,
        manufacturer=record.manufacturer,
        model=record.model,
        serial=record.serial,
        macs=list(record.macs),
        source_address=record.source_address,
        installer_release_id=record.installer_release_id,
        selected_campaign_id=record.selected_campaign_id,
        created_at=record.created_at,
        expires_at=record.expires_at,
    )


async def _append_decision_audit(
    session,
    *,
    record: EnrollmentRequest,
    principal: AdminPrincipal,
    request: Request,
    action: str,
    now: datetime,
) -> None:
    await append_audit_event(
        session,
        actor_kind="admin",
        actor_identifier=str(principal.user.id),
        action=action,
        object_kind="enrollment_request",
        object_identifier=str(record.id),
        request_id=audit_request_id(request),
        details={"reason": record.decision_reason, "status": record.status},
        occurred_at=now,
    )


@router.get("/requests", response_model=EnrollmentRequestQueueResponse)
async def list_enrollment_requests(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    limit: int = Query(default=100, ge=1, le=500),
) -> EnrollmentRequestQueueResponse:
    """Expose a bounded review queue without device bindings or raw claims."""
    async with request.app.state.session_provider() as session:
        result = await session.execute(
            select(EnrollmentRequest)
            .order_by(EnrollmentRequest.created_at.desc())
            .limit(limit)
        )
        records = result.scalars().all()
    return EnrollmentRequestQueueResponse(requests=[project_enrollment_request(record) for record in records])


@router.post(
    "/requests/{request_id}/approve",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
async def approve_request(
    request_id: UUID,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> None:
    """Approve only the persisted campaign selected at request creation time."""
    now = datetime.now(UTC)
    async with request.app.state.session_provider() as session:
        try:
            record = (
                await session.execute(
                    select(EnrollmentRequest)
                    .where(EnrollmentRequest.id == request_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if record is None:
                raise _not_found()
            if record.selected_campaign_id is None:
                raise _conflict()
            campaign = (
                await session.execute(
                    select(EnrollmentCampaign)
                    .where(EnrollmentCampaign.id == record.selected_campaign_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if campaign is None:
                deny_enrollment_request(
                    record, reason="SELECTED_CAMPAIGN_INVALID", now=now
                )
                record.decided_by = principal.user.id
                await _append_decision_audit(
                    session,
                    record=record,
                    principal=principal,
                    request=request,
                    action="enrollment_request.denied",
                    now=now,
                )
                await session.commit()
                raise _conflict()
            try:
                approve_enrollment_request(record, campaign=campaign, now=now)
            except RequestTransitionError:
                if record.status in {"waiting_approval", "review_required"}:
                    deny_enrollment_request(
                        record, reason="SELECTED_CAMPAIGN_INVALID", now=now
                    )
                    record.decided_by = principal.user.id
                    await _append_decision_audit(
                        session,
                        record=record,
                        principal=principal,
                        request=request,
                        action="enrollment_request.denied",
                        now=now,
                    )
                    await session.commit()
                raise _conflict()
            record.decided_by = principal.user.id
            await _append_decision_audit(
                session,
                record=record,
                principal=principal,
                request=request,
                action="enrollment_request.manually_approved",
                now=now,
            )
            await session.commit()
        except HTTPException:
            raise
        except Exception:
            await session.rollback()
            raise


@router.post(
    "/requests/{request_id}/deny",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
async def deny_request(
    request_id: UUID,
    body: DenyEnrollmentRequestBody,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> None:
    """Record an explicit terminal denial without ever creating a claim."""
    now = datetime.now(UTC)
    async with request.app.state.session_provider() as session:
        try:
            record = (
                await session.execute(
                    select(EnrollmentRequest)
                    .where(EnrollmentRequest.id == request_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if record is None:
                raise _not_found()
            if record.status == "denied":
                return
            deny_enrollment_request(record, reason=body.reason, now=now)
            record.decided_by = principal.user.id
            await _append_decision_audit(
                session,
                record=record,
                principal=principal,
                request=request,
                action="enrollment_request.denied",
                now=now,
            )
            await session.commit()
        except HTTPException:
            raise
        except RequestTransitionError as error:
            await session.rollback()
            raise _conflict() from error
        except Exception:
            await session.rollback()
            raise
