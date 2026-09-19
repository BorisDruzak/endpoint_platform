"""Public, capability-bound pre-enrollment request endpoints."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select

from endpoint_contracts import PreEnrollmentRequestCreateV1, PreEnrollmentRequestStatusV1
from endpoint_contracts.identity import (
    normalize_hardware_fingerprint,
    normalize_install_session_id,
)
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import (
    EnrollmentCampaign,
    EnrollmentRequest,
    EnrollmentRequestClaimEnvelope,
    EnrollmentClaim,
)
from endpoint_server.network import observed_client_address

from .campaigns import EnrollmentDenied, hardware_fingerprint_digest, issue_install_claim
from .credentials import recover_retry_token, seal_retry_envelope
from .requests import (
    build_enrollment_request,
    deny_enrollment_request,
    evaluate_campaign_selection,
    enrollment_request_rate_limited,
    mark_request_claim_issued,
    persist_enrollment_request,
    request_bindings_match,
    request_capability_matches,
    selected_campaign_still_allows_request,
)


router = APIRouter(prefix="/api/v1/enrollment", tags=["enrollment-requests"])


class EnrollmentRequestStatusProof(BaseModel):
    """Ephemeral capability proof; never persisted or reflected."""

    model_config = ConfigDict(extra="forbid")

    request_capability: SecretStr = Field(min_length=43, max_length=43)


class EnrollmentRequestClaimProof(BaseModel):
    """Ephemeral capability and binding proof used only for claim handoff."""

    model_config = ConfigDict(extra="forbid")

    request_capability: SecretStr = Field(min_length=43, max_length=43)
    installation_id: SecretStr = Field(min_length=1, max_length=128)
    hardware_fingerprint: SecretStr = Field(min_length=8, max_length=256)


class EnrollmentRequestClaimResponse(BaseModel):
    """Claim response is intentionally separate from the polling status view."""

    model_config = ConfigDict(extra="forbid")

    claim: str
    expires_at: datetime


_INSTALL_CLAIM_LIFETIME = timedelta(minutes=15)


def _source_address(request: Request):
    try:
        return observed_client_address(request)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Enrollment denied") from error


@router.post(
    "/requests",
    status_code=status.HTTP_201_CREATED,
    response_model=PreEnrollmentRequestStatusV1,
)
async def create_enrollment_request(
    body: PreEnrollmentRequestCreateV1,
    request: Request,
) -> PreEnrollmentRequestStatusV1:
    """Persist one selected/no-selection request; clients cannot choose campaigns."""
    source_address = _source_address(request)
    now = datetime.now(UTC)
    async with request.app.state.session_provider() as session:
        try:
            result = await session.execute(select(EnrollmentCampaign).with_for_update())
            fingerprint_digest = hardware_fingerprint_digest(
                body.hardware_fingerprint,
                request.app.state.settings.device_token_pepper,
            )
            prior_claims = await session.execute(
                select(EnrollmentClaim)
                .where(
                    EnrollmentClaim.fingerprint_digest == fingerprint_digest,
                    EnrollmentClaim.device_id.is_not(None),
                )
                .with_for_update()
            )
            selection = evaluate_campaign_selection(
                result.scalars().all(),
                source_address=source_address,
                installer_release_id=body.installer_release_id,
                now=now,
                blocking_identity_conflict=bool(prior_claims.scalars().all()),
            )
            record = build_enrollment_request(
                installation_id=body.installation_id,
                hardware_fingerprint=body.hardware_fingerprint,
                request_capability=body.request_capability,
                source_address=source_address,
                installer_version=body.installer_version,
                installer_release_id=body.installer_release_id,
                hostname=body.hostname,
                manufacturer=body.manufacturer,
                model=body.model,
                serial=body.serial,
                product_uuid=body.product_uuid,
                macs=body.macs,
                selection=selection,
                pepper=request.app.state.settings.device_token_pepper,
                now=now,
            )
            recent_requests = await session.execute(
                select(EnrollmentRequest)
                .where(EnrollmentRequest.created_at >= now - timedelta(hours=1))
                .with_for_update()
            )
            if enrollment_request_rate_limited(
                recent_requests.scalars().all(), record, now=now
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Enrollment request rate limited",
                )
            await persist_enrollment_request(
                session,
                request=record,
                selection=selection,
                request_id=audit_request_id(request),
                now=now,
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return PreEnrollmentRequestStatusV1(
        schema_version="pre_enrollment_request_status_v1",
        request_id=record.id,
        status=record.status,
        reason=record.decision_reason,
        expires_at=record.expires_at,
    )


@router.post(
    "/requests/{request_id}/status",
    response_model=PreEnrollmentRequestStatusV1,
)
async def enrollment_request_status(
    request_id: UUID,
    body: EnrollmentRequestStatusProof,
    request: Request,
) -> PreEnrollmentRequestStatusV1:
    """Return bounded status only to the in-memory request capability holder."""
    capability = body.request_capability.get_secret_value()
    now = datetime.now(UTC)
    async with request.app.state.session_provider() as session:
        result = await session.execute(
            select(EnrollmentRequest)
            .where(EnrollmentRequest.id == request_id)
            .with_for_update()
        )
        record = result.scalar_one_or_none()
        if record is None or not request_capability_matches(
            capability,
            record.request_capability_digest,
            request.app.state.settings.device_token_pepper,
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Enrollment request not found",
            )
        if (
            now >= record.expires_at.astimezone(UTC)
            and record.status not in {"denied", "expired", "failed", "cancelled"}
        ):
            record.status = "expired"
            record.decision_reason = "REQUEST_EXPIRED"
            record.updated_at = now
            await append_audit_event(
                session,
                actor_kind="installer",
                actor_identifier=None,
                action="enrollment_request.expired",
                object_kind="enrollment_request",
                object_identifier=str(record.id),
                request_id=audit_request_id(request),
                details={"status": record.status},
                occurred_at=now,
            )
            await session.commit()
    return PreEnrollmentRequestStatusV1(
        schema_version="pre_enrollment_request_status_v1",
        request_id=record.id,
        status=record.status,
        reason=record.decision_reason,
        expires_at=record.expires_at,
    )


async def _load_proven_request(
    session,
    *,
    request_id: UUID,
    capability: str,
    installation_id: str,
    hardware_fingerprint: str,
    pepper: bytes,
) -> EnrollmentRequest:
    record = (
        await session.execute(
            select(EnrollmentRequest)
            .where(EnrollmentRequest.id == request_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        record is None
        or not request_capability_matches(
            capability, record.request_capability_digest, pepper
        )
        or not request_bindings_match(
            record,
            installation_id=installation_id,
            hardware_fingerprint=hardware_fingerprint,
            pepper=pepper,
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Enrollment request not found",
        )
    return record


async def _deny_invalid_selected_campaign(
    session,
    *,
    record: EnrollmentRequest,
    request: Request,
    now: datetime,
) -> None:
    deny_enrollment_request(record, reason="SELECTED_CAMPAIGN_INVALID", now=now)
    await append_audit_event(
        session,
        actor_kind="installer",
        actor_identifier=None,
        action="enrollment_request.denied",
        object_kind="enrollment_request",
        object_identifier=str(record.id),
        request_id=audit_request_id(request),
        details={"reason": record.decision_reason, "status": record.status},
        occurred_at=now,
    )


@router.post(
    "/requests/{request_id}/claim",
    response_model=EnrollmentRequestClaimResponse,
)
async def handoff_enrollment_request_claim(
    request_id: UUID,
    body: EnrollmentRequestClaimProof,
    request: Request,
) -> EnrollmentRequestClaimResponse:
    """Issue or safely recover the exact claim bound to a frozen request."""
    try:
        capability = body.request_capability.get_secret_value()
        installation_id = normalize_install_session_id(
            body.installation_id.get_secret_value()
        )
        hardware_fingerprint = normalize_hardware_fingerprint(
            body.hardware_fingerprint.get_secret_value()
        )
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid enrollment request claim proof",
        ) from error

    now = datetime.now(UTC)
    settings = request.app.state.settings
    async with request.app.state.session_provider() as session:
        try:
            record = await _load_proven_request(
                session,
                request_id=request_id,
                capability=capability,
                installation_id=installation_id,
                hardware_fingerprint=hardware_fingerprint,
                pepper=settings.device_token_pepper,
            )
            if now >= record.expires_at.astimezone(UTC):
                if record.status not in {"denied", "expired", "failed", "cancelled"}:
                    record.status = "expired"
                    record.decision_reason = "REQUEST_EXPIRED"
                    record.updated_at = now
                    await append_audit_event(
                        session,
                        actor_kind="installer",
                        actor_identifier=None,
                        action="enrollment_request.expired",
                        object_kind="enrollment_request",
                        object_identifier=str(record.id),
                        request_id=audit_request_id(request),
                        details={"status": record.status},
                        occurred_at=now,
                    )
                    await session.commit()
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="Enrollment request expired",
                )
            if record.status not in {"auto_approved", "approved", "claim_issued"}:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Enrollment request is not approved",
                )
            if record.selected_campaign_id is None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Enrollment request is not approved",
                )
            campaign = (
                await session.execute(
                    select(EnrollmentCampaign)
                    .where(EnrollmentCampaign.id == record.selected_campaign_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if campaign is None or not selected_campaign_still_allows_request(
                record, campaign, now=now
            ):
                await _deny_invalid_selected_campaign(
                    session, record=record, request=request, now=now
                )
                await session.commit()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Enrollment request is no longer eligible",
                )
            if record.status == "claim_issued":
                envelope = (
                    await session.execute(
                        select(EnrollmentRequestClaimEnvelope)
                        .where(
                            EnrollmentRequestClaimEnvelope.enrollment_request_id
                            == record.id
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                claim = (
                    recover_retry_token(
                        capability,
                        hardware_fingerprint,
                        envelope,
                        settings.device_token_pepper,
                        settings.session_secret,
                        now=now,
                    )
                    if envelope is not None
                    else None
                )
                if claim is None:
                    raise HTTPException(
                        status_code=status.HTTP_410_GONE,
                        detail="Enrollment claim is no longer available",
                    )
                return EnrollmentRequestClaimResponse(
                    claim=claim, expires_at=envelope.expires_at
                )

            campaign_expiry = campaign.expires_at.astimezone(UTC)
            expires_at = min(
                now + _INSTALL_CLAIM_LIFETIME,
                campaign_expiry,
                record.expires_at.astimezone(UTC),
            )
            issued = issue_install_claim(
                campaign,
                settings.device_token_pepper,
                installation_session=installation_id,
                hardware_fingerprint=hardware_fingerprint,
                expires_at=expires_at,
                now=now,
            )
            issued.record.enrollment_request_id = record.id
            sealed = seal_retry_envelope(
                issued.token,
                hardware_fingerprint,
                settings.device_token_pepper,
                settings.session_secret,
                receipt=capability,
                now=now,
                lifetime=expires_at - now,
            )
            envelope = EnrollmentRequestClaimEnvelope(
                id=uuid4(),
                enrollment_request_id=record.id,
                claim_id=issued.record.id,
                receipt_digest=sealed.receipt_digest,
                fingerprint_digest=sealed.fingerprint_digest,
                encrypted_token=sealed.encrypted_token,
                encryption_nonce=sealed.encryption_nonce,
                expires_at=sealed.expires_at,
            )
            mark_request_claim_issued(record, campaign=campaign, now=now)
            session.add_all((issued.record, envelope))
            await append_audit_event(
                session,
                actor_kind="installer",
                actor_identifier=None,
                action="enrollment_request.claim_issued",
                object_kind="enrollment_request",
                object_identifier=str(record.id),
                request_id=audit_request_id(request),
                details={
                    "campaign_id": str(campaign.id),
                    "expires_at": issued.record.expires_at,
                    "status": record.status,
                },
                occurred_at=now,
            )
            await session.commit()
        except (EnrollmentDenied, ValueError) as error:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Enrollment request is no longer eligible",
            ) from error
        except HTTPException:
            raise
        except Exception:
            await session.rollback()
            raise
    return EnrollmentRequestClaimResponse(
        claim=issued.token, expires_at=issued.record.expires_at
    )
