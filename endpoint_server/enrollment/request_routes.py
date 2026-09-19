"""Public, capability-bound pre-enrollment request endpoints."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from endpoint_contracts import PreEnrollmentRequestCreateV1, PreEnrollmentRequestStatusV1
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.db.models import EnrollmentCampaign
from endpoint_server.network import observed_client_address

from .requests import (
    build_enrollment_request,
    evaluate_campaign_selection,
    persist_enrollment_request,
)


router = APIRouter(prefix="/api/v1/enrollment", tags=["enrollment-requests"])


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
            selection = evaluate_campaign_selection(
                result.scalars().all(),
                source_address=source_address,
                installer_release_id=body.installer_release_id,
                now=now,
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
            await persist_enrollment_request(
                session,
                request=record,
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
