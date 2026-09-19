"""Server-observed completion checks for universal Windows enrollment."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import func, select

from endpoint_contracts import PreEnrollmentRequestStatusV1
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.context.models import ContextCurrent, ContextSnapshot
from endpoint_server.db.models import DeviceSession, EnrollmentRequest

from .requests import request_capability_matches, transition_request_status


router = APIRouter(prefix="/api/v1/enrollment", tags=["enrollment-verification"])
_PRESENCE_TTL = timedelta(seconds=90)


class VerificationProof(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_capability: SecretStr = Field(min_length=43, max_length=43)


@router.post("/requests/{request_id}/verify", response_model=PreEnrollmentRequestStatusV1)
async def verify_enrollment_completion(
    request_id: UUID, body: VerificationProof, request: Request
) -> PreEnrollmentRequestStatusV1:
    """Advance only a proven request from device registration to completion."""
    now = datetime.now(UTC)
    async with request.app.state.session_provider() as session:
        record = (
            await session.execute(
                select(EnrollmentRequest)
                .where(EnrollmentRequest.id == request_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if record is None or not request_capability_matches(
            body.request_capability.get_secret_value(),
            record.request_capability_digest,
            request.app.state.settings.device_token_pepper,
        ):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Enrollment request not found")
        if record.status in {"claim_issued", "enrolling"}:
            return PreEnrollmentRequestStatusV1(
                schema_version="pre_enrollment_request_status_v1",
                request_id=record.id,
                status=record.status,
                reason="WAITING_DEVICE_REGISTRATION",
                expires_at=record.expires_at,
            )
        if record.device_id is None or record.status not in {"device_registered", "waiting_wss", "completed"}:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Enrollment request is not ready")
        if record.status != "completed":
            observed_at = func.coalesce(DeviceSession.last_seen_at, DeviceSession.created_at)
            latest_session = (
                await session.execute(
                    select(DeviceSession)
                    .where(DeviceSession.device_id == record.device_id)
                    .order_by(observed_at.desc(), DeviceSession.id.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            fresh_presence = (
                latest_session is not None
                and latest_session.closed_at is None
                and latest_session.last_seen_at is not None
                and latest_session.last_seen_at.astimezone(UTC) <= now
                and now - latest_session.last_seen_at.astimezone(UTC) <= _PRESENCE_TTL
            )
            if not fresh_presence:
                if record.status == "device_registered":
                    transition_request_status(record.status, "waiting_wss")
                    record.status = "waiting_wss"
                    record.updated_at = now
                    await session.commit()
                return PreEnrollmentRequestStatusV1(
                    schema_version="pre_enrollment_request_status_v1", request_id=record.id,
                    status=record.status, reason="WAITING_WSS", expires_at=record.expires_at
                )
            baseline = (
                await session.execute(
                    select(ContextSnapshot)
                    .join(ContextCurrent, ContextCurrent.snapshot_id == ContextSnapshot.id)
                    .where(
                        ContextCurrent.device_id == record.device_id,
                        ContextCurrent.profile == "baseline_v1",
                    )
                    .limit(1)
                )
            ).scalar_one_or_none()
            if baseline is None:
                if record.status == "device_registered":
                    transition_request_status(record.status, "waiting_wss")
                    record.status = "waiting_wss"
                    record.updated_at = now
                    await session.commit()
                return PreEnrollmentRequestStatusV1(
                    schema_version="pre_enrollment_request_status_v1", request_id=record.id,
                    status="waiting_wss", reason="WAITING_BASELINE", expires_at=record.expires_at
                )
            if record.status == "device_registered":
                transition_request_status(record.status, "waiting_wss")
                record.status = "waiting_wss"
            transition_request_status(record.status, "completed")
            record.status = "completed"
            record.updated_at = now
            await append_audit_event(
                session, actor_kind="installer", actor_identifier=None,
                action="installer_wss_verified", object_kind="enrollment_request",
                object_identifier=str(record.id), request_id=audit_request_id(request),
                details={"device_id": str(record.device_id), "status": record.status}, occurred_at=now,
            )
            await session.commit()
    return PreEnrollmentRequestStatusV1(
        schema_version="pre_enrollment_request_status_v1", request_id=record.id,
        status=record.status, reason=record.decision_reason, expires_at=record.expires_at
    )
