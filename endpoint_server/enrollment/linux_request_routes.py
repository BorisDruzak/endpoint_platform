"""Linux-only source intake; shared canonical claim/recovery and admin controls."""
from datetime import UTC, datetime, timedelta
import hashlib
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from endpoint_contracts.enrollment import PreEnrollmentRequestStatusV1
from endpoint_contracts.linux_enrollment import LinuxPreEnrollmentRequestCreateV1
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.db.models import EnrollmentCampaign, EnrollmentClaim, EnrollmentRequest
from .campaigns import EnrollmentDenied, hardware_fingerprint_digest
from .linux_requests import resolve_enrollment_source, select_linux_campaign, build_linux_request
from .requests import enrollment_request_rate_limited, persist_enrollment_request, request_bindings_match, request_capability_matches
from .request_routes import (EnrollmentRequestStatusProof, EnrollmentRequestClaimProof, EnrollmentRequestClaimResponse,
    _source_address, enrollment_request_status, handoff_enrollment_request_claim)

router = APIRouter(prefix='/api/v1/enrollment/linux/requests', tags=['enrollment-requests'])


def project(record):
    return PreEnrollmentRequestStatusV1(schema_version='pre_enrollment_request_status_v1', request_id=record.id,
        status=record.status, reason=record.decision_reason, expires_at=record.expires_at)


@router.post('', response_model=PreEnrollmentRequestStatusV1, status_code=201,
    responses={200: {'model': PreEnrollmentRequestStatusV1, 'description': 'Recovered the exact existing request'}})
async def create_linux_request(body: LinuxPreEnrollmentRequestCreateV1, request: Request, response: Response):
    response.headers['Cache-Control'] = 'no-store'
    now = datetime.now(UTC)
    source_address = _source_address(request)
    pepper = request.app.state.settings.device_token_pepper
    async with request.app.state.session_provider() as session:
        try:
            # Serialize Linux intake (including no-campaign review requests)
            # without locking existing Windows requests or their AUTO campaign.
            intake_key = int.from_bytes(hashlib.sha256(b'endpoint-linux-request-intake-v1').digest()[:8], 'big', signed=True)
            await session.execute(select(func.pg_advisory_xact_lock(intake_key)))
            campaigns = (await session.scalars(select(EnrollmentCampaign).where(
                EnrollmentCampaign.target_platform == 'linux').order_by(EnrollmentCampaign.id).with_for_update())).all()
            source = await resolve_enrollment_source(session, body.native)
            prior = await session.scalar(select(EnrollmentClaim.id).where(
                EnrollmentClaim.fingerprint_digest == hardware_fingerprint_digest(body.hardware_fingerprint, pepper),
                EnrollmentClaim.device_id.is_not(None)).limit(1))
            selection = select_linux_campaign(campaigns, source_id=source.id, source_address=source_address,
                now=now, blocking_identity_conflict=prior is not None)
            record, binding = build_linux_request(body, source_id=source.id, selection=selection,
                source_address=source_address, pepper=pepper, now=now)
            existing = await session.scalar(select(EnrollmentRequest).where(
                EnrollmentRequest.installation_id_digest == record.installation_id_digest,
                EnrollmentRequest.platform == 'linux').order_by(EnrollmentRequest.created_at.desc()).limit(1))
            if existing is not None:
                from .linux_requests import LinuxEnrollmentBinding
                old_binding = await session.scalar(select(LinuxEnrollmentBinding).where(
                    LinuxEnrollmentBinding.enrollment_request_id == existing.id))
                if (old_binding is None or old_binding.native_release_id != source.id
                    or not request_capability_matches(body.request_capability, existing.request_capability_digest, pepper)
                    or not request_bindings_match(existing, installation_id=body.installation_id,
                        hardware_fingerprint=body.hardware_fingerprint, pepper=pepper)
                    or existing.source_address != str(source_address)):
                    raise HTTPException(409, 'Enrollment request identity is already owned')
                response.status_code = 200
                return project(existing)
            recent = (await session.scalars(select(EnrollmentRequest).where(
                EnrollmentRequest.created_at >= now - timedelta(hours=1)))).all()
            if enrollment_request_rate_limited(recent, record, now=now):
                raise HTTPException(429, 'Enrollment request rate limited')
            await persist_enrollment_request(session, request=record, selection=selection,
                request_id=audit_request_id(request), now=now)
            await session.flush()
            session.add(binding)
            await session.commit()
            return project(record)
        except EnrollmentDenied:
            await session.rollback()
            raise HTTPException(409, 'Exact registered Linux source required') from None
        except IntegrityError:
            await session.rollback()
            raise HTTPException(409, 'Enrollment request identity is already owned') from None


async def require_linux_request(request, request_id):
    async with request.app.state.session_provider() as session:
        platform = await session.scalar(select(EnrollmentRequest.platform).where(EnrollmentRequest.id == request_id))
        if platform != 'linux':
            raise HTTPException(404, 'Enrollment request not found')


@router.post('/{request_id}/status', response_model=PreEnrollmentRequestStatusV1)
async def linux_request_status(request_id: UUID, body: EnrollmentRequestStatusProof, request: Request, response: Response):
    response.headers['Cache-Control'] = 'no-store'
    await require_linux_request(request, request_id)
    return await enrollment_request_status(request_id, body, request)


@router.post('/{request_id}/claim', response_model=EnrollmentRequestClaimResponse)
async def linux_request_claim(request_id: UUID, body: EnrollmentRequestClaimProof, request: Request, response: Response):
    response.headers['Cache-Control'] = 'no-store'
    await require_linux_request(request, request_id)
    try:
        return await handoff_enrollment_request_claim(request_id, body, request)
    except IntegrityError:
        # The canonical handler rolls back before returning a capability collision.
        raise HTTPException(409, 'Enrollment capability conflicts with existing authority') from None
