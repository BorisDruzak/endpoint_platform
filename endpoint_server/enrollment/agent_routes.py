"""Agent-facing enrollment and credential delivery routes."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import func, select

from endpoint_contracts import (
    AgentEnrollmentDeliveryV1,
    AgentEnrollmentRequestV1,
    DeviceCredentialRotationV1,
    EnrollmentDeliveryProofV1,
)
from endpoint_contracts.json_types import validate_bounded_json
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import (
    Device,
    DeviceCredential,
    EnrollmentCampaign,
    EnrollmentClaim,
    EnrollmentEvent,
    EnrollmentRetryEnvelope,
)
from endpoint_server.network import observed_client_address

from .campaigns import (
    EnrollmentDenied,
    campaign_request_denial_category,
    campaign_token_digest,
    claim_token_digest,
    consume_install_claim,
    install_claim_binding_denial_category,
    reserve_campaign_use,
)
from .credentials import (
    DEFAULT_RETRY_ENVELOPE_LIFETIME,
    activate_pending_device_credential,
    begin_device_credential_rotation,
    device_credential_accepts_token,
    device_token_digest,
    device_token_matches,
    generate_device_token,
    recover_retry_token,
    retry_envelope_proof_matches,
    retry_receipt_digest,
    seal_retry_envelope,
)
from .delivery import ExpiredEnrollmentDelivery, derive_enrollment_receipt


router = APIRouter(prefix="/agent/v1", tags=["agent-enrollment"])
_DEVICE_IDENTIFIER_CONTEXT = b"endpoint-device-identity-v1\0"


def _denied() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Enrollment denied",
    )


def _delivery_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Enrollment delivery unavailable",
    )


def _invalid_device_credential() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid device credential",
    )


def _bearer_token(
    request: Request,
    *,
    denial: HTTPException | None = None,
) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if (
        not separator
        or scheme.lower() != "bearer"
        or not token
        or token != token.strip()
        or " " in token
    ):
        raise denial or _denied()
    return token


def _observed_source_address(request: Request):
    try:
        source = observed_client_address(request)
    except ValueError as error:
        raise _denied() from error
    if not any(
        source in network for network in request.app.state.settings.allowed_agent_cidrs
    ):
        raise _denied()
    return source


def _advisory_lock_key(device_identifier: str) -> int:
    raw = bytes.fromhex(device_identifier.removeprefix("dev_")[:16])
    return int.from_bytes(raw, byteorder="big", signed=True)


async def _lock_device_identity(session, device_identifier: str) -> None:
    """Serialize first creation even while no device row exists to lock."""
    await session.execute(
        select(func.pg_advisory_xact_lock(_advisory_lock_key(device_identifier)))
    )


def _device_identifier(
    installation_id: str,
    hardware_fingerprint: str,
    pepper: bytes,
) -> str:
    material = "\0".join((installation_id, hardware_fingerprint)).encode("utf-8")
    digest = hmac.new(
        pepper,
        _DEVICE_IDENTIFIER_CONTEXT + material,
        hashlib.sha256,
    ).hexdigest()
    return f"dev_{digest}"


def _policy_id(policy: dict[str, object], campaign_identifier: str) -> str:
    candidate = policy.get("policy_id")
    if (
        isinstance(candidate, str)
        and candidate
        and candidate == candidate.strip()
        and candidate.isascii()
        and len(candidate) <= 256
        and all(32 <= ord(character) <= 126 for character in candidate)
    ):
        return candidate
    return campaign_identifier


def _validated_delivery_policy(
    campaign: EnrollmentCampaign,
) -> dict[str, object]:
    policy = dict(campaign.policy)
    try:
        validate_bounded_json(policy)
    except (TypeError, ValueError) as error:
        raise EnrollmentDenied("Enrollment denied", category="campaign") from error
    return policy


async def _load_enrollment_authority(
    session,
    token: str,
    pepper: bytes,
) -> tuple[EnrollmentCampaign, EnrollmentClaim | None]:
    try:
        if token.startswith("ec_"):
            digest = campaign_token_digest(token, pepper)
            result = await session.execute(
                select(EnrollmentCampaign)
                .where(EnrollmentCampaign.token_digest == digest)
                .with_for_update()
            )
            campaign = result.scalar_one_or_none()
            if campaign is None:
                raise EnrollmentDenied("Enrollment denied", category="campaign")
            return campaign, None
        if token.startswith("ic_"):
            digest = claim_token_digest(token, pepper)
            claim_result = await session.execute(
                select(EnrollmentClaim)
                .where(EnrollmentClaim.claim_digest == digest)
                .with_for_update()
            )
            claim = claim_result.scalar_one_or_none()
            if claim is None:
                raise EnrollmentDenied("Enrollment denied", category="claim")
            campaign_result = await session.execute(
                select(EnrollmentCampaign)
                .where(EnrollmentCampaign.id == claim.campaign_id)
                .with_for_update()
            )
            campaign = campaign_result.scalar_one_or_none()
            if campaign is None:
                raise EnrollmentDenied("Enrollment denied", category="campaign")
            return campaign, claim
    except ValueError as error:
        raise EnrollmentDenied("Enrollment denied", category="claim") from error
    raise EnrollmentDenied("Enrollment denied", category="claim")


async def _load_existing_device(session, device_identifier: str) -> Device | None:
    result = await session.execute(
        select(Device)
        .where(Device.device_identifier == device_identifier)
        .with_for_update()
    )
    return result.scalar_one_or_none()


async def _existing_enrollment_matches(
    session,
    device: Device,
    campaign: EnrollmentCampaign,
    claim: EnrollmentClaim | None,
) -> bool:
    result = await session.execute(
        select(EnrollmentEvent).where(
            EnrollmentEvent.remote_identifier == str(device.id),
            EnrollmentEvent.event_kind == "device_enrolled",
        )
    )
    event = result.scalar_one_or_none()
    return (
        event is not None
        and event.campaign_id == campaign.id
        and event.claim_id == (claim.id if claim is not None else None)
    )


def _campaign_allows_delivery(
    campaign: EnrollmentCampaign,
    *,
    now: datetime,
) -> bool:
    return (
        campaign.revoked_at is None
        and campaign.disabled_at is None
        and campaign.expires_at is not None
        and campaign.expires_at.tzinfo is not None
        and now < campaign.expires_at
    )


def _claim_enrollment_denial_category(
    claim: EnrollmentClaim | None,
    *,
    now: datetime,
) -> str | None:
    """Return the internal category for a claim that became unavailable."""
    if claim is None:
        return None
    if claim.expires_at.tzinfo is None:
        return "claim"
    if now >= claim.expires_at.astimezone(UTC):
        return "expired"
    return None


async def _audit_enrollment_denial(
    session,
    *,
    request: Request,
    request_id: str,
    category: str,
) -> None:
    """Persist a non-secret denial category after the enrollment rollback."""
    try:
        await append_audit_event(
            session,
            actor_kind="agent",
            actor_identifier=None,
            action="enrollment.denied",
            object_kind="agent_enrollment",
            object_identifier="denied",
            request_id=request_id,
            details={"category": category},
            occurred_at=datetime.now(UTC),
        )
        await session.commit()
    except Exception:
        await session.rollback()


def _raise_if_delivery_expired(
    envelope: EnrollmentRetryEnvelope,
    *,
    observed_at: datetime,
) -> None:
    if (
        envelope.expires_at.tzinfo is None
        or observed_at >= envelope.expires_at.astimezone(UTC)
    ):
        raise ExpiredEnrollmentDelivery(
            envelope,
            observed_at=observed_at,
        )


async def _load_delivery(
    session,
    receipt: str,
    hardware_fingerprint: str,
    *,
    pepper: bytes,
    session_secret: bytes,
) -> tuple[
    EnrollmentRetryEnvelope,
    DeviceCredential,
    Device,
    EnrollmentCampaign,
    EnrollmentEvent,
    str,
]:
    try:
        digest = retry_receipt_digest(receipt, pepper)
    except (UnicodeEncodeError, ValueError) as error:
        raise EnrollmentDenied("Enrollment delivery unavailable") from error
    envelope_result = await session.execute(
        select(EnrollmentRetryEnvelope)
        .where(EnrollmentRetryEnvelope.receipt_digest == digest)
        .with_for_update()
    )
    envelope = envelope_result.scalar_one_or_none()
    if envelope is None:
        raise EnrollmentDenied("Enrollment delivery unavailable")
    if not retry_envelope_proof_matches(
        receipt,
        hardware_fingerprint,
        envelope,
        pepper,
    ):
        raise EnrollmentDenied("Enrollment delivery unavailable")
    checked_at = datetime.now(UTC)
    _raise_if_delivery_expired(envelope, observed_at=checked_at)
    credential_result = await session.execute(
        select(DeviceCredential)
        .where(DeviceCredential.id == envelope.device_credential_id)
        .with_for_update()
    )
    credential = credential_result.scalar_one_or_none()
    checked_at = datetime.now(UTC)
    _raise_if_delivery_expired(envelope, observed_at=checked_at)
    if credential is None or credential.pending_token_digest is not None:
        raise EnrollmentDenied("Enrollment delivery unavailable")
    token = recover_retry_token(
        receipt,
        hardware_fingerprint,
        envelope,
        pepper,
        session_secret,
        now=checked_at,
    )
    if (
        token is None
        or not device_token_matches(token, credential.token_digest, pepper)
        or not device_credential_accepts_token(
            credential,
            token,
            pepper,
            now=checked_at,
        )
    ):
        raise EnrollmentDenied("Enrollment delivery unavailable")
    device_result = await session.execute(
        select(Device).where(Device.id == credential.device_id)
    )
    device = device_result.scalar_one_or_none()
    if device is None:
        raise EnrollmentDenied("Enrollment delivery unavailable")
    event_result = await session.execute(
        select(EnrollmentEvent).where(
            EnrollmentEvent.remote_identifier == str(device.id),
            EnrollmentEvent.event_kind == "device_enrolled",
        )
    )
    event = event_result.scalar_one_or_none()
    if event is None or event.campaign_id is None:
        raise EnrollmentDenied("Enrollment delivery unavailable")
    campaign_result = await session.execute(
        select(EnrollmentCampaign).where(EnrollmentCampaign.id == event.campaign_id)
    )
    campaign = campaign_result.scalar_one_or_none()
    checked_at = datetime.now(UTC)
    _raise_if_delivery_expired(envelope, observed_at=checked_at)
    if (
        device.retired_at is not None
        or not device_credential_accepts_token(
            credential,
            token,
            pepper,
            now=checked_at,
        )
        or campaign is None
        or event.remote_identifier != str(device.id)
        or not _campaign_allows_delivery(campaign, now=checked_at)
    ):
        raise EnrollmentDenied("Enrollment delivery unavailable")
    _validated_delivery_policy(campaign)
    return envelope, credential, device, campaign, event, token


async def _destroy_observed_expired_delivery(
    session,
    *,
    envelope: EnrollmentRetryEnvelope,
    request: Request,
    source_address: object,
    source: str,
    occurred_at: datetime,
) -> None:
    """Destroy one proven expired envelope in the observing transaction."""
    await session.delete(envelope)
    await append_audit_event(
        session,
        actor_kind="agent",
        actor_identifier=None,
        action="enrollment.delivery_expired",
        object_kind="enrollment_retry_envelope",
        object_identifier=str(envelope.id),
        request_id=audit_request_id(request),
        details={
            "source": source,
            "source_address": str(source_address),
        },
        occurred_at=occurred_at,
    )
    await session.commit()


@router.post(
    "/enroll",
    status_code=status.HTTP_201_CREATED,
    response_model=AgentEnrollmentDeliveryV1,
)
async def enroll_agent(
    body: AgentEnrollmentRequestV1,
    request: Request,
    response: Response,
) -> AgentEnrollmentDeliveryV1:
    """Atomically reserve a campaign use and deliver a retry-safe credential."""
    token = _bearer_token(request)
    source_address = _observed_source_address(request)
    settings = request.app.state.settings
    request_id = audit_request_id(request)

    async with request.app.state.session_provider() as session:
        expired_cleanup_committed = False
        try:
            campaign, claim = await _load_enrollment_authority(
                session,
                token,
                settings.device_token_pepper,
            )
            issued_at = datetime.now(UTC)
            category = campaign_request_denial_category(
                campaign,
                now=issued_at,
                source_address=source_address,
                platform=body.platform,
            )
            if category is not None:
                raise EnrollmentDenied("Enrollment denied", category=category)
            policy = _validated_delivery_policy(campaign)
            device_identifier = _device_identifier(
                body.installation_id,
                body.hardware_fingerprint,
                settings.device_token_pepper,
            )
            delivery_receipt = derive_enrollment_receipt(
                settings.session_secret,
                delivery_nonce=body.delivery_nonce,
                device_identifier=device_identifier,
                campaign_id=campaign.id,
                claim_id=claim.id if claim is not None else None,
                platform=body.platform,
                requested_at=body.requested_at,
            )
            await _lock_device_identity(session, device_identifier)
            existing_device = await _load_existing_device(
                session,
                device_identifier,
            )
            issued_at = datetime.now(UTC)
            category = campaign_request_denial_category(
                campaign,
                now=issued_at,
                source_address=source_address,
                platform=body.platform,
            )
            if category is not None:
                raise EnrollmentDenied("Enrollment denied", category=category)
            category = _claim_enrollment_denial_category(claim, now=issued_at)
            if category is not None:
                raise EnrollmentDenied("Enrollment denied", category=category)
            if existing_device is not None:
                if claim is not None and claim.device_id != existing_device.id:
                    raise EnrollmentDenied("Enrollment denied", category="claim")
                category = (
                    install_claim_binding_denial_category(
                        claim,
                        settings.device_token_pepper,
                        installation_session=body.installation_id,
                        hardware_fingerprint=body.hardware_fingerprint,
                    )
                    if claim is not None
                    else None
                )
                if category is not None:
                    raise EnrollmentDenied("Enrollment denied", category=category)
                if await _existing_enrollment_matches(
                    session,
                    existing_device,
                    campaign,
                    claim,
                ):
                    try:
                        (
                            envelope,
                            _,
                            device,
                            delivery_campaign,
                            event,
                            raw_device_token,
                        ) = await _load_delivery(
                            session,
                            delivery_receipt,
                            body.hardware_fingerprint,
                            pepper=settings.device_token_pepper,
                            session_secret=settings.session_secret,
                        )
                    except ExpiredEnrollmentDelivery as error:
                        await _destroy_observed_expired_delivery(
                            session,
                            envelope=error.envelope,
                            request=request,
                            source_address=source_address,
                            source="observed_enroll_retry",
                            occurred_at=error.observed_at,
                        )
                        expired_cleanup_committed = True
                        raise _delivery_unavailable() from error
                    except EnrollmentDenied as error:
                        raise _delivery_unavailable() from error
                    if (
                        device.id != existing_device.id
                        or delivery_campaign.id != campaign.id
                        or event.claim_id != (claim.id if claim is not None else None)
                    ):
                        raise _delivery_unavailable()
                    campaign = delivery_campaign
                    issued_envelope = envelope
                    issued_at = envelope.expires_at - DEFAULT_RETRY_ENVELOPE_LIFETIME
                    response.status_code = status.HTTP_200_OK
                    return AgentEnrollmentDeliveryV1(
                        schema_version="agent_enrollment_delivery_v1",
                        device_id=device.id,
                        policy_id=_policy_id(
                            policy,
                            campaign.campaign_identifier,
                        ),
                        policy=policy,
                        enrollment_receipt=delivery_receipt,
                        device_token=raw_device_token,
                        issued_at=issued_at,
                    )
                raise EnrollmentDenied("Enrollment denied", category="claim")
            if claim is None:
                campaign = await reserve_campaign_use(
                    session,
                    token,
                    settings.device_token_pepper,
                    source_address=source_address,
                    platform=body.platform,
                    actor_kind="agent",
                    actor_identifier=None,
                    request_id=request_id,
                    now=issued_at,
                )
            else:
                claim = await consume_install_claim(
                    session,
                    token,
                    settings.device_token_pepper,
                    installation_session=body.installation_id,
                    hardware_fingerprint=body.hardware_fingerprint,
                    source_address=source_address,
                    platform=body.platform,
                    actor_kind="agent",
                    actor_identifier=None,
                    request_id=request_id,
                    now=issued_at,
                )
            device = Device(
                id=uuid4(),
                device_identifier=device_identifier,
                display_name=campaign.label,
                retired_at=None,
            )
            raw_device_token = generate_device_token()
            credential = DeviceCredential(
                id=uuid4(),
                device_id=device.id,
                credential_identifier=secrets.token_hex(16),
                token_digest=device_token_digest(
                    raw_device_token,
                    settings.device_token_pepper,
                ),
                pending_token_digest=None,
                rotation_overlap_expires_at=None,
                expires_at=None,
                revoked_at=None,
            )
            issued_envelope = seal_retry_envelope(
                raw_device_token,
                body.hardware_fingerprint,
                settings.device_token_pepper,
                settings.session_secret,
                receipt=delivery_receipt,
                now=issued_at,
            )
            envelope = EnrollmentRetryEnvelope(
                id=uuid4(),
                device_credential_id=credential.id,
                receipt_digest=issued_envelope.receipt_digest,
                fingerprint_digest=issued_envelope.fingerprint_digest,
                encrypted_token=issued_envelope.encrypted_token,
                encryption_nonce=issued_envelope.encryption_nonce,
                expires_at=issued_envelope.expires_at,
            )
            event = EnrollmentEvent(
                id=uuid4(),
                campaign_id=campaign.id,
                claim_id=claim.id if claim is not None else None,
                event_kind="device_enrolled",
                remote_identifier=str(device.id),
            )
            if claim is not None:
                claim.device_id = device.id
            session.add_all((device, credential, envelope, event))
            await append_audit_event(
                session,
                actor_kind="agent",
                actor_identifier=str(device.id),
                action="device.enrolled",
                object_kind="device",
                object_identifier=str(device.id),
                request_id=request_id,
                details={
                    "campaign_id": str(campaign.id),
                    "platform": body.platform,
                    "source_address": str(source_address),
                },
                occurred_at=issued_at,
            )
            await session.commit()
        except EnrollmentDenied as error:
            await session.rollback()
            await _audit_enrollment_denial(
                session,
                request=request,
                request_id=request_id,
                category=error.category,
            )
            raise _denied() from error
        except HTTPException:
            if not expired_cleanup_committed:
                await session.rollback()
            raise
        except Exception:
            await session.rollback()
            raise

    return AgentEnrollmentDeliveryV1(
        schema_version="agent_enrollment_delivery_v1",
        device_id=device.id,
        policy_id=_policy_id(policy, campaign.campaign_identifier),
        policy=policy,
        enrollment_receipt=issued_envelope.receipt,
        device_token=raw_device_token,
        issued_at=issued_at,
    )


@router.post(
    "/enroll/retry",
    response_model=AgentEnrollmentDeliveryV1,
)
async def retry_enrollment_delivery(
    body: EnrollmentDeliveryProofV1,
    request: Request,
) -> AgentEnrollmentDeliveryV1:
    """Recover an unacknowledged enrollment credential before envelope expiry."""
    source_address = _observed_source_address(request)
    settings = request.app.state.settings
    receipt = body.enrollment_receipt
    hardware_fingerprint = body.hardware_fingerprint
    async with request.app.state.session_provider() as session:
        try:
            envelope, _, device, campaign, _, token = await _load_delivery(
                session,
                receipt,
                hardware_fingerprint,
                pepper=settings.device_token_pepper,
                session_secret=settings.session_secret,
            )
        except ExpiredEnrollmentDelivery as error:
            await _destroy_observed_expired_delivery(
                session,
                envelope=error.envelope,
                request=request,
                source_address=source_address,
                source="observed_retry",
                occurred_at=error.observed_at,
            )
            raise _delivery_unavailable() from error
        except EnrollmentDenied as error:
            raise _delivery_unavailable() from error
    policy = dict(campaign.policy)
    return AgentEnrollmentDeliveryV1(
        schema_version="agent_enrollment_delivery_v1",
        device_id=device.id,
        policy_id=_policy_id(policy, campaign.campaign_identifier),
        policy=policy,
        enrollment_receipt=receipt,
        device_token=token,
        issued_at=envelope.expires_at - DEFAULT_RETRY_ENVELOPE_LIFETIME,
    )


@router.post(
    "/enroll/ack",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
async def acknowledge_enrollment_delivery(
    body: EnrollmentDeliveryProofV1,
    request: Request,
) -> None:
    """Delete one correctly bound delivery envelope after durable agent storage."""
    source_address = _observed_source_address(request)
    settings = request.app.state.settings
    receipt = body.enrollment_receipt
    hardware_fingerprint = body.hardware_fingerprint
    async with request.app.state.session_provider() as session:
        try:
            envelope, _, device, _, _, _ = await _load_delivery(
                session,
                receipt,
                hardware_fingerprint,
                pepper=settings.device_token_pepper,
                session_secret=settings.session_secret,
            )
            now = datetime.now(UTC)
            await session.delete(envelope)
            await append_audit_event(
                session,
                actor_kind="agent",
                actor_identifier=str(device.id),
                action="enrollment.delivery_acknowledged",
                object_kind="device",
                object_identifier=str(device.id),
                request_id=audit_request_id(request),
                details={"source_address": str(source_address)},
                occurred_at=now,
            )
            await session.commit()
        except ExpiredEnrollmentDelivery as error:
            await _destroy_observed_expired_delivery(
                session,
                envelope=error.envelope,
                request=request,
                source_address=source_address,
                source="observed_ack",
                occurred_at=error.observed_at,
            )
            raise _delivery_unavailable() from error
        except EnrollmentDenied as error:
            await session.rollback()
            raise _delivery_unavailable() from error
        except Exception:
            await session.rollback()
            raise


@router.post(
    "/credentials/rotate",
    status_code=status.HTTP_201_CREATED,
    response_model=DeviceCredentialRotationV1,
)
async def rotate_device_credential(
    request: Request,
) -> DeviceCredentialRotationV1:
    """Create one pending token using only the still-valid current bearer."""
    _observed_source_address(request)
    token = _bearer_token(request, denial=_invalid_device_credential())
    settings = request.app.state.settings
    try:
        digest = device_token_digest(token, settings.device_token_pepper)
    except ValueError as error:
        raise _invalid_device_credential() from error
    async with request.app.state.session_provider() as session:
        result = await session.execute(
            select(DeviceCredential)
            .where(DeviceCredential.token_digest == digest)
            .with_for_update()
        )
        credential = result.scalar_one_or_none()
        now = datetime.now(UTC)
        if (
            credential is None
            or not device_token_matches(
                token,
                credential.token_digest,
                settings.device_token_pepper,
            )
            or not device_credential_accepts_token(
                credential,
                token,
                settings.device_token_pepper,
                now=now,
            )
        ):
            raise _invalid_device_credential()
        try:
            issued = begin_device_credential_rotation(
                credential,
                settings.device_token_pepper,
                now=now,
            )
        except ValueError as error:
            if credential.pending_token_digest is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Credential rotation already pending",
                ) from error
            raise _invalid_device_credential() from error
        try:
            await append_audit_event(
                session,
                actor_kind="agent",
                actor_identifier=str(credential.device_id),
                action="device_credential.rotation_started",
                object_kind="device_credential",
                object_identifier=str(credential.id),
                request_id=audit_request_id(request),
                details={"overlap_expires_at": credential.rotation_overlap_expires_at},
                occurred_at=now,
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return DeviceCredentialRotationV1(
        schema_version="device_credential_rotation_v1",
        device_token=issued.token,
        overlap_expires_at=credential.rotation_overlap_expires_at,
    )


@router.post(
    "/credentials/activate",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
async def activate_device_credential(
    request: Request,
) -> None:
    """Promote the matching pending bearer and immediately retire the old one."""
    _observed_source_address(request)
    token = _bearer_token(request, denial=_invalid_device_credential())
    settings = request.app.state.settings
    try:
        digest = device_token_digest(token, settings.device_token_pepper)
    except ValueError as error:
        raise _invalid_device_credential() from error
    async with request.app.state.session_provider() as session:
        result = await session.execute(
            select(DeviceCredential)
            .where(DeviceCredential.pending_token_digest == digest)
            .with_for_update()
        )
        credential = result.scalar_one_or_none()
        now = datetime.now(UTC)
        if (
            credential is None
            or credential.pending_token_digest is None
            or not device_token_matches(
                token,
                credential.pending_token_digest,
                settings.device_token_pepper,
            )
            or not activate_pending_device_credential(
                credential,
                token,
                settings.device_token_pepper,
                now=now,
            )
        ):
            raise _invalid_device_credential()
        try:
            await append_audit_event(
                session,
                actor_kind="agent",
                actor_identifier=str(credential.device_id),
                action="device_credential.rotation_activated",
                object_kind="device_credential",
                object_identifier=str(credential.id),
                request_id=audit_request_id(request),
                details={},
                occurred_at=now,
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
