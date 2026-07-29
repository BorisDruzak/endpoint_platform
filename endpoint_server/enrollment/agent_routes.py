"""Agent-facing enrollment and credential delivery routes."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import func, select

from endpoint_contracts import EnrollmentRequestV1
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import (
    Device,
    DeviceCredential,
    EnrollmentCampaign,
    EnrollmentClaim,
    EnrollmentEvent,
    EnrollmentRetryEnvelope,
)

from .campaigns import (
    EnrollmentDenied,
    campaign_request_matches,
    campaign_token_digest,
    claim_token_digest,
    consume_install_claim,
    install_claim_bindings_match,
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
    retry_receipt_digest,
    seal_retry_envelope,
)


router = APIRouter(prefix="/agent/v1", tags=["agent-enrollment"])
_DEVICE_IDENTIFIER_CONTEXT = b"endpoint-device-identity-v1\0"


class EnrollmentDeliveryResponse(BaseModel):
    """One-time enrollment delivery containing secret transport material."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["enrollment_response_v1"] = "enrollment_response_v1"
    device_id: UUID
    policy_id: str
    policy: dict[str, object]
    enrollment_receipt: str = Field(repr=False)
    device_token: str = Field(repr=False)
    issued_at: datetime


class EnrollmentDeliveryRequest(BaseModel):
    """Secret-bound receipt recovery or acknowledgement input."""

    model_config = ConfigDict(extra="forbid")

    receipt: SecretStr = Field(min_length=1, max_length=256)
    hardware_fingerprint: SecretStr = Field(min_length=8, max_length=256)


class CredentialRotationResponse(BaseModel):
    """Show-once pending device credential and overlap deadline."""

    model_config = ConfigDict(extra="forbid")

    device_token: str = Field(repr=False)
    overlap_expires_at: datetime


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


def _already_enrolled() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Enrollment already completed",
    )


def _request_id(request: Request) -> str:
    supplied = request.headers.get("x-request-id", "").strip()
    return supplied or f"request-{uuid4().hex}"


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
    if request.client is None:
        raise _denied()
    try:
        source = ip_address(request.client.host)
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
                raise EnrollmentDenied("Enrollment denied")
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
                raise EnrollmentDenied("Enrollment denied")
            campaign_result = await session.execute(
                select(EnrollmentCampaign)
                .where(EnrollmentCampaign.id == claim.campaign_id)
                .with_for_update()
            )
            campaign = campaign_result.scalar_one_or_none()
            if campaign is None:
                raise EnrollmentDenied("Enrollment denied")
            return campaign, claim
    except ValueError as error:
        raise EnrollmentDenied("Enrollment denied") from error
    raise EnrollmentDenied("Enrollment denied")


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


async def _load_delivery(
    session,
    receipt: str,
    hardware_fingerprint: str,
    *,
    pepper: bytes,
    session_secret: bytes,
    now: datetime,
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
    token = recover_retry_token(
        receipt,
        hardware_fingerprint,
        envelope,
        pepper,
        session_secret,
        now=now,
    )
    if token is None:
        raise EnrollmentDenied("Enrollment delivery unavailable")
    credential_result = await session.execute(
        select(DeviceCredential)
        .where(DeviceCredential.id == envelope.device_credential_id)
        .with_for_update()
    )
    credential = credential_result.scalar_one_or_none()
    if (
        credential is None
        or credential.pending_token_digest is not None
        or not device_token_matches(token, credential.token_digest, pepper)
        or not device_credential_accepts_token(
            credential,
            token,
            pepper,
            now=now,
        )
    ):
        raise EnrollmentDenied("Enrollment delivery unavailable")
    device_result = await session.execute(
        select(Device).where(Device.id == credential.device_id)
    )
    device = device_result.scalar_one_or_none()
    if device is None or device.retired_at is not None:
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
    if (
        campaign is None
        or event.remote_identifier != str(device.id)
        or not _campaign_allows_delivery(campaign, now=now)
    ):
        raise EnrollmentDenied("Enrollment delivery unavailable")
    return envelope, credential, device, campaign, event, token


@router.post(
    "/enroll",
    status_code=status.HTTP_201_CREATED,
    response_model=EnrollmentDeliveryResponse,
)
async def enroll_agent(
    body: Annotated[EnrollmentRequestV1, Field()],
    request: Request,
) -> EnrollmentDeliveryResponse:
    """Atomically reserve a campaign use and deliver a retry-safe credential."""
    token = _bearer_token(request)
    source_address = _observed_source_address(request)
    issued_at = datetime.now(UTC)
    settings = request.app.state.settings
    request_id = _request_id(request)

    async with request.app.state.session_provider() as session:
        try:
            campaign, claim = await _load_enrollment_authority(
                session,
                token,
                settings.device_token_pepper,
            )
            if not campaign_request_matches(
                campaign,
                now=issued_at,
                source_address=source_address,
                platform=body.platform,
            ):
                raise EnrollmentDenied("Enrollment denied")
            device_identifier = _device_identifier(
                body.installation_id,
                body.hardware_fingerprint,
                settings.device_token_pepper,
            )
            await _lock_device_identity(session, device_identifier)
            existing_device = await _load_existing_device(
                session,
                device_identifier,
            )
            if existing_device is not None:
                bindings_match = claim is None or (
                    claim.device_id == existing_device.id
                    and install_claim_bindings_match(
                        claim,
                        settings.device_token_pepper,
                        installation_session=body.installation_id,
                        hardware_fingerprint=body.hardware_fingerprint,
                    )
                )
                if bindings_match and await _existing_enrollment_matches(
                    session,
                    existing_device,
                    campaign,
                    claim,
                ):
                    raise _already_enrolled()
                raise EnrollmentDenied("Enrollment denied")
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
            raise _denied() from error
        except HTTPException:
            await session.rollback()
            raise
        except Exception:
            await session.rollback()
            raise

    policy = dict(campaign.policy)
    return EnrollmentDeliveryResponse(
        device_id=str(device.id),
        policy_id=_policy_id(policy, campaign.campaign_identifier),
        policy=policy,
        enrollment_receipt=issued_envelope.receipt,
        device_token=raw_device_token,
        issued_at=issued_at,
    )


@router.post(
    "/enroll/retry",
    response_model=EnrollmentDeliveryResponse,
)
async def retry_enrollment_delivery(
    body: EnrollmentDeliveryRequest,
    request: Request,
) -> EnrollmentDeliveryResponse:
    """Recover an unacknowledged enrollment credential before envelope expiry."""
    _observed_source_address(request)
    settings = request.app.state.settings
    now = datetime.now(UTC)
    receipt = body.receipt.get_secret_value()
    hardware_fingerprint = body.hardware_fingerprint.get_secret_value()
    async with request.app.state.session_provider() as session:
        try:
            envelope, _, device, campaign, _, token = await _load_delivery(
                session,
                receipt,
                hardware_fingerprint,
                pepper=settings.device_token_pepper,
                session_secret=settings.session_secret,
                now=now,
            )
        except EnrollmentDenied as error:
            raise _delivery_unavailable() from error
    policy = dict(campaign.policy)
    return EnrollmentDeliveryResponse(
        device_id=str(device.id),
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
    body: EnrollmentDeliveryRequest,
    request: Request,
) -> None:
    """Delete one correctly bound delivery envelope after durable agent storage."""
    source_address = _observed_source_address(request)
    settings = request.app.state.settings
    now = datetime.now(UTC)
    receipt = body.receipt.get_secret_value()
    hardware_fingerprint = body.hardware_fingerprint.get_secret_value()
    async with request.app.state.session_provider() as session:
        try:
            envelope, _, device, _, _, _ = await _load_delivery(
                session,
                receipt,
                hardware_fingerprint,
                pepper=settings.device_token_pepper,
                session_secret=settings.session_secret,
                now=now,
            )
            await session.delete(envelope)
            await append_audit_event(
                session,
                actor_kind="agent",
                actor_identifier=str(device.id),
                action="enrollment.delivery_acknowledged",
                object_kind="device",
                object_identifier=str(device.id),
                request_id=_request_id(request),
                details={"source_address": str(source_address)},
                occurred_at=now,
            )
            await session.commit()
        except EnrollmentDenied as error:
            await session.rollback()
            raise _delivery_unavailable() from error
        except Exception:
            await session.rollback()
            raise


@router.post(
    "/credentials/rotate",
    status_code=status.HTTP_201_CREATED,
    response_model=CredentialRotationResponse,
)
async def rotate_device_credential(
    request: Request,
) -> CredentialRotationResponse:
    """Create one pending token using only the still-valid current bearer."""
    _observed_source_address(request)
    token = _bearer_token(request, denial=_invalid_device_credential())
    settings = request.app.state.settings
    now = datetime.now(UTC)
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
                request_id=_request_id(request),
                details={"overlap_expires_at": credential.rotation_overlap_expires_at},
                occurred_at=now,
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return CredentialRotationResponse(
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
    now = datetime.now(UTC)
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
                request_id=_request_id(request),
                details={},
                occurred_at=now,
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
