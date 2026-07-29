"""Retry-safe enrollment delivery derivation, recovery, and cleanup."""

from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import EnrollmentRetryEnvelope


_DELIVERY_RECEIPT_CONTEXT = b"endpoint-enrollment-delivery-receipt-v1\0"
_OPAQUE_SECRET_LENGTH = 43
_URLSAFE_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


class ExpiredEnrollmentDelivery(Exception):
    """A correctly proven delivery envelope that must now be destroyed."""

    def __init__(
        self,
        envelope: EnrollmentRetryEnvelope,
        *,
        observed_at: datetime,
    ) -> None:
        super().__init__("Enrollment delivery unavailable")
        self.envelope = envelope
        self.observed_at = observed_at


def _length_prefixed(value: bytes) -> bytes:
    if len(value) > (2**32 - 1):
        raise ValueError("canonical enrollment field is too long")
    return len(value).to_bytes(4, byteorder="big") + value


def derive_enrollment_receipt(
    session_secret: bytes,
    *,
    delivery_nonce: str,
    device_identifier: str,
    campaign_id: UUID,
    claim_id: UUID | None,
    platform: str,
    requested_at: datetime,
) -> str:
    """Derive one opaque receipt from a client-known nonce and exact intent."""
    if not session_secret:
        raise ValueError("session secret must not be empty")
    if (
        len(delivery_nonce) != _OPAQUE_SECRET_LENGTH
        or not delivery_nonce.isascii()
        or any(character not in _URLSAFE_CHARACTERS for character in delivery_nonce)
    ):
        raise ValueError("delivery nonce must be 43 URL-safe characters")
    if requested_at.tzinfo is None:
        raise ValueError("requested_at must be timezone-aware")
    try:
        nonce_bytes = delivery_nonce.encode("ascii")
        identifier_bytes = device_identifier.encode("ascii")
        platform_bytes = platform.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("canonical enrollment text must be ASCII") from error
    timestamp_bytes = (
        requested_at.astimezone(UTC).isoformat(timespec="microseconds").encode("ascii")
    )
    message = b"".join(
        (
            _DELIVERY_RECEIPT_CONTEXT,
            _length_prefixed(nonce_bytes),
            _length_prefixed(identifier_bytes),
            _length_prefixed(campaign_id.bytes),
            _length_prefixed(claim_id.bytes if claim_id is not None else b""),
            _length_prefixed(platform_bytes),
            _length_prefixed(timestamp_bytes),
        )
    )
    digest = hmac.new(session_secret, message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


async def cleanup_expired_retry_envelopes(
    session: AsyncSession,
    *,
    request_id: str,
    now: datetime | None = None,
    limit: int = 100,
) -> int:
    """Lock, delete, and audit one bounded batch of expired envelopes."""
    if not 1 <= limit <= 100:
        raise ValueError("cleanup limit must be between 1 and 100")
    cleaned_at = now or datetime.now(UTC)
    if cleaned_at.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if not request_id.strip():
        raise ValueError("request_id must not be blank")
    cleaned_at = cleaned_at.astimezone(UTC)
    result = await session.execute(
        select(EnrollmentRetryEnvelope)
        .where(EnrollmentRetryEnvelope.expires_at <= cleaned_at)
        .order_by(
            EnrollmentRetryEnvelope.expires_at,
            EnrollmentRetryEnvelope.id,
        )
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    envelopes = result.scalars().all()
    for envelope in envelopes:
        await session.delete(envelope)
        await append_audit_event(
            session,
            actor_kind="system",
            actor_identifier=None,
            action="enrollment.delivery_expired",
            object_kind="enrollment_retry_envelope",
            object_identifier=str(envelope.id),
            request_id=request_id,
            details={"source": "periodic_cleanup"},
            occurred_at=cleaned_at,
        )
    return len(envelopes)
