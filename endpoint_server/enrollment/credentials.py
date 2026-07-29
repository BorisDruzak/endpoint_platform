"""Device bearer credential and retry-envelope primitives."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DEVICE_TOKEN_BYTES = 32
RETRY_RECEIPT_BYTES = 32
DEFAULT_RETRY_ENVELOPE_LIFETIME = timedelta(minutes=5)
MAX_RETRY_ENVELOPE_LIFETIME = timedelta(minutes=15)
DEFAULT_ROTATION_OVERLAP = timedelta(minutes=10)
_AES_GCM_NONCE_BYTES = 12
_RECEIPT_DIGEST_CONTEXT = b"endpoint-enrollment-receipt-v1\0"
_FINGERPRINT_DIGEST_CONTEXT = b"endpoint-enrollment-fingerprint-v1\0"
_ENVELOPE_KEY_CONTEXT = b"endpoint-enrollment-envelope-key-v1"


class RetryEnvelope(Protocol):
    """Stored fields required to recover one encrypted retry token."""

    receipt_digest: str
    fingerprint_digest: str
    encrypted_token: bytes
    encryption_nonce: bytes
    expires_at: datetime


class DeviceCredentialState(Protocol):
    """Mutable credential fields used by the rotation state machine."""

    token_digest: str
    pending_token_digest: str | None
    rotation_overlap_expires_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class IssuedRetryEnvelope:
    """Opaque receipt plus the encrypted, persistence-safe envelope fields."""

    receipt: str = field(repr=False)
    receipt_digest: str
    fingerprint_digest: str
    encrypted_token: bytes = field(repr=False)
    encryption_nonce: bytes
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class IssuedDeviceToken:
    """One-time raw rotation token safe from accidental representation."""

    token: str = field(repr=False)


def generate_device_token() -> str:
    """Return a URL-safe bearer token containing 32 random bytes."""
    return (
        base64.urlsafe_b64encode(secrets.token_bytes(DEVICE_TOKEN_BYTES))
        .rstrip(b"=")
        .decode("ascii")
    )


def generate_retry_receipt() -> str:
    """Return a URL-safe opaque receipt containing 32 random bytes."""
    return (
        base64.urlsafe_b64encode(secrets.token_bytes(RETRY_RECEIPT_BYTES))
        .rstrip(b"=")
        .decode("ascii")
    )


def device_token_digest(token: str, device_token_pepper: bytes) -> str:
    """Return the HMAC-SHA256 digest stored for a device bearer token."""
    if not token or not device_token_pepper:
        raise ValueError("device token and pepper must not be empty")
    try:
        encoded_token = token.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("device token must be ASCII") from error
    return hmac.new(
        device_token_pepper,
        encoded_token,
        hashlib.sha256,
    ).hexdigest()


def device_token_matches(
    token: str,
    expected_digest: str,
    device_token_pepper: bytes,
) -> bool:
    """Compare a presented token with a stored digest in constant time."""
    if not expected_digest:
        return False
    try:
        actual_digest = device_token_digest(token, device_token_pepper)
    except ValueError:
        return False
    try:
        return hmac.compare_digest(actual_digest, expected_digest)
    except TypeError:
        return False


def _context_digest(value: str, pepper: bytes, context: bytes) -> str:
    if not value or not pepper:
        raise ValueError("digest input and pepper must not be empty")
    return hmac.new(
        pepper,
        context + value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _envelope_key(session_secret: bytes) -> bytes:
    if not session_secret:
        raise ValueError("session secret must not be empty")
    return hmac.new(
        session_secret,
        _ENVELOPE_KEY_CONTEXT,
        hashlib.sha256,
    ).digest()


def _envelope_aad(
    receipt_digest: str,
    fingerprint_digest: str,
    expires_at: datetime,
) -> bytes:
    return "\0".join(
        (
            receipt_digest,
            fingerprint_digest,
            expires_at.isoformat(),
        )
    ).encode("ascii")


def seal_retry_envelope(
    token: str,
    hardware_fingerprint: str,
    device_token_pepper: bytes,
    session_secret: bytes,
    *,
    now: datetime | None = None,
    lifetime: timedelta = DEFAULT_RETRY_ENVELOPE_LIFETIME,
) -> IssuedRetryEnvelope:
    """Encrypt a device token under an opaque, fingerprint-bound retry receipt."""
    issued_at = now or datetime.now(UTC)
    if issued_at.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if lifetime <= timedelta(0) or lifetime > MAX_RETRY_ENVELOPE_LIFETIME:
        raise ValueError(
            "retry envelope lifetime must be positive and at most 15 minutes"
        )
    try:
        token_bytes = token.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("device token must be ASCII") from error
    if not token_bytes or not hardware_fingerprint:
        raise ValueError("device token and hardware fingerprint must not be empty")

    receipt = generate_retry_receipt()
    receipt_digest = _context_digest(
        receipt,
        device_token_pepper,
        _RECEIPT_DIGEST_CONTEXT,
    )
    fingerprint_digest = _context_digest(
        hardware_fingerprint,
        device_token_pepper,
        _FINGERPRINT_DIGEST_CONTEXT,
    )
    expires_at = issued_at + lifetime
    encryption_nonce = secrets.token_bytes(_AES_GCM_NONCE_BYTES)
    encrypted_token = AESGCM(_envelope_key(session_secret)).encrypt(
        encryption_nonce,
        token_bytes,
        _envelope_aad(receipt_digest, fingerprint_digest, expires_at),
    )
    return IssuedRetryEnvelope(
        receipt=receipt,
        receipt_digest=receipt_digest,
        fingerprint_digest=fingerprint_digest,
        encrypted_token=encrypted_token,
        encryption_nonce=encryption_nonce,
        expires_at=expires_at,
    )


def recover_retry_token(
    receipt: str,
    hardware_fingerprint: str,
    envelope: RetryEnvelope,
    device_token_pepper: bytes,
    session_secret: bytes,
    *,
    now: datetime | None = None,
) -> str | None:
    """Recover a retry token only for the original receipt and fingerprint."""
    checked_at = now or datetime.now(UTC)
    if (
        checked_at.tzinfo is None
        or envelope.expires_at.tzinfo is None
        or checked_at >= envelope.expires_at
    ):
        return None
    try:
        presented_receipt_digest = _context_digest(
            receipt,
            device_token_pepper,
            _RECEIPT_DIGEST_CONTEXT,
        )
        presented_fingerprint_digest = _context_digest(
            hardware_fingerprint,
            device_token_pepper,
            _FINGERPRINT_DIGEST_CONTEXT,
        )
    except (UnicodeEncodeError, ValueError):
        return None
    try:
        receipt_matches = hmac.compare_digest(
            presented_receipt_digest,
            envelope.receipt_digest,
        )
        fingerprint_matches = hmac.compare_digest(
            presented_fingerprint_digest,
            envelope.fingerprint_digest,
        )
    except TypeError:
        return None
    if not receipt_matches or not fingerprint_matches:
        return None
    try:
        token_bytes = AESGCM(_envelope_key(session_secret)).decrypt(
            envelope.encryption_nonce,
            envelope.encrypted_token,
            _envelope_aad(
                envelope.receipt_digest,
                envelope.fingerprint_digest,
                envelope.expires_at,
            ),
        )
        return token_bytes.decode("ascii")
    except (InvalidTag, UnicodeDecodeError, ValueError):
        return None


def begin_device_credential_rotation(
    record: DeviceCredentialState,
    device_token_pepper: bytes,
    *,
    now: datetime | None = None,
    overlap: timedelta = DEFAULT_ROTATION_OVERLAP,
) -> IssuedDeviceToken:
    """Create pending token state while retaining the old token for an overlap."""
    started_at = now or datetime.now(UTC)
    if started_at.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if overlap <= timedelta(0):
        raise ValueError("rotation overlap must be positive")
    if record.revoked_at is not None:
        raise ValueError("revoked credential cannot be rotated")
    if record.expires_at is not None:
        if record.expires_at.tzinfo is None or started_at >= record.expires_at:
            raise ValueError("expired credential cannot be rotated")
    if record.pending_token_digest is not None:
        raise ValueError("credential rotation is already pending")

    token = generate_device_token()
    record.pending_token_digest = device_token_digest(token, device_token_pepper)
    record.rotation_overlap_expires_at = started_at + overlap
    return IssuedDeviceToken(token=token)


def device_credential_accepts_token(
    record: DeviceCredentialState,
    token: str,
    device_token_pepper: bytes,
    *,
    now: datetime | None = None,
) -> bool:
    """Accept current or pending material according to rotation overlap state."""
    checked_at = now or datetime.now(UTC)
    if checked_at.tzinfo is None or record.revoked_at is not None:
        return False
    if record.expires_at is not None:
        if record.expires_at.tzinfo is None or checked_at >= record.expires_at:
            return False
    if record.pending_token_digest is not None and device_token_matches(
        token,
        record.pending_token_digest,
        device_token_pepper,
    ):
        return True
    if record.pending_token_digest is None:
        return device_token_matches(token, record.token_digest, device_token_pepper)
    overlap_deadline = record.rotation_overlap_expires_at
    return (
        overlap_deadline is not None
        and overlap_deadline.tzinfo is not None
        and checked_at < overlap_deadline
        and device_token_matches(token, record.token_digest, device_token_pepper)
    )


def activate_pending_device_credential(
    record: DeviceCredentialState,
    token: str,
    device_token_pepper: bytes,
    *,
    now: datetime | None = None,
) -> bool:
    """Promote matching pending material and immediately retire the old digest."""
    activated_at = now or datetime.now(UTC)
    pending_digest = record.pending_token_digest
    if (
        activated_at.tzinfo is None
        or pending_digest is None
        or record.revoked_at is not None
        or (
            record.expires_at is not None
            and (record.expires_at.tzinfo is None or activated_at >= record.expires_at)
        )
        or not device_token_matches(token, pending_digest, device_token_pepper)
    ):
        return False
    record.token_digest = pending_digest
    record.pending_token_digest = None
    record.rotation_overlap_expires_at = None
    return True
