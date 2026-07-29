"""Security-focused tests for device credential primitives."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import endpoint_server.enrollment.credentials as credentials
import endpoint_server.db.models as models
from endpoint_server.db.models import DeviceCredential


def _decode_urlsafe(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_device_token_is_32_random_bytes_with_hmac_only_comparison() -> None:
    """Short tokens or direct equality would weaken bearer authentication."""
    pepper = b"device-token-pepper-for-test"
    token = credentials.generate_device_token()
    expected_digest = hmac.new(
        pepper,
        token.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()

    assert len(_decode_urlsafe(token)) == credentials.DEVICE_TOKEN_BYTES == 32
    assert credentials.device_token_digest(token, pepper) == expected_digest
    assert credentials.device_token_matches(token, expected_digest, pepper)
    assert not credentials.device_token_matches(
        credentials.generate_device_token(),
        expected_digest,
        pepper,
    )


def test_device_token_comparison_fails_closed_for_malformed_values() -> None:
    """Malformed input or persisted digest data must deny instead of raising."""
    pepper = b"device-token-pepper-for-test"

    assert not credentials.device_token_matches("\N{SNOWMAN}", "0" * 64, pepper)
    assert not credentials.device_token_matches("presented", "\N{SNOWMAN}", pepper)


def test_retry_envelope_recovers_only_matching_fingerprint_before_expiry() -> None:
    """A stolen, mismatched, or expired receipt must not recover bearer material."""
    now = datetime(2026, 7, 29, 10, tzinfo=UTC)
    token = credentials.generate_device_token()
    token_pepper = secrets.token_bytes(32)
    session_secret = secrets.token_bytes(32)
    issued = credentials.seal_retry_envelope(
        token,
        "sha256:device-a",
        token_pepper,
        session_secret,
        now=now,
        lifetime=timedelta(minutes=5),
    )

    assert len(_decode_urlsafe(issued.receipt)) == credentials.RETRY_RECEIPT_BYTES == 32
    assert (
        issued.receipt_digest
        == hmac.new(
            token_pepper,
            b"endpoint-enrollment-receipt-v1\0" + issued.receipt.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
    )
    assert issued.fingerprint_digest != "sha256:device-a"
    assert issued.encrypted_token != token.encode("ascii")
    assert (
        credentials.recover_retry_token(
            issued.receipt,
            "sha256:device-a",
            issued,
            token_pepper,
            session_secret,
            now=now + timedelta(minutes=4),
        )
        == token
    )
    assert (
        credentials.recover_retry_token(
            issued.receipt,
            "sha256:device-b",
            issued,
            token_pepper,
            session_secret,
            now=now + timedelta(minutes=4),
        )
        is None
    )
    assert (
        credentials.recover_retry_token(
            credentials.generate_retry_receipt(),
            "sha256:device-a",
            issued,
            token_pepper,
            session_secret,
            now=now + timedelta(minutes=4),
        )
        is None
    )
    assert (
        credentials.recover_retry_token(
            issued.receipt,
            "sha256:device-a",
            issued,
            token_pepper,
            session_secret,
            now=now + timedelta(minutes=5),
        )
        is None
    )
    assert token not in repr(issued)
    assert issued.receipt not in repr(issued)


def test_retry_envelope_fails_closed_when_persisted_state_is_corrupt() -> None:
    """Corrupt digest or ciphertext state must deny recovery instead of escaping."""
    now = datetime(2026, 7, 29, 10, tzinfo=UTC)
    token_pepper = secrets.token_bytes(32)
    session_secret = secrets.token_bytes(32)
    issued = credentials.seal_retry_envelope(
        credentials.generate_device_token(),
        "sha256:device-a",
        token_pepper,
        session_secret,
        now=now,
    )

    for corrupted in (
        replace(issued, fingerprint_digest="\N{SNOWMAN}"),
        replace(
            issued,
            encrypted_token=(
                issued.encrypted_token[:-1] + bytes((issued.encrypted_token[-1] ^ 1,))
            ),
        ),
    ):
        assert (
            credentials.recover_retry_token(
                issued.receipt,
                "sha256:device-a",
                corrupted,
                token_pepper,
                session_secret,
                now=now + timedelta(minutes=1),
            )
            is None
        )


def test_rotation_accepts_old_only_during_overlap_and_activation_promotes_new() -> None:
    """Retaining the old digest after activation or deadline would defeat rotation."""
    now = datetime(2026, 7, 29, 10, tzinfo=UTC)
    pepper = secrets.token_bytes(32)
    old_token = credentials.generate_device_token()
    record = DeviceCredential(
        device_id=uuid4(),
        credential_identifier="credential-1",
        token_digest=credentials.device_token_digest(old_token, pepper),
        expires_at=None,
        revoked_at=None,
    )

    issued = credentials.begin_device_credential_rotation(
        record,
        pepper,
        now=now,
        overlap=timedelta(minutes=10),
    )

    assert record.pending_token_digest == credentials.device_token_digest(
        issued.token,
        pepper,
    )
    assert record.rotation_overlap_expires_at == now + timedelta(minutes=10)
    assert credentials.device_credential_accepts_token(
        record,
        old_token,
        pepper,
        now=now + timedelta(minutes=9),
    )
    assert credentials.device_credential_accepts_token(
        record,
        issued.token,
        pepper,
        now=now + timedelta(minutes=9),
    )
    assert not credentials.device_credential_accepts_token(
        record,
        old_token,
        pepper,
        now=now + timedelta(minutes=10),
    )
    assert credentials.device_credential_accepts_token(
        record,
        issued.token,
        pepper,
        now=now + timedelta(minutes=10),
    )

    assert credentials.activate_pending_device_credential(
        record,
        issued.token,
        pepper,
        now=now + timedelta(minutes=5),
    )
    assert record.token_digest == credentials.device_token_digest(
        issued.token,
        pepper,
    )
    assert record.pending_token_digest is None
    assert record.rotation_overlap_expires_at is None
    assert not credentials.device_credential_accepts_token(
        record,
        old_token,
        pepper,
        now=now + timedelta(minutes=5),
    )
    assert issued.token not in repr(issued)
    assert issued.token not in repr(record)


def test_schema_persists_only_digests_ciphertext_and_rotation_state() -> None:
    """A raw receipt, fingerprint, or device token column would leak credentials."""
    credential_columns = DeviceCredential.__table__.columns
    envelope_columns = models.EnrollmentRetryEnvelope.__table__.columns

    assert {
        "pending_token_digest",
        "rotation_overlap_expires_at",
    } <= set(credential_columns.keys())
    assert credential_columns["pending_token_digest"].unique
    assert {
        "device_credential_id",
        "receipt_digest",
        "fingerprint_digest",
        "encrypted_token",
        "encryption_nonce",
        "expires_at",
    } == set(envelope_columns.keys()) - {"id", "created_at"}
    assert envelope_columns["receipt_digest"].unique
    assert not {
        "receipt",
        "hardware_fingerprint",
        "token",
    }.intersection(envelope_columns.keys())
