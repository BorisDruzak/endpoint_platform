"""Scoped service credential issuance and persistence helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import ServiceCredential


SERVICE_TOKEN_BYTES = 32
_PUBLIC_IDENTIFIER_BYTES = 16
_TOKEN_PREFIX_MARKER = "svc_"
_ENCODED_SECRET_LENGTH = 43
_URLSAFE_TOKEN_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


@dataclass(frozen=True, slots=True)
class IssuedServiceCredential:
    """One-time bearer material paired with its secret-free database record."""

    token: str = field(repr=False)
    record: ServiceCredential = field(repr=False)


@dataclass(frozen=True, slots=True)
class ServiceCredentialSummary:
    """Public service credential fields returned after one-time creation."""

    id: UUID
    service_client_id: UUID
    credential_identifier: str
    token_prefix: str
    scopes: tuple[str, ...]
    expires_at: datetime | None
    revoked_at: datetime | None


def _normalize_scopes(scopes: Iterable[str]) -> list[str]:
    if isinstance(scopes, (str, bytes)):
        raise ValueError("service scopes must be provided as a scope collection")
    normalized = []
    for scope in scopes:
        if (
            not isinstance(scope, str)
            or not scope
            or scope != scope.strip()
            or not scope.isascii()
            or len(scope) > 128
            or any(
                character.isspace() or not 32 <= ord(character) <= 126
                for character in scope
            )
        ):
            raise ValueError("service scopes must be non-empty printable ASCII")
        normalized.append(scope)
    unique_scopes = sorted(set(normalized))
    if not unique_scopes:
        raise ValueError("at least one service scope is required")
    return unique_scopes


def service_token_digest(token: str, service_token_pepper: bytes) -> str:
    """Return the HMAC-SHA256 value used for service token comparison."""
    if not token or not service_token_pepper:
        raise ValueError("service token and pepper must not be empty")
    return hmac.new(
        service_token_pepper,
        token.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def parse_service_token(token: str) -> str | None:
    """Return a valid token's public prefix without exposing its secret material."""
    try:
        prefix, encoded_secret = token.split(".")
        identifier = prefix.removeprefix(_TOKEN_PREFIX_MARKER)
        decoded_secret = base64.b64decode(
            encoded_secret + "=" * (-len(encoded_secret) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError):
        return None
    valid = (
        prefix.startswith(_TOKEN_PREFIX_MARKER)
        and len(identifier) == _PUBLIC_IDENTIFIER_BYTES * 2
        and all(character in "0123456789abcdef" for character in identifier)
        and len(encoded_secret) == _ENCODED_SECRET_LENGTH
        and encoded_secret.isascii()
        and all(
            character in _URLSAFE_TOKEN_CHARACTERS
            for character in encoded_secret
        )
        and len(decoded_secret) == SERVICE_TOKEN_BYTES
    )
    return prefix if valid else None


async def create_service_credential(
    session: AsyncSession,
    service_client_id: UUID,
    service_token_pepper: bytes,
    *,
    actor_kind: str,
    actor_identifier: str | None,
    request_id: str,
    scopes: Iterable[str],
    expires_at: datetime | None = None,
    now: datetime | None = None,
    commit: bool = True,
) -> IssuedServiceCredential:
    """Persist a credential and audit row, returning raw token material once."""
    issued_at = now or datetime.now(UTC)
    if issued_at.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if expires_at is not None:
        if expires_at.tzinfo is None:
            raise ValueError("credential expiry must be timezone-aware")
        if expires_at <= issued_at:
            raise ValueError("credential expiry must be in the future")
    normalized_scopes = _normalize_scopes(scopes)
    if not service_token_pepper:
        raise ValueError("service token pepper must not be empty")

    credential_identifier = secrets.token_hex(_PUBLIC_IDENTIFIER_BYTES)
    token_prefix = f"{_TOKEN_PREFIX_MARKER}{credential_identifier}"
    raw_material = base64.urlsafe_b64encode(
        secrets.token_bytes(SERVICE_TOKEN_BYTES)
    ).rstrip(b"=").decode("ascii")
    token = f"{token_prefix}.{raw_material}"
    record = ServiceCredential(
        id=uuid4(),
        service_client_id=service_client_id,
        credential_identifier=credential_identifier,
        token_prefix=token_prefix,
        secret_digest=service_token_digest(token, service_token_pepper),
        scopes=normalized_scopes,
        expires_at=expires_at,
        revoked_at=None,
    )
    session.add(record)
    try:
        await append_audit_event(
            session,
            actor_kind=actor_kind,
            actor_identifier=actor_identifier,
            action="service_credential.created",
            object_kind="service_credential",
            object_identifier=str(record.id),
            request_id=request_id,
            details={
                "expires_at": expires_at,
                "scopes": normalized_scopes,
            },
        )
        if commit:
            await session.commit()
    except Exception:
        if commit:
            await session.rollback()
        raise
    return IssuedServiceCredential(token=token, record=record)


def service_credential_is_active(
    record: ServiceCredential, *, now: datetime | None = None
) -> bool:
    """Return whether a service credential is unrevoked and unexpired."""
    checked_at = now or datetime.now(UTC)
    if checked_at.tzinfo is None:
        return False
    if record.revoked_at is not None:
        return False
    if record.expires_at is None:
        return True
    if record.expires_at.tzinfo is None:
        return False
    return checked_at < record.expires_at


def revoke_service_credential(
    record: ServiceCredential, *, now: datetime | None = None
) -> None:
    """Revoke a credential while retaining its first revocation timestamp."""
    revoked_at = now or datetime.now(UTC)
    if revoked_at.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if record.revoked_at is None:
        record.revoked_at = revoked_at


def service_credential_summary(
    record: ServiceCredential,
) -> ServiceCredentialSummary:
    """Build the secret-free representation suitable for subsequent reads."""
    return ServiceCredentialSummary(
        id=record.id,
        service_client_id=record.service_client_id,
        credential_identifier=record.credential_identifier,
        token_prefix=record.token_prefix,
        scopes=tuple(record.scopes),
        expires_at=record.expires_at,
        revoked_at=record.revoked_at,
    )
