"""Strict local record for the server-assigned Endpoint Device identity."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID


ENROLLMENT_IDENTITY_FILENAME = "enrollment-identity.json"
ENROLLMENT_IDENTITY_SCHEMA_VERSION = "endpoint_enrollment_identity_v1"
_MAX_IDENTITY_BYTES = 160


class EnrollmentIdentityError(ValueError):
    """The authoritative enrollment identity is unavailable or malformed."""


def canonical_enrollment_device_id(value: object) -> UUID:
    """Parse one canonical UUID without inventing or consulting another identity."""
    if isinstance(value, UUID):
        return UUID(str(value))
    if not isinstance(value, str):
        raise EnrollmentIdentityError("Endpoint enrollment identity is invalid")
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise EnrollmentIdentityError(
            "Endpoint enrollment identity is invalid"
        ) from error
    if value != str(parsed):
        raise EnrollmentIdentityError("Endpoint enrollment identity is invalid")
    return parsed


def serialize_enrollment_identity(device_id: object) -> bytes:
    """Return the bounded canonical record for an enrollment response UUID."""
    parsed = canonical_enrollment_device_id(device_id)
    return json.dumps(
        {
            "schema_version": ENROLLMENT_IDENTITY_SCHEMA_VERSION,
            "device_id": str(parsed),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def read_enrollment_device_id(path: Path) -> UUID:
    """Read the authoritative server Device.id from its dedicated local record."""
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise EnrollmentIdentityError(
            "Endpoint enrollment identity is unavailable"
        ) from error
    if not raw or len(raw) > _MAX_IDENTITY_BYTES:
        raise EnrollmentIdentityError("Endpoint enrollment identity is invalid")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EnrollmentIdentityError(
            "Endpoint enrollment identity is invalid"
        ) from error
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "device_id"}
        or payload.get("schema_version") != ENROLLMENT_IDENTITY_SCHEMA_VERSION
    ):
        raise EnrollmentIdentityError("Endpoint enrollment identity is invalid")
    return canonical_enrollment_device_id(payload.get("device_id"))


__all__ = [
    "ENROLLMENT_IDENTITY_FILENAME",
    "ENROLLMENT_IDENTITY_SCHEMA_VERSION",
    "EnrollmentIdentityError",
    "canonical_enrollment_device_id",
    "read_enrollment_device_id",
    "serialize_enrollment_identity",
]
