"""Errors and small validation helpers for the Device Context ownership zone."""

from __future__ import annotations

from uuid import UUID

from endpoint_contracts import ContextProfileV1


class ContextError(Exception):
    """Base error for safe Device Context lifecycle failures."""


class ContextConflict(ContextError):
    """A correlation key already owns a different collection."""


class ContextNotFound(ContextError):
    """The referenced context-owned or device record does not exist."""


class ContextValidationError(ContextError):
    """A transport result cannot become a validated context observation."""


PROFILES: tuple[ContextProfileV1, ...] = (
    "baseline_v1", "health_v1", "network_v1", "diagnostic_v1",
)


def require_profile(value: str) -> ContextProfileV1:
    if value not in PROFILES:
        raise ContextValidationError("unknown device context profile")
    return value  # type: ignore[return-value]


def require_uuid(value: UUID | str, name: str) -> UUID:
    try:
        return value if isinstance(value, UUID) else UUID(value)
    except (TypeError, ValueError, AttributeError) as error:
        raise ContextValidationError(f"{name} must be a UUID") from error
