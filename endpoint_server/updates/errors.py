"""Fail-closed update control-plane domain errors."""


class UpdateError(Exception):
    """Base error for update control-plane operations."""


class UpdateValidationError(UpdateError):
    """Caller input does not satisfy the bounded update contract."""


class UpdateNotFound(UpdateError):
    """The requested update object is not visible to the caller."""


class UpdateConflict(UpdateError):
    """The request conflicts with immutable or concurrently owned state."""


class UpdateStateError(UpdateError):
    """The requested lifecycle transition is not currently legal."""


__all__ = [
    "UpdateConflict",
    "UpdateError",
    "UpdateNotFound",
    "UpdateStateError",
    "UpdateValidationError",
]
