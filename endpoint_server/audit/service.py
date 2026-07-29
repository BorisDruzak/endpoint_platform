"""Service boundary for appending immutable redacted audit events."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_server.db.models import AuditEvent

from .errors import AuditMutationError
from .redaction import JSONValue, redact_audit_details


async def append_audit_event(
    session: AsyncSession,
    *,
    actor_kind: str,
    actor_identifier: str | None,
    action: str,
    object_kind: str,
    object_identifier: str | None,
    request_id: str,
    details: Mapping[str, object],
    occurred_at: datetime | None = None,
) -> AuditEvent:
    """Add one sanitized event to the caller's uncommitted transaction."""
    timestamp = occurred_at or datetime.now(UTC)
    if timestamp.utcoffset() is None:
        raise ValueError("audit event timestamp must be timezone-aware")
    required_attribution = {
        "actor_kind": actor_kind,
        "action": action,
        "object_kind": object_kind,
        "request_id": request_id,
    }
    for field, value in required_attribution.items():
        if not value.strip():
            raise ValueError(f"audit event {field} must not be blank")
    redacted = redact_audit_details(details)
    if not isinstance(redacted, dict):
        raise TypeError("audit event details must be a JSON object")

    event = AuditEvent(
        actor_kind=actor_kind,
        actor_identifier=actor_identifier,
        action=action,
        object_kind=object_kind,
        object_identifier=object_identifier,
        request_id=request_id,
        details=redacted,
        created_at=timestamp.astimezone(UTC),
    )
    session.add(event)
    return event


__all__ = [
    "AuditMutationError",
    "JSONValue",
    "append_audit_event",
]
