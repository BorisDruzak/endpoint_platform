"""Strict service contract for an Endpoint-owned runtime diagnostic target."""

from __future__ import annotations

import hmac
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, StrictBool, ValidationError, field_validator

from .base import ContractModelV1


CorrelationID = Annotated[
    str,
    Field(
        min_length=1,
        max_length=128,
        pattern=r"^[\x20-\x7e]+$",
    ),
]


class RuntimeDiagnosticTargetV1(ContractModelV1):
    """The complete allowlist that a Helpdesk diagnostic target may expose."""

    device_ref: UUID
    online: StrictBool
    connection_state: Literal["online", "offline"]
    last_seen_at: AwareDatetime | None
    last_handshake_at: AwareDatetime | None
    agent_version: Annotated[str, Field(min_length=1, max_length=128)] | None

    @field_validator("last_seen_at", "last_handshake_at", mode="before")
    @classmethod
    def require_rfc3339_timestamp_string(cls, value: object) -> object:
        if value is not None and not isinstance(value, str):
            raise ValueError("runtime timestamp must be an RFC3339 string")
        return value


class RuntimeDiagnosticTargetEnvelopeV1(ContractModelV1):
    """Successful runtime target response bound to a caller correlation ID."""

    schema_version: Literal["endpoint_runtime_v1"]
    correlation_id: CorrelationID
    data: RuntimeDiagnosticTargetV1


class RuntimeDiagnosticTargetNotFoundDataV1(ContractModelV1):
    status: Literal["not_found"]
    code: Literal["endpoint_device_not_found"]


class RuntimeDiagnosticTargetNotFoundEnvelopeV1(ContractModelV1):
    """The only valid 404 body for the runtime diagnostic target endpoint."""

    correlation_id: CorrelationID
    data: RuntimeDiagnosticTargetNotFoundDataV1


class RuntimeDiagnosticTargetUnavailable(ValueError):
    """Fail-closed classification for unusable diagnostic target inputs."""


def parse_runtime_diagnostic_target_response(
    payload: object, correlation_id: str
) -> RuntimeDiagnosticTargetEnvelopeV1:
    """Accept only one exact successful target response for a known correlation."""
    try:
        parsed = RuntimeDiagnosticTargetEnvelopeV1.model_validate(payload)
    except ValidationError as error:
        raise RuntimeDiagnosticTargetUnavailable("invalid runtime diagnostic target") from error
    if not hmac.compare_digest(parsed.correlation_id, correlation_id):
        raise RuntimeDiagnosticTargetUnavailable("runtime diagnostic target correlation mismatch")
    if parsed.data.online != (parsed.data.connection_state == "online"):
        raise RuntimeDiagnosticTargetUnavailable("runtime diagnostic target state mismatch")
    return parsed


def redacted_runtime_diagnostic_target_shadow(
    envelope: RuntimeDiagnosticTargetEnvelopeV1,
) -> dict[str, object]:
    """Return the safe state comparison surface, excluding opaque device identity."""
    data = envelope.data.model_dump(mode="json")
    return {
        key: data[key]
        for key in (
            "online",
            "connection_state",
            "last_seen_at",
            "last_handshake_at",
            "agent_version",
        )
    }


__all__ = [
    "CorrelationID",
    "RuntimeDiagnosticTargetEnvelopeV1",
    "RuntimeDiagnosticTargetNotFoundDataV1",
    "RuntimeDiagnosticTargetNotFoundEnvelopeV1",
    "RuntimeDiagnosticTargetUnavailable",
    "RuntimeDiagnosticTargetV1",
    "parse_runtime_diagnostic_target_response",
    "redacted_runtime_diagnostic_target_shadow",
]
