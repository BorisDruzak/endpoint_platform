"""Closed local IPC envelope for the user sensor and browser bridge."""

from __future__ import annotations

import json
from typing import Annotated, Literal

from pydantic import Field, TypeAdapter, ValidationError, model_validator

from endpoint_contracts.base import ContractModelV1
from pc_agent.browser_protocol import BrowserHelloV1, BrowserMessageV1, ExtensionId

from endpoint_contracts.activity import ForegroundApplicationV1
from pc_agent.browser_protocol import MAX_NATIVE_MESSAGE_BYTES

MAX_IPC_MESSAGE_BYTES = MAX_NATIVE_MESSAGE_BYTES
DesktopState = Literal["UNLOCKED", "LOCKED", "DISCONNECTED", "UNKNOWN"]
_MAX_IDLE_SECONDS = 86400


class UserSessionSampleV1(ContractModelV1):
    schema_version: Literal["user_session_sample_v1"]
    desktop_state: DesktopState
    idle_seconds: Annotated[int | None, Field(strict=True, ge=0, le=_MAX_IDLE_SECONDS)] = None
    foreground: ForegroundApplicationV1 | None = None

    @model_validator(mode="after")
    def validate_state(self) -> "UserSessionSampleV1":
        if self.desktop_state == "UNLOCKED":
            if self.idle_seconds is None:
                raise ValueError("unlocked session needs idle time")
        elif self.idle_seconds is not None or self.foreground is not None:
            raise ValueError("noninteractive session cannot expose idle or foreground")
        return self


class LocalSensorProtocolError(ValueError):
    def __init__(self, code: Literal["INVALID_MESSAGE", "OVERSIZE"]) -> None:
        super().__init__(code)
        self.code = code


class LocalBrowserEnvelopeV1(ContractModelV1):
    schema_version: Literal["local_sensor_envelope_v1"]
    source: Literal["browser"]
    extension_id: ExtensionId
    message: BrowserMessageV1

    @model_validator(mode="after")
    def match_hello_identity(self) -> "LocalBrowserEnvelopeV1":
        if isinstance(self.message, BrowserHelloV1) and self.message.extension_id != self.extension_id:
            raise ValueError("browser hello identity mismatch")
        return self


class LocalUserSessionEnvelopeV1(ContractModelV1):
    schema_version: Literal["local_sensor_envelope_v1"]
    source: Literal["user_session"]
    sample: UserSessionSampleV1


LocalSensorEnvelopeV1 = Annotated[
    LocalBrowserEnvelopeV1 | LocalUserSessionEnvelopeV1,
    Field(discriminator="source"),
]
_ENVELOPE_ADAPTER = TypeAdapter(LocalSensorEnvelopeV1)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate local sensor key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("invalid JSON constant")


def parse_local_sensor_payload(payload: bytes) -> LocalBrowserEnvelopeV1 | LocalUserSessionEnvelopeV1:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_IPC_MESSAGE_BYTES:
        raise LocalSensorProtocolError("OVERSIZE")
    try:
        raw = json.loads(
            payload, object_pairs_hook=_unique_object, parse_constant=_reject_constant,
        )
        return _ENVELOPE_ADAPTER.validate_python(raw)
    except (UnicodeDecodeError, ValueError, TypeError, ValidationError) as error:
        raise LocalSensorProtocolError("INVALID_MESSAGE") from error


def serialize_local_sensor_payload(
    envelope: LocalBrowserEnvelopeV1 | LocalUserSessionEnvelopeV1,
) -> bytes:
    if not isinstance(envelope, (LocalBrowserEnvelopeV1, LocalUserSessionEnvelopeV1)):
        raise LocalSensorProtocolError("INVALID_MESSAGE")
    body = envelope.model_dump_json().encode("utf-8")
    if len(body) > MAX_IPC_MESSAGE_BYTES:
        raise LocalSensorProtocolError("OVERSIZE")
    return body
