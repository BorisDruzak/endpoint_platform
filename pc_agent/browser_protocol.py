"""Typed, bounded Browser Sensor Native Messaging contract.

No browser content, file names, credentials or arbitrary JSON pass this edge.
"""

from __future__ import annotations

import json
import struct
from typing import Annotated, BinaryIO, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, StrictBool, ValidationError, field_validator, model_validator

from endpoint_contracts.activity import BrowserActivityV1
from endpoint_contracts.base import ContractModelV1


MAX_NATIVE_MESSAGE_BYTES = 16 * 1024
ExtensionId = Annotated[str, Field(strict=True, pattern=r"^[a-p]{32}$")]
Version = Annotated[str, Field(strict=True, min_length=1, max_length=64,
                                pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")]
Family = Literal["chrome", "yandex"]
Category = Literal["spreadsheet", "document", "image", "video", "audio", "archive", "other"]
ClipboardType = Literal["text", "html", "image", "files", "other"]
InstallType = Literal["admin", "development", "normal", "sideload", "other", "unknown"]


class BrowserProtocolError(ValueError):
    def __init__(self, code: str, description: str = "invalid browser message") -> None:
        super().__init__(description)
        self.code = code


def _validate_origin(family: Family, origin: str, domain: str) -> None:
    BrowserActivityV1(
        browser_family=family, origin=origin, domain=domain,
        sensor_state="ACTIVE",
    )


def _unique(value: list[str]) -> list[str]:
    if len(value) != len(set(value)):
        raise ValueError("categories must be unique")
    return value


class BrowserHelloV1(ContractModelV1):
    schema_version: Literal["browser_sensor_hello_v1"]
    protocol_version: Literal[1]
    extension_id: ExtensionId
    extension_version: Version
    browser_family: Family
    observed_at: AwareDatetime


class BrowserHeartbeatV1(ContractModelV1):
    schema_version: Literal["browser_sensor_heartbeat_v1"]
    protocol_version: Literal[1]
    extension_version: Version
    browser_family: Family
    observed_at: AwareDatetime
    install_type: InstallType = "unknown"


class BrowserContextV1(ContractModelV1):
    schema_version: Literal["browser_sensor_context_v1"]
    protocol_version: Literal[1]
    browser_family: Family
    scheme: Literal["http", "https"]
    origin: Annotated[str, Field(strict=True, max_length=512)]
    domain: Annotated[str, Field(strict=True, max_length=253)]
    tab_active: Literal[True]
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_context(self) -> "BrowserContextV1":
        _validate_origin(self.browser_family, self.origin, self.domain)
        if not self.origin.startswith(self.scheme + "://"):
            raise ValueError("browser scheme does not match origin")
        return self


class _BrowserEventV1(ContractModelV1):
    schema_version: Literal["browser_sensor_event_v1"]
    protocol_version: Literal[1]
    event_identifier: UUID
    browser_family: Family
    destination_origin: Annotated[str, Field(strict=True, max_length=512)]
    destination_domain: Annotated[str, Field(strict=True, max_length=253)]
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_destination(self) -> "_BrowserEventV1":
        _validate_origin(self.browser_family, self.destination_origin, self.destination_domain)
        return self


class BrowserUploadV1(_BrowserEventV1):
    event_type: Literal["BROWSER_UPLOAD"]
    file_count: Annotated[int, Field(strict=True, ge=1, le=64)]
    total_bytes: Annotated[int, Field(strict=True, ge=0, le=2**53 - 1)]
    mime_categories: list[Category] = Field(min_length=1, max_length=7)

    @field_validator("mime_categories")
    @classmethod
    def validate_categories(cls, value: list[str]) -> list[str]:
        return _unique(value)


class BrowserPasteV1(_BrowserEventV1):
    event_type: Literal["BROWSER_PASTE"]
    clipboard_types: list[ClipboardType] = Field(max_length=5)

    @field_validator("clipboard_types")
    @classmethod
    def validate_types(cls, value: list[str]) -> list[str]:
        return _unique(value)


BrowserMessageV1 = BrowserHelloV1 | BrowserHeartbeatV1 | BrowserContextV1 | BrowserUploadV1 | BrowserPasteV1


class BrowserBridgeAckV1(ContractModelV1):
    schema_version: Literal["browser_bridge_ack_v1"]
    accepted: StrictBool
    error_code: Literal[
        "OK", "INVALID_MESSAGE", "UNSUPPORTED_VERSION", "OVERSIZE",
        "IDENTITY_MISMATCH", "IPC_UNAVAILABLE", "POLICY_DISABLED", "SENSOR_NOT_READY",
    ]

    @model_validator(mode="after")
    def validate_status(self) -> "BrowserBridgeAckV1":
        if self.accepted != (self.error_code == "OK"):
            raise ValueError("browser bridge ACK status is inconsistent")
        return self


_MODELS: dict[tuple[str, str | None], type[ContractModelV1]] = {
    ("browser_sensor_hello_v1", None): BrowserHelloV1,
    ("browser_sensor_heartbeat_v1", None): BrowserHeartbeatV1,
    ("browser_sensor_context_v1", None): BrowserContextV1,
    ("browser_sensor_event_v1", "BROWSER_UPLOAD"): BrowserUploadV1,
    ("browser_sensor_event_v1", "BROWSER_PASTE"): BrowserPasteV1,
}


def _read_exact(stream: BinaryIO, length: int, *, allow_eof: bool = False) -> bytes | None:
    result = bytearray()
    while len(result) < length:
        chunk = stream.read(length - len(result))
        if not chunk:
            if allow_eof and not result:
                return None
            raise BrowserProtocolError("INVALID_MESSAGE", "incomplete browser message")
        result.extend(chunk)
    return bytes(result)


def decode_native_message(stream: BinaryIO) -> BrowserMessageV1 | None:
    """Reject oversized Native Messaging lengths before reading a byte of body."""
    header = _read_exact(stream, 4, allow_eof=True)
    if header is None:
        return None
    length = struct.unpack("<I", header)[0]
    if not 1 <= length <= MAX_NATIVE_MESSAGE_BYTES:
        raise BrowserProtocolError("OVERSIZE", "browser message is too large or empty")
    body = _read_exact(stream, length)
    try:
        def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            value: dict[str, object] = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate key")
                value[key] = item
            return value

        payload = json.loads(body, object_pairs_hook=unique_pairs)
        if not isinstance(payload, dict):
            raise ValueError("not an object")
        if payload.get("protocol_version") != 1:
            raise BrowserProtocolError("UNSUPPORTED_VERSION", "unsupported browser protocol")
        kind = payload.get("schema_version")
        model = _MODELS.get((kind, payload.get("event_type") if kind == "browser_sensor_event_v1" else None))
        if model is None:
            raise ValueError("unknown browser message")
        return model.model_validate(payload)
    except BrowserProtocolError:
        raise
    except (TypeError, UnicodeDecodeError, ValueError, ValidationError) as error:
        raise BrowserProtocolError("INVALID_MESSAGE") from error


def encode_native_ack(*, accepted: bool, error_code: str) -> bytes:
    ack = BrowserBridgeAckV1(schema_version="browser_bridge_ack_v1", accepted=accepted, error_code=error_code)
    body = ack.model_dump_json().encode("utf-8")
    if len(body) > 1024:
        raise BrowserProtocolError("OVERSIZE", "browser ACK is too large")
    return struct.pack("<I", len(body)) + body


class BrowserProtocolSession:
    """Bind one Native Messaging process to the pinned extension and family."""

    def __init__(self, *, expected_extension_id: str) -> None:
        if not isinstance(expected_extension_id, str) or len(expected_extension_id) != 32 or any(
            character not in "abcdefghijklmnop" for character in expected_extension_id
        ):
            raise BrowserProtocolError("IDENTITY_MISMATCH", "invalid pinned extension ID")
        self.expected_extension_id = expected_extension_id
        self.family: Family | None = None

    def accept(self, message: BrowserMessageV1 | None) -> BrowserMessageV1:
        if message is None:
            raise BrowserProtocolError("INVALID_MESSAGE", "empty browser message")
        if self.family is None:
            if not isinstance(message, BrowserHelloV1) or message.extension_id != self.expected_extension_id:
                raise BrowserProtocolError("IDENTITY_MISMATCH", "browser identity mismatch")
            self.family = message.browser_family
        elif isinstance(message, BrowserHelloV1) or message.browser_family != self.family:
            raise BrowserProtocolError("IDENTITY_MISMATCH", "browser session mismatch")
        return message


__all__ = [
    "BrowserBridgeAckV1", "BrowserContextV1", "BrowserHeartbeatV1", "BrowserHelloV1",
    "BrowserMessageV1", "BrowserPasteV1", "BrowserProtocolError", "BrowserProtocolSession",
    "BrowserUploadV1", "MAX_NATIVE_MESSAGE_BYTES", "decode_native_message", "encode_native_ack",
]
