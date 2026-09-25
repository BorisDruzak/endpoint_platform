"""Content-free, bounded SecurityEvent transport contracts."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, StrictBool, field_validator, model_validator

from .activity import BrowserActivityV1
from .base import ContractModelV1


MAX_SECURITY_EVENTS_PER_BATCH_V1 = 50
MAX_SECURITY_EVENT_BATCH_BYTES_V1 = 64 * 1024
MAX_SECURITY_EVENT_METADATA_BYTES_V1 = 2048

_SafeIdentity = Annotated[
    str,
    Field(strict=True, min_length=1, max_length=128, pattern=r"^[^\\/\x00-\x1f:]+$"),
]
_UserLogin = Annotated[
    str | None,
    Field(strict=True, max_length=256, pattern=r"^[^\x00-\x1f]+$"),
]
_Hash = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{64}$")]
_Category = Literal[
    "spreadsheet", "document", "image", "video", "audio", "archive", "other"
]
_ClipboardType = Literal["text", "html", "image", "files", "other"]


def _unique(values: list[object]) -> list[object]:
    if len(values) != len(set(values)):
        raise ValueError("values must be unique")
    return values


class UsbEventMetadataV1(ContractModelV1):
    vendor: _SafeIdentity | None = None
    product: _SafeIdentity | None = None
    device_class: Literal["mass_storage", "hid", "printer", "other"] | None = None
    removable: StrictBool
    serial_hash: _Hash | None = None


class PrintEventMetadataV1(ContractModelV1):
    printer_identity: _SafeIdentity
    page_count: Annotated[int | None, Field(strict=True, ge=0, le=1_000_000)] = None
    copies: Annotated[int | None, Field(strict=True, ge=1, le=1_000_000)] = None
    total_bytes: Annotated[int | None, Field(strict=True, ge=0, le=2**53 - 1)] = None


class _BrowserEventMetadataV1(ContractModelV1):
    domain: Annotated[str, Field(strict=True, min_length=1, max_length=253)]
    origin: Annotated[str, Field(strict=True, min_length=1, max_length=512)]
    browser_family: Literal["chrome", "yandex"]

    @model_validator(mode="after")
    def validate_origin(self) -> "_BrowserEventMetadataV1":
        BrowserActivityV1(
            browser_family=self.browser_family,
            domain=self.domain,
            origin=self.origin,
            sensor_state="ACTIVE",
        )
        return self


class BrowserUploadMetadataV1(_BrowserEventMetadataV1):
    file_count: Annotated[int, Field(strict=True, ge=1, le=64)]
    total_bytes: Annotated[int, Field(strict=True, ge=0, le=2**53 - 1)]
    mime_categories: list[_Category] = Field(min_length=1, max_length=7)

    @field_validator("mime_categories")
    @classmethod
    def validate_categories(cls, value: list[str]) -> list[str]:
        return _unique(value)


class BrowserPasteMetadataV1(_BrowserEventMetadataV1):
    clipboard_types: list[_ClipboardType] = Field(max_length=5)

    @field_validator("clipboard_types")
    @classmethod
    def validate_types(cls, value: list[str]) -> list[str]:
        return _unique(value)


class _SecurityEventBaseV1(ContractModelV1):
    schema_version: Literal["security_event_v1"]
    event_identifier: UUID
    severity: Literal["INFO"]
    occurred_at: AwareDatetime
    user_login: _UserLogin = None
    policy_id: UUID
    policy_version: Annotated[int, Field(strict=True, ge=1, le=2**31 - 1)]

    @model_validator(mode="after")
    def validate_metadata_size(self) -> "_SecurityEventBaseV1":
        if (
            len(self.safe_metadata.model_dump_json().encode("utf-8"))
            > MAX_SECURITY_EVENT_METADATA_BYTES_V1
        ):
            raise ValueError("security event metadata exceeds bound")
        return self


class UsbConnectedEventV1(_SecurityEventBaseV1):
    event_type: Literal["USB_DEVICE_CONNECTED"]
    channel: Literal["USB"]
    safe_metadata: UsbEventMetadataV1


class UsbDisconnectedEventV1(_SecurityEventBaseV1):
    event_type: Literal["USB_DEVICE_DISCONNECTED"]
    channel: Literal["USB"]
    safe_metadata: UsbEventMetadataV1


class PrintJobEventV1(_SecurityEventBaseV1):
    event_type: Literal["PRINT_JOB"]
    channel: Literal["PRINT"]
    safe_metadata: PrintEventMetadataV1


class BrowserUploadEventV1(_SecurityEventBaseV1):
    event_type: Literal["BROWSER_UPLOAD"]
    channel: Literal["BROWSER"]
    safe_metadata: BrowserUploadMetadataV1


class BrowserPasteEventV1(_SecurityEventBaseV1):
    event_type: Literal["BROWSER_PASTE"]
    channel: Literal["BROWSER"]
    safe_metadata: BrowserPasteMetadataV1


SecurityEventV1 = Annotated[
    UsbConnectedEventV1
    | UsbDisconnectedEventV1
    | PrintJobEventV1
    | BrowserUploadEventV1
    | BrowserPasteEventV1,
    Field(discriminator="event_type"),
]


class AgentSecurityEventBatchV1(ContractModelV1):
    schema_version: Literal["agent_security_event_batch_v1"]
    batch_id: UUID
    events: list[SecurityEventV1] = Field(
        min_length=1, max_length=MAX_SECURITY_EVENTS_PER_BATCH_V1
    )

    @model_validator(mode="after")
    def validate_batch(self) -> "AgentSecurityEventBatchV1":
        _unique([event.event_identifier for event in self.events])
        if (
            len(self.model_dump_json().encode("utf-8"))
            > MAX_SECURITY_EVENT_BATCH_BYTES_V1
        ):
            raise ValueError("security event batch exceeds bound")
        return self


class SecurityEventAckV1(ContractModelV1):
    schema_version: Literal["security_event_ack_v1"]
    batch_id: UUID
    event_identifiers: list[UUID] = Field(
        min_length=1, max_length=MAX_SECURITY_EVENTS_PER_BATCH_V1
    )
    persisted_at: AwareDatetime

    @field_validator("event_identifiers")
    @classmethod
    def validate_identifiers(cls, values: list[UUID]) -> list[UUID]:
        return _unique(values)


__all__ = [
    "AgentSecurityEventBatchV1",
    "SecurityEventAckV1",
    "SecurityEventV1",
    "MAX_SECURITY_EVENTS_PER_BATCH_V1",
    "MAX_SECURITY_EVENT_BATCH_BYTES_V1",
    "MAX_SECURITY_EVENT_METADATA_BYTES_V1",
]
