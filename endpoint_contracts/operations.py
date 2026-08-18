from __future__ import annotations

import re
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    ConfigDict,
    Field,
    StrictBool,
    field_validator,
    model_validator,
)

from .base import ContractModelV1
from .context import ContextWarningCodeV1, DiagnosticProcessV1


EndpointOperationStatusV1 = Literal[
    "queued",
    "delivered",
    "acknowledged",
    "running",
    "succeeded",
    "failed",
    "canceled",
    "expired",
]

_REASON_JSON_SCHEMA_PATTERN = r"^(?![\s\S]*://)[^\x00-\x1f\x7f]{1,256}(?![\s\S])"
_NORMALIZED_IDENTIFIER_PATTERN = r"^[a-z][a-z0-9._-]{0,63}$"
_OPAQUE_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
_LOG_EXCERPT_JSON_SCHEMA_PATTERN = (
    r"^(?![\s\S]*(?:"
    r"[Tt][Rr][Aa][Cc][Ee][Bb][Aa][Cc][Kk]\s*\(\s*[Mm]ost\s+[Rr]ecent\s+"
    r"[Cc]all\s+[Ll]ast\s*\)\s*:|"
    r"[Ff]ile\s+[\"'][^\r\n\"']+[\"']\s*,\s*[Ll]ine\s+\d+|"
    r"[Bb][Ee][Aa][Rr][Ee][Rr]\s+"
    r"(?!(?:(?:[Aa]uth|[Aa]uthentication)\s+(?:[Ww]as\s+)?"
    r"(?:\[[Rr]edacted\]|[Rr]edacted|[Aa]bsent|[Nn]one|[Nn]ull)|"
    r"\[[Rr]edacted\]|[Rr]edacted|[Aa]bsent|[Nn]one|[Nn]ull)(?:[.,;)]?\s*)$)\S+|"
    r"\b(?:[Tt]oken|[Ss]ecret|[Aa][Cc][Cc][Ee][Ss][Ss][_ -]?[Tt][Oo][Kk][Ee][Nn]|"
    r"[Aa][Pp][Ii][_ -]?[Kk][Ee][Yy]|"
    r"[Cc][Ll][Ii][Ee][Nn][Tt][_ -]?[Ss][Ee][Cc][Rr][Ee][Tt]|"
    r"[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|"
    r"[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll]|"
    r"[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn])\s*(?:[:=]|\s+)\s*"
    r"(?!(?:\[[Rr]edacted\]|[Rr]edacted|[Aa]bsent|[Nn]one|[Nn]ull)"
    r"(?:[.,;)]?\s*)$)\S+|"
    r"(?:[Tt][Oo][Kk]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Aa][Pp][Ii]|[Ss][Kk]|[Pp][Kk])_"
    r"[A-Za-z0-9_-]{8,}|"
    r"(?:[A-Za-z]:[\\/]|/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)"
    r"))[\s\S]{0,8192}(?![\s\S])"
)
_REDACTED_LOG_EXCERPT_PATTERN = re.compile(_LOG_EXCERPT_JSON_SCHEMA_PATTERN)

DiagnosticReasonV1 = Annotated[
    str,
    Field(
        strict=True,
        min_length=1,
        max_length=256,
        json_schema_extra={"pattern": _REASON_JSON_SCHEMA_PATTERN},
    ),
]
NormalizedIdentifierV1 = Annotated[
    str,
    Field(
        strict=True,
        min_length=1,
        max_length=64,
        pattern=_NORMALIZED_IDENTIFIER_PATTERN,
    ),
]
OpaqueIdentifierV1 = Annotated[
    str,
    Field(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=_OPAQUE_IDENTIFIER_PATTERN,
    ),
]


def _validate_safe_reason(value: str) -> str:
    if "://" in value or _CONTROL_CHARACTER_PATTERN.search(value):
        raise ValueError("reason must be control-character- and URL-free")
    return value


class DiagnosticCollectionParametersV1(ContractModelV1):
    """The only public operation input supported in v1."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    reason: DiagnosticReasonV1

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        return _validate_safe_reason(value)


class EndpointOperationCorrelationV1(ContractModelV1):
    """Opaque caller correlation that never reaches the endpoint agent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["endpoint_operation_correlation_v1"]
    source_system: NormalizedIdentifierV1
    source_entity_type: NormalizedIdentifierV1
    source_entity_id: OpaqueIdentifierV1
    request_id: UUID | None = None


class EndpointOperationCreateV1(ContractModelV1):
    """Strict service request for one bounded diagnostic collection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["endpoint_operation_create_v1"]
    capability: Literal["context.diagnostic.collect"]
    parameters: DiagnosticCollectionParametersV1
    correlation: EndpointOperationCorrelationV1 | None = None


class EndpointDiagnosticResultV1(ContractModelV1):
    """Safe, redacted diagnostic snapshot exposed outside Endpoint Platform."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["endpoint_diagnostic_result_v1"]
    profile: Literal["diagnostic_v1"]
    collected_at: AwareDatetime
    reason: DiagnosticReasonV1
    warnings: list[ContextWarningCodeV1] = Field(default_factory=list, max_length=16)
    processes: list[DiagnosticProcessV1] = Field(default_factory=list, max_length=64)
    log_excerpt: Annotated[
        str | None,
        Field(
            strict=True,
            max_length=8192,
            json_schema_extra={"pattern": _LOG_EXCERPT_JSON_SCHEMA_PATTERN},
        ),
    ] = None

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        return _validate_safe_reason(value)

    @field_validator("log_excerpt")
    @classmethod
    def validate_redacted_log_excerpt(cls, value: str | None) -> str | None:
        if value is not None and not _REDACTED_LOG_EXCERPT_PATTERN.fullmatch(value):
            raise ValueError(
                "log_excerpt must not expose exception, path, or credential text"
            )
        return value

    @field_validator("warnings")
    @classmethod
    def validate_unique_warnings(
        cls, value: list[ContextWarningCodeV1]
    ) -> list[ContextWarningCodeV1]:
        if len(value) != len(set(value)):
            raise ValueError("warnings must not contain duplicates")
        return value


class EndpointOperationV1(ContractModelV1):
    """Service-visible operation lifecycle without command or agent internals."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "$comment": (
                "Model-only constraints: deadline_at must be after created_at; "
                "completed_at is set only for terminal states; succeeded "
                "operations expose an available safe diagnostic result."
            )
        },
    )

    schema_version: Literal["endpoint_operation_v1"]
    operation_id: UUID
    device_id: UUID
    capability: Literal["context.diagnostic.collect"]
    status: EndpointOperationStatusV1
    created_at: AwareDatetime
    deadline_at: AwareDatetime
    completed_at: AwareDatetime | None = None
    correlation: EndpointOperationCorrelationV1 | None = None
    result_available: StrictBool
    warnings: list[ContextWarningCodeV1] = Field(default_factory=list, max_length=16)

    @field_validator("warnings")
    @classmethod
    def validate_unique_warnings(
        cls, value: list[ContextWarningCodeV1]
    ) -> list[ContextWarningCodeV1]:
        if len(value) != len(set(value)):
            raise ValueError("warnings must not contain duplicates")
        return value

    @model_validator(mode="after")
    def validate_public_lifecycle(self) -> EndpointOperationV1:
        terminal_statuses = frozenset({"succeeded", "failed", "canceled", "expired"})
        if self.deadline_at <= self.created_at:
            raise ValueError("deadline_at must be after created_at")
        if self.completed_at is not None and self.completed_at < self.created_at:
            raise ValueError("completed_at must not be before created_at")
        if (self.completed_at is not None) != (self.status in terminal_statuses):
            raise ValueError("completed_at must match a terminal operation status")
        if self.result_available != (self.status == "succeeded"):
            raise ValueError("result availability must match succeeded status")
        return self


__all__ = [
    "DiagnosticCollectionParametersV1",
    "EndpointDiagnosticResultV1",
    "EndpointOperationCorrelationV1",
    "EndpointOperationCreateV1",
    "EndpointOperationStatusV1",
    "EndpointOperationV1",
]
