"""Negotiated nonfatal dispositions for optional Gateway telemetry."""
from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import ConfigDict, Field, model_validator

from .base import ContractModelV1

TELEMETRY_RESULTS_FEATURE = "endpoint.telemetry-results.v1"


class TelemetryResultV1(ContractModelV1):
    model_config = ConfigDict(json_schema_extra={
        "allOf": [{
            "if": {"properties": {"report_kind": {"const": "security_event_batch"}}},
            "then": {"required": ["event_identifiers"], "properties": {"event_identifiers": {"minItems": 1}}},
            "else": {"properties": {"event_identifiers": {"maxItems": 0}}},
        }],
    })
    schema_version: Literal["telemetry_result_v1"]
    report_kind: Literal[
        "activity_observation", "browser_status_report", "policy_sensor_health_report",
        "security_event_batch",
    ]
    report_id: UUID
    report_sequence: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
    disposition: Literal["accepted", "retry_later", "rejected"]
    reason_code: Annotated[str, Field(strict=True, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")]
    event_identifiers: list[UUID] = Field(default_factory=list, max_length=50, json_schema_extra={"uniqueItems": True})

    @model_validator(mode="after")
    def validate_identifiers(self) -> "TelemetryResultV1":
        if len(self.event_identifiers) != len(set(self.event_identifiers)):
            raise ValueError("event identifiers must be unique")
        if bool(self.event_identifiers) != (self.report_kind == "security_event_batch"):
            raise ValueError("only security batch results require event identifiers")
        return self
