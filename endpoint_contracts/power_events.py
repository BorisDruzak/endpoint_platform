"""Policy-independent, bounded native OS power evidence and exact dispositions."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, field_validator, model_validator
from .base import ContractModelV1

POWER_EVENTS_FEATURE = "endpoint.power-events.v1"
MAX_POWER_EVENT_BATCH_BYTES_V1 = 60 * 1024
PowerEventKindV1 = Literal[
    "OS_STARTED",
    "OS_SHUTDOWN_STARTED",
    "OS_SLEEP_STARTED",
    "OS_RESUMED",
    "OS_UNEXPECTED_SHUTDOWN_REPORTED",
]
PowerIdentifierV1 = Annotated[
    str,
    Field(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:+/=-]*$",
    ),
]
PowerCounterV1 = Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]


class PowerEventV1(ContractModelV1):
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "event_kind": {"enum": ["OS_STARTED", "OS_RESUMED"]}
                        }
                    },
                    "then": {"properties": {"evidence": {"const": "transition"}}},
                },
                {
                    "if": {
                        "properties": {
                            "event_kind": {"const": "OS_UNEXPECTED_SHUTDOWN_REPORTED"}
                        }
                    },
                    "then": {"properties": {"evidence": {"const": "reported"}}},
                },
                {
                    "if": {
                        "properties": {
                            "event_kind": {"not": {"const": "OS_SLEEP_STARTED"}}
                        }
                    },
                    "then": {"properties": {"sleep_subtype": {"type": "null"}}},
                },
            ]
        }
    )
    schema_version: Literal["power_event_v1"]
    event_identifier: UUID
    event_kind: PowerEventKindV1
    occurred_at: AwareDatetime
    observed_at: AwareDatetime
    boot_id: PowerIdentifierV1
    source: PowerIdentifierV1
    native_record_id: PowerIdentifierV1
    evidence: Literal["transition", "request", "reported"]
    sleep_subtype: Literal["sleep", "hibernate", "hybrid", "unknown"] | None = None

    @model_validator(mode="after")
    def validate_evidence(self):
        if self.sleep_subtype is not None and self.event_kind != "OS_SLEEP_STARTED":
            raise ValueError("sleep subtype requires sleep entry")
        if (
            self.event_kind == "OS_UNEXPECTED_SHUTDOWN_REPORTED"
            and self.evidence != "reported"
        ):
            raise ValueError("unclean shutdown is reported evidence")
        if (
            self.event_kind in {"OS_STARTED", "OS_RESUMED"}
            and self.evidence != "transition"
        ):
            raise ValueError("startup and resume require transition evidence")
        return self


class PowerSourceStatusV1(ContractModelV1):
    schema_version: Literal["power_source_status_v1"]
    source: PowerIdentifierV1
    availability: Literal["READY", "DEGRADED", "UNAVAILABLE", "UNSUPPORTED"]
    reported_at: AwareDatetime
    coverage_started_at: AwareDatetime | None = None
    loss_count: PowerCounterV1 = 0
    reset_count: PowerCounterV1 = 0

    @model_validator(mode="after")
    def validate_coverage(self):
        if (
            self.coverage_started_at is not None
            and self.coverage_started_at > self.reported_at
        ):
            raise ValueError("coverage starts after report")
        return self


class PowerEventBatchV1(ContractModelV1):
    schema_version: Literal["power_event_batch_v1"]
    batch_id: UUID
    events: Annotated[list[PowerEventV1], Field(max_length=128)]
    source_status: PowerSourceStatusV1

    @field_validator("events")
    @classmethod
    def unique_events(cls, values):
        ids = [value.event_identifier for value in values]
        if len(ids) != len(set(ids)):
            raise ValueError("event identifiers must be unique")
        return values


class PowerEventDispositionV1(ContractModelV1):
    event_identifier: UUID
    disposition: Literal["accepted", "retry_later", "rejected"]
    reason_code: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$"),
    ]


class PowerEventAckV1(ContractModelV1):
    schema_version: Literal["power_event_ack_v1"]
    batch_id: UUID
    persisted_at: AwareDatetime
    results: Annotated[list[PowerEventDispositionV1], Field(max_length=128)]

    @field_validator("results")
    @classmethod
    def unique_results(cls, values):
        ids = [value.event_identifier for value in values]
        if len(ids) != len(set(ids)):
            raise ValueError("disposition identifiers must be unique")
        return values
