"""Fixed, metadata-only Windows Event Log query contracts."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, model_validator

from .base import ContractModelV1
from .system_process_primitives import ErrorCodeV1


EventProfileV1 = Literal["system", "application", "print", "endpoint"]
EventSeverityV1 = Literal["error", "warning", "information"]


class EventFactV1(ContractModelV1):
    timestamp: AwareDatetime
    severity: EventSeverityV1
    event_id: Annotated[int, Field(strict=True, ge=0, le=2**32 - 1)]
    provider: Annotated[str, Field(strict=True, min_length=1, max_length=128, pattern=r"^[^\x00-\x1f\x7f]+$")]
    message_code: Annotated[str, Field(strict=True, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")]


class EventQueryParametersV1(ContractModelV1):
    schema_version: Literal["eventlog_query_parameters_v1"]
    profile: EventProfileV1
    lookback_minutes: Annotated[int, Field(strict=True, ge=1, le=60)]
    severity: EventSeverityV1
    max_events: Annotated[int, Field(strict=True, ge=1, le=32)]


class EventQueryResultV1(ContractModelV1):
    schema_version: Literal["eventlog_query_result_v1"]
    events: list[EventFactV1] = Field(default_factory=list, max_length=32)
    event_count: Annotated[int, Field(strict=True, ge=0, le=32)]
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def validate_result(self) -> "EventQueryResultV1":
        if self.event_count != len(self.events):
            raise ValueError("event count must match safe summaries")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed event query requires an error code")
        return self


class RecentErrorsParametersV1(ContractModelV1):
    schema_version: Literal["eventlog_recent_errors_parameters_v1"]
    profile: EventProfileV1
    lookback_minutes: Annotated[int, Field(strict=True, ge=1, le=60)]


class RecentErrorsResultV1(ContractModelV1):
    schema_version: Literal["eventlog_recent_errors_result_v1"]
    events: list[EventFactV1] = Field(default_factory=list, max_length=20)
    event_count: Annotated[int, Field(strict=True, ge=0, le=20)]
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def validate_result(self) -> "RecentErrorsResultV1":
        if self.event_count != len(self.events):
            raise ValueError("event count must match safe summaries")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed event query requires an error code")
        return self
