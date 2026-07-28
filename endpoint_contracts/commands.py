from math import isfinite
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, JsonValue, model_validator

from .base import ContractModelV1

CommandStatusV1 = Literal[
    "queued",
    "delivered",
    "acknowledged",
    "running",
    "succeeded",
    "failed",
    "canceled",
    "expired",
]


def _contains_non_finite_number(value: JsonValue) -> bool:
    if isinstance(value, float):
        return not isfinite(value)
    if isinstance(value, dict):
        return any(_contains_non_finite_number(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_non_finite_number(item) for item in value)
    return False


class CommandCorrelationV1(ContractModelV1):
    schema_version: Literal["command_correlation_v1"] = "command_correlation_v1"
    request_id: UUID | None = None
    parent_command_id: UUID | None = None


class AgentCommandV1(ContractModelV1):
    schema_version: Literal["agent_command_v1"]
    command_id: UUID
    device_id: UUID
    capability: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{2,95}$")]
    parameters: dict[str, JsonValue] = Field(default_factory=dict, max_length=32)
    requested_by_service: Annotated[str, Field(min_length=3, max_length=96)]
    idempotency_key: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$"),
    ]
    created_at: AwareDatetime
    deadline_at: AwareDatetime
    correlation: CommandCorrelationV1 = Field(default_factory=CommandCorrelationV1)

    @model_validator(mode="after")
    def validate_deadline(self) -> "AgentCommandV1":
        if self.deadline_at <= self.created_at:
            raise ValueError("deadline_at must be after created_at")
        if _contains_non_finite_number(self.parameters):
            raise ValueError("parameters must contain only finite JSON numbers")
        return self


class AgentCommandAckV1(ContractModelV1):
    schema_version: Literal["agent_command_ack_v1"]
    command_id: UUID
    device_id: UUID
    status: CommandStatusV1
    acknowledged_at: AwareDatetime
    message: Annotated[str | None, Field(max_length=4096)] = None


class AgentResultV1(ContractModelV1):
    schema_version: Literal["agent_result_v1"]
    command_id: UUID
    device_id: UUID
    status: CommandStatusV1
    result_items: list[JsonValue] = Field(default_factory=list, max_length=32)
    message: Annotated[str | None, Field(max_length=4096)] = None
    completed_at: AwareDatetime
