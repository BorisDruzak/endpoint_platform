from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, model_validator

from .base import ContractModelV1
from .capabilities import (
    MODULE_CAPABILITY_REGISTRY,
    ModuleCapabilityNameV1,
    validate_module_capability_parameters,
)
from .json_types import (
    BoundedJsonKeyV1,
    BoundedJsonValueV1,
    validate_bounded_json,
)

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
LegacyAgentCapabilityV1 = Literal[
    "agent.status.read",
    "gateway.echo",
    "context.baseline.collect",
    "context.health.collect",
    "context.network.collect",
    "context.diagnostic.collect",
]
AgentCapabilityV1 = LegacyAgentCapabilityV1 | ModuleCapabilityNameV1


class CommandCorrelationV1(ContractModelV1):
    schema_version: Literal["command_correlation_v1"] = "command_correlation_v1"
    request_id: UUID | None = None
    parent_command_id: UUID | None = None


class AgentCommandV1(ContractModelV1):
    model_config = ConfigDict(
        json_schema_extra={
            "$comment": (
                "deadline_at must be after created_at; this cross-field ordering "
                "rule is enforced by the Pydantic model only."
            )
        }
    )

    schema_version: Literal["agent_command_v1"]
    command_id: UUID
    device_id: UUID
    capability: AgentCapabilityV1
    parameters: dict[BoundedJsonKeyV1, BoundedJsonValueV1] = Field(
        default_factory=dict,
        max_length=32,
        json_schema_extra={
            "$comment": (
                "Aggregate node count and serialized byte size are enforced by "
                "the Pydantic model only; JSON Schema enforces per-node bounds."
            )
        },
    )
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
        validate_bounded_json(self.parameters)
        if self.capability in MODULE_CAPABILITY_REGISTRY:
            validate_module_capability_parameters(self.capability, self.parameters)
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
    result_items: list[BoundedJsonValueV1] = Field(
        default_factory=list,
        max_length=32,
        json_schema_extra={
            "$comment": (
                "Aggregate node count and serialized byte size are enforced by "
                "the Pydantic model only; JSON Schema enforces per-node bounds."
            )
        },
    )
    message: Annotated[str | None, Field(max_length=4096)] = None
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_result_items(self) -> "AgentResultV1":
        validate_bounded_json(self.result_items)
        return self
