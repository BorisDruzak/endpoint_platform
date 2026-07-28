import json
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

MAX_JSON_DEPTH = 8
MAX_JSON_STRING_LENGTH = 4096
MAX_JSON_LIST_ITEMS = 32
MAX_JSON_MAP_ITEMS = 32
MAX_JSON_NODES = 1024
MAX_JSON_SERIALIZED_BYTES = 65536


def _validate_bounded_json(value: JsonValue, *, depth: int, node_count: list[int]) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON value exceeds maximum nesting depth")

    node_count[0] += 1
    if node_count[0] > MAX_JSON_NODES:
        raise ValueError("JSON value exceeds maximum structural size")

    if isinstance(value, str):
        if len(value) > MAX_JSON_STRING_LENGTH:
            raise ValueError("JSON string exceeds maximum length")
        return
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return
    if isinstance(value, dict):
        if len(value) > MAX_JSON_MAP_ITEMS:
            raise ValueError("JSON map exceeds maximum size")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON map keys must be strings")
            _validate_bounded_json(key, depth=depth + 1, node_count=node_count)
            _validate_bounded_json(item, depth=depth + 1, node_count=node_count)
        return
    if isinstance(value, list):
        if len(value) > MAX_JSON_LIST_ITEMS:
            raise ValueError("JSON list exceeds maximum size")
        for item in value:
            _validate_bounded_json(item, depth=depth + 1, node_count=node_count)


def validate_bounded_json(value: JsonValue) -> None:
    _validate_bounded_json(value, depth=0, node_count=[0])
    serialized = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    if len(serialized.encode("utf-8")) > MAX_JSON_SERIALIZED_BYTES:
        raise ValueError("JSON value exceeds maximum serialized size")


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
        validate_bounded_json(self.parameters)
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

    @model_validator(mode="after")
    def validate_result_items(self) -> "AgentResultV1":
        validate_bounded_json(self.result_items)
        return self
