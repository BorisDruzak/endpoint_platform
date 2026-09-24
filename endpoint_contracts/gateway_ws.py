from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    ConfigDict,
    Field,
    RootModel,
    StrictBool,
    field_validator,
    model_validator,
)

from .base import ContractModelV1
from .activity import ActivityObservationV1
from .capabilities import (
    MODULE_CAPABILITY_REGISTRY,
    module_capability_gateway_parameter_schema,
    validate_module_capability_parameters,
)
from .commands import AgentCommandAckV1, AgentCommandV1, AgentResultV1
from .endpoint_policy import EndpointPolicyV1, policy_digest
from .telemetry import AgentHeartbeatV1


MAX_SEQUENCE_V1 = 2**63 - 1
MAX_CAPABILITIES_V1 = 64
MAX_GATEWAY_MESSAGE_BYTES_V1 = 1024 * 1024

BoundedVersionV1 = Annotated[
    str,
    Field(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$",
    ),
]
BoundedStableIdentifierV1 = Annotated[
    str,
    Field(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
CapabilityNameV1 = Annotated[
    str,
    Field(
        strict=True,
        min_length=3,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$",
    ),
]
SequenceV1 = Annotated[int, Field(strict=True, ge=0, le=MAX_SEQUENCE_V1)]
PolicyRevisionV1 = Annotated[int, Field(strict=True, ge=0, le=MAX_SEQUENCE_V1)]
CapabilityListV1 = Annotated[
    list[CapabilityNameV1],
    Field(max_length=MAX_CAPABILITIES_V1, json_schema_extra={"uniqueItems": True}),
]
ProtocolFeatureV1 = Literal[
    "endpoint.policy.v1", "endpoint.activity.v1", "endpoint.security-events.v1"
]
ProtocolFeaturesV1 = Annotated[
    list[ProtocolFeatureV1], Field(strict=True, max_length=3)
]


def _validate_unique_capabilities(capabilities: list[str]) -> list[str]:
    if len(capabilities) != len(set(capabilities)):
        raise ValueError("capabilities must not contain duplicates")
    return capabilities


class AgentHelloV1(ContractModelV1):
    schema_version: Literal["agent_hello_v1"]
    device_id: UUID
    agent_instance_id: UUID
    agent_version: BoundedVersionV1
    launcher_version: BoundedVersionV1
    platform: Literal["linux_amd64", "windows_amd64"]
    boot_id: BoundedStableIdentifierV1
    capabilities: CapabilityListV1
    last_result_sequence: SequenceV1
    last_policy_revision: PolicyRevisionV1
    protocol_features: ProtocolFeaturesV1 = Field(default_factory=list)

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, capabilities: list[str]) -> list[str]:
        return _validate_unique_capabilities(capabilities)

    @field_validator("protocol_features")
    @classmethod
    def validate_protocol_features(cls, features: list[str]) -> list[str]:
        if len(features) != len(set(features)):
            raise ValueError("protocol features must not contain duplicates")
        return features


class GatewayHelloV1(ContractModelV1):
    schema_version: Literal["gateway_hello_v1"]
    session_id: UUID
    heartbeat_interval_seconds: Annotated[int, Field(strict=True, ge=1, le=3600)]
    maximum_message_bytes: Annotated[
        int,
        Field(strict=True, ge=1024, le=MAX_GATEWAY_MESSAGE_BYTES_V1),
    ]
    policy_revision: PolicyRevisionV1
    effective_capabilities: CapabilityListV1
    server_time: AwareDatetime

    @field_validator("effective_capabilities")
    @classmethod
    def validate_effective_capabilities(cls, capabilities: list[str]) -> list[str]:
        return _validate_unique_capabilities(capabilities)


def _gateway_command_schema_extra(schema: dict[str, object]) -> None:
    """Publish the same capability-specific parameter allowlist used at runtime."""
    parent_schema_extra = AgentCommandV1.model_config.get("json_schema_extra")
    if isinstance(parent_schema_extra, dict):
        schema.update(parent_schema_extra)
    no_parameters = [
        "agent.status.read",
        "context.baseline.collect",
        "context.health.collect",
        "context.network.collect",
        "context.inventory.collect",
        "context.session.collect",
    ]
    safe_text = {
        "type": "string",
        "minLength": 1,
        "maxLength": 512,
        "pattern": r"^(?![\s\S]*://)[\s\S]*$",
    }
    schema["allOf"] = [
        {
            "if": {"properties": {"capability": {"enum": no_parameters}}},
            "then": {"properties": {"parameters": {"maxProperties": 0}}},
        },
        {
            "if": {"properties": {"capability": {"const": "gateway.echo"}}},
            "then": {
                "properties": {
                    "parameters": {
                        "type": "object",
                        "properties": {"message": safe_text},
                        "additionalProperties": False,
                    }
                }
            },
        },
        {
            "if": {
                "properties": {"capability": {"const": "context.diagnostic.collect"}}
            },
            "then": {
                "properties": {
                    "parameters": {
                        "type": "object",
                        "properties": {"reason": {**safe_text, "maxLength": 256}},
                        "additionalProperties": False,
                    }
                }
            },
        },
    ]
    schema["allOf"].extend(
        {
            "if": {"properties": {"capability": {"const": capability}}},
            "then": {
                "properties": {
                    "parameters": module_capability_gateway_parameter_schema(capability)
                }
            },
        }
        for capability in MODULE_CAPABILITY_REGISTRY
    )


class GatewayCommandV1(AgentCommandV1):
    """Existing neutral command contract narrowed for the WSS control channel."""

    model_config = ConfigDict(json_schema_extra=_gateway_command_schema_extra)

    @model_validator(mode="after")
    def validate_control_parameters(self) -> "GatewayCommandV1":
        allowed_keys: dict[str, frozenset[str]] = {
            "agent.status.read": frozenset(),
            "gateway.echo": frozenset({"message"}),
            "context.baseline.collect": frozenset(),
            "context.health.collect": frozenset(),
            "context.network.collect": frozenset(),
            "context.inventory.collect": frozenset(),
            "context.session.collect": frozenset(),
            "context.diagnostic.collect": frozenset({"reason"}),
        }
        if self.capability in MODULE_CAPABILITY_REGISTRY:
            validate_module_capability_parameters(self.capability, self.parameters)
            return self
        unexpected = set(self.parameters) - allowed_keys[self.capability]
        if unexpected:
            raise ValueError(
                "gateway command parameters are not allowed for this capability"
            )
        for key, value in self.parameters.items():
            limit = 256 if key == "reason" else 512
            if (
                not isinstance(value, str)
                or not value
                or len(value) > limit
                or "://" in value
            ):
                raise ValueError(
                    "gateway command text parameters must be bounded and URL-free"
                )
        return self


class CommandCancelV1(ContractModelV1):
    schema_version: Literal["command_cancel_v1"]
    command_id: UUID
    reason: Literal[
        "operator_requested",
        "expired",
        "superseded",
        "policy_changed",
        "server_shutdown",
    ]
    canceled_at: AwareDatetime


class ResultAckV1(ContractModelV1):
    schema_version: Literal["result_ack_v1"]
    command_id: UUID
    result_sequence: SequenceV1


class PolicyUpdateV1(ContractModelV1):
    schema_version: Literal["policy_update_v1"]
    policy_revision: PolicyRevisionV1
    effective_capabilities: CapabilityListV1

    @field_validator("effective_capabilities")
    @classmethod
    def validate_effective_capabilities(cls, capabilities: list[str]) -> list[str]:
        return _validate_unique_capabilities(capabilities)


PolicyDigestV1 = Annotated[
    str, Field(strict=True, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
]


class EndpointPolicyDeliveryV1(ContractModelV1):
    schema_version: Literal["endpoint_policy_delivery_v1"]
    policy_version_id: UUID
    policy: EndpointPolicyV1
    policy_digest: PolicyDigestV1
    issued_at: AwareDatetime

    @model_validator(mode="after")
    def validate_digest(self) -> "EndpointPolicyDeliveryV1":
        if self.policy_digest != policy_digest(self.policy):
            raise ValueError("policy delivery digest does not match document")
        return self


class EndpointPolicyAckV1(ContractModelV1):
    model_config = ConfigDict(json_schema_extra={
        "allOf": [
            {
                "if": {"properties": {"status": {"const": "APPLIED"}}},
                "then": {
                    "required": ["applied_at"],
                    "properties": {
                        "applied_at": {"type": "string", "format": "date-time"},
                        "error_code": {"type": "null"},
                    },
                },
            },
            {
                "if": {"properties": {"status": {"const": "ERROR"}}},
                "then": {
                    "required": ["error_code"],
                    "properties": {
                        "applied_at": {"type": "null"},
                        "error_code": {"type": "string"},
                    },
                },
            },
        ]
    })

    schema_version: Literal["endpoint_policy_ack_v1"]
    policy_id: UUID
    policy_version: Annotated[int, Field(strict=True, ge=1, le=2**31 - 1)]
    policy_digest: PolicyDigestV1
    received_at: AwareDatetime
    applied_at: AwareDatetime | None = None
    status: Literal["APPLIED", "ERROR"]
    error_code: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=64, pattern=r"^[A-Z][A-Z0-9_]*$"),
    ] = None

    @model_validator(mode="after")
    def validate_status(self) -> "EndpointPolicyAckV1":
        if self.status == "APPLIED":
            if self.applied_at is None or self.error_code is not None:
                raise ValueError("applied policy requires applied_at and no error")
        elif self.error_code is None or self.applied_at is not None:
            raise ValueError("failed policy requires an error code and no applied_at")
        if self.applied_at is not None and self.applied_at < self.received_at:
            raise ValueError("applied_at must follow received_at")
        return self


class ServerShutdownNoticeV1(ContractModelV1):
    schema_version: Literal["server_shutdown_notice_v1"]
    reason: Literal[
        "server_restart",
        "session_replaced",
        "maintenance",
        "server_shutdown",
    ]
    retry_after_seconds: Annotated[int | None, Field(strict=True, ge=0, le=86400)] = (
        None
    )


class GatewayErrorV1(ContractModelV1):
    schema_version: Literal["gateway_error_v1"]
    code: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            max_length=64,
            pattern=r"^[a-z][a-z0-9_]*$",
        ),
    ]
    message: Annotated[str, Field(strict=True, min_length=1, max_length=512)]
    retryable: StrictBool


class _GatewayWsEnvelopeBaseV1(ContractModelV1):
    schema_version: Literal["gateway_ws_envelope_v1"]
    sequence: SequenceV1


class AgentHelloEnvelopeV1(_GatewayWsEnvelopeBaseV1):
    kind: Literal["agent_hello"]
    payload: AgentHelloV1


class GatewayHelloEnvelopeV1(_GatewayWsEnvelopeBaseV1):
    kind: Literal["gateway_hello"]
    payload: GatewayHelloV1


class HeartbeatEnvelopeV1(_GatewayWsEnvelopeBaseV1):
    kind: Literal["heartbeat"]
    payload: AgentHeartbeatV1


class CommandEnvelopeV1(_GatewayWsEnvelopeBaseV1):
    kind: Literal["command"]
    payload: GatewayCommandV1


class CommandAckEnvelopeV1(_GatewayWsEnvelopeBaseV1):
    kind: Literal["command_ack"]
    payload: AgentCommandAckV1


class CommandResultEnvelopeV1(_GatewayWsEnvelopeBaseV1):
    kind: Literal["command_result"]
    payload: AgentResultV1


class CommandCancelEnvelopeV1(_GatewayWsEnvelopeBaseV1):
    kind: Literal["command_cancel"]
    payload: CommandCancelV1


class ResultAckEnvelopeV1(_GatewayWsEnvelopeBaseV1):
    kind: Literal["result_ack"]
    payload: ResultAckV1


class PolicyUpdateEnvelopeV1(_GatewayWsEnvelopeBaseV1):
    kind: Literal["policy_update"]
    payload: PolicyUpdateV1


class EndpointPolicyDeliveryEnvelopeV1(_GatewayWsEnvelopeBaseV1):
    kind: Literal["endpoint_policy_delivery"]
    payload: EndpointPolicyDeliveryV1


class EndpointPolicyAckEnvelopeV1(_GatewayWsEnvelopeBaseV1):
    kind: Literal["endpoint_policy_ack"]
    payload: EndpointPolicyAckV1


class ActivityObservationEnvelopeV1(_GatewayWsEnvelopeBaseV1):
    kind: Literal["activity_observation"]
    payload: ActivityObservationV1


class ServerShutdownNoticeEnvelopeV1(_GatewayWsEnvelopeBaseV1):
    kind: Literal["server_shutdown_notice"]
    payload: ServerShutdownNoticeV1


class ErrorEnvelopeV1(_GatewayWsEnvelopeBaseV1):
    kind: Literal["error"]
    payload: GatewayErrorV1


GatewayWsEnvelopeBodyV1 = Annotated[
    AgentHelloEnvelopeV1
    | GatewayHelloEnvelopeV1
    | HeartbeatEnvelopeV1
    | CommandEnvelopeV1
    | CommandAckEnvelopeV1
    | CommandResultEnvelopeV1
    | CommandCancelEnvelopeV1
    | ResultAckEnvelopeV1
    | PolicyUpdateEnvelopeV1
    | EndpointPolicyDeliveryEnvelopeV1
    | EndpointPolicyAckEnvelopeV1
    | ActivityObservationEnvelopeV1
    | ServerShutdownNoticeEnvelopeV1
    | ErrorEnvelopeV1,
    Field(discriminator="kind"),
]


class GatewayWsEnvelopeV1(RootModel[GatewayWsEnvelopeBodyV1]):
    model_config = ConfigDict(frozen=True)


GatewayInboundBodyV1 = Annotated[
    CommandEnvelopeV1
    | CommandCancelEnvelopeV1
    | ResultAckEnvelopeV1
    | PolicyUpdateEnvelopeV1
    | EndpointPolicyDeliveryEnvelopeV1
    | ServerShutdownNoticeEnvelopeV1
    | ErrorEnvelopeV1,
    Field(discriminator="kind"),
]


class GatewayInboundV1(RootModel[GatewayInboundBodyV1]):
    """Strict server-to-agent messages returned by a connected transport."""

    model_config = ConfigDict(frozen=True)


__all__ = [
    "AgentHelloV1",
    "ActivityObservationEnvelopeV1",
    "CommandCancelV1",
    "GatewayErrorV1",
    "GatewayHelloV1",
    "GatewayInboundV1",
    "GatewayWsEnvelopeV1",
    "EndpointPolicyAckEnvelopeV1",
    "EndpointPolicyAckV1",
    "EndpointPolicyDeliveryEnvelopeV1",
    "EndpointPolicyDeliveryV1",
    "PolicyUpdateV1",
    "ResultAckV1",
    "ServerShutdownNoticeV1",
]
