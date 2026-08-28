"""Closed, typed module-capability registry owned by Endpoint Platform."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Literal

from pydantic import Field

from .base import ContractModelV1
from .network_primitives import (
    DnsResolveParametersV1,
    DnsResolveResultV1,
    NetworkPingParametersV1,
    NetworkPingResultV1,
    TcpConnectParametersV1,
    TcpConnectResultV1,
)
from .read_only_primitives import (
    AdapterListParametersV1,
    AdapterListResultV1,
    RouteGetParametersV1,
    RouteGetResultV1,
    ServiceStatusParametersV1,
    ServiceStatusResultV1,
)


ModuleCapabilityNameV1 = Literal[
    "dns.resolve",
    "network.ping",
    "tcp.connect",
    "route.get",
    "adapter.list",
    "system.service_status",
]
ModuleCapabilityPlatformV1 = Literal["linux_amd64", "windows_amd64"]
ModuleCapabilityRiskV1 = Literal["safe_read"]
ModuleCapabilityFeatureFlagV1 = Literal[
    "endpoint_network_primitives_enabled",
    "endpoint_read_only_primitives_enabled",
]
ModuleCapabilityPolicyV1 = Literal["network_target_policy", "none"]
ModuleCapabilityParameterTypeV1 = Literal["string", "integer"]


class ModuleCapabilityAuthoringV1(ContractModelV1):
    """Stable public metadata for one fixed recipe-capable primitive."""

    capability: ModuleCapabilityNameV1
    parameter_schema_version: str = Field(strict=True, min_length=1, max_length=128)
    result_schema_version: str = Field(strict=True, min_length=1, max_length=128)
    platforms: list[ModuleCapabilityPlatformV1] = Field(min_length=1, max_length=2)
    minimum_agent_version: str = Field(
        strict=True,
        min_length=5,
        max_length=32,
        pattern=r"^\d+\.\d+\.\d+$",
    )
    risk: ModuleCapabilityRiskV1
    consent_required: Literal[False]
    feature_flag: ModuleCapabilityFeatureFlagV1
    policy: ModuleCapabilityPolicyV1


class ModuleCapabilityCatalogV1(ContractModelV1):
    """Versioned, closed discovery response without an execution surface."""

    schema_version: Literal["module_capability_catalog_v1"]
    capabilities: list[ModuleCapabilityAuthoringV1] = Field(min_length=6, max_length=6)


@dataclass(frozen=True, slots=True)
class ModuleCapabilityDescriptor:
    """Private binding from public metadata to fixed typed DTOs."""

    metadata: ModuleCapabilityAuthoringV1
    parameter_model: type[ContractModelV1]
    result_model: type[ContractModelV1]
    authoring_parameters: Mapping[str, ModuleCapabilityParameterTypeV1]


def _descriptor(
    *,
    capability: ModuleCapabilityNameV1,
    parameter_schema_version: str,
    result_schema_version: str,
    minimum_agent_version: str,
    feature_flag: ModuleCapabilityFeatureFlagV1,
    policy: ModuleCapabilityPolicyV1,
    parameter_model: type[ContractModelV1],
    result_model: type[ContractModelV1],
    authoring_parameters: Mapping[str, ModuleCapabilityParameterTypeV1],
) -> ModuleCapabilityDescriptor:
    return ModuleCapabilityDescriptor(
        metadata=ModuleCapabilityAuthoringV1(
            capability=capability,
            parameter_schema_version=parameter_schema_version,
            result_schema_version=result_schema_version,
            platforms=["linux_amd64", "windows_amd64"],
            minimum_agent_version=minimum_agent_version,
            risk="safe_read",
            consent_required=False,
            feature_flag=feature_flag,
            policy=policy,
        ),
        parameter_model=parameter_model,
        result_model=result_model,
        authoring_parameters=dict(authoring_parameters),
    )


MODULE_CAPABILITY_REGISTRY: Mapping[ModuleCapabilityNameV1, ModuleCapabilityDescriptor] = {
    "dns.resolve": _descriptor(
        capability="dns.resolve",
        parameter_schema_version="dns_resolve_parameters_v1",
        result_schema_version="dns_resolve_result_v1",
        minimum_agent_version="3.2.27",
        feature_flag="endpoint_network_primitives_enabled",
        policy="network_target_policy",
        parameter_model=DnsResolveParametersV1,
        result_model=DnsResolveResultV1,
        authoring_parameters={"target": "string", "family": "string"},
    ),
    "network.ping": _descriptor(
        capability="network.ping",
        parameter_schema_version="network_ping_parameters_v1",
        result_schema_version="network_ping_result_v1",
        minimum_agent_version="3.2.27",
        feature_flag="endpoint_network_primitives_enabled",
        policy="network_target_policy",
        parameter_model=NetworkPingParametersV1,
        result_model=NetworkPingResultV1,
        authoring_parameters={
            "target": "string",
            "count": "integer",
            "timeout_ms": "integer",
        },
    ),
    "tcp.connect": _descriptor(
        capability="tcp.connect",
        parameter_schema_version="tcp_connect_parameters_v1",
        result_schema_version="tcp_connect_result_v1",
        minimum_agent_version="3.2.27",
        feature_flag="endpoint_network_primitives_enabled",
        policy="network_target_policy",
        parameter_model=TcpConnectParametersV1,
        result_model=TcpConnectResultV1,
        authoring_parameters={
            "target": "string",
            "port": "integer",
            "timeout_ms": "integer",
        },
    ),
    "route.get": _descriptor(
        capability="route.get",
        parameter_schema_version="route_get_parameters_v1",
        result_schema_version="route_get_result_v1",
        minimum_agent_version="3.2.29",
        feature_flag="endpoint_read_only_primitives_enabled",
        policy="network_target_policy",
        parameter_model=RouteGetParametersV1,
        result_model=RouteGetResultV1,
        authoring_parameters={
            "target": "string",
            "port": "integer",
            "family": "string",
            "timeout_ms": "integer",
        },
    ),
    "adapter.list": _descriptor(
        capability="adapter.list",
        parameter_schema_version="adapter_list_parameters_v1",
        result_schema_version="adapter_list_result_v1",
        minimum_agent_version="3.2.29",
        feature_flag="endpoint_read_only_primitives_enabled",
        policy="none",
        parameter_model=AdapterListParametersV1,
        result_model=AdapterListResultV1,
        authoring_parameters={},
    ),
    "system.service_status": _descriptor(
        capability="system.service_status",
        parameter_schema_version="service_status_parameters_v1",
        result_schema_version="service_status_result_v1",
        minimum_agent_version="3.2.29",
        feature_flag="endpoint_read_only_primitives_enabled",
        policy="none",
        parameter_model=ServiceStatusParametersV1,
        result_model=ServiceStatusResultV1,
        authoring_parameters={"service_key": "string"},
    ),
}


def module_capability_catalog() -> ModuleCapabilityCatalogV1:
    """Return only the six public descriptors in stable authoring order."""
    return ModuleCapabilityCatalogV1(
        schema_version="module_capability_catalog_v1",
        capabilities=[entry.metadata for entry in MODULE_CAPABILITY_REGISTRY.values()],
    )


def module_capability_descriptor(capability: str) -> ModuleCapabilityDescriptor:
    """Resolve one closed capability without any dynamic import or dispatch."""
    try:
        return MODULE_CAPABILITY_REGISTRY[capability]  # type: ignore[index]
    except KeyError as error:
        raise ValueError("module capability is not catalog-defined") from error


def validate_module_capability_parameters(
    capability: str,
    parameters: Mapping[str, object],
) -> dict[str, object]:
    """Validate one typed payload and strip only the fixed schema discriminator."""
    descriptor = module_capability_descriptor(capability)
    model = descriptor.parameter_model.model_validate(
        {"schema_version": descriptor.metadata.parameter_schema_version, **parameters}
    )
    return model.model_dump(mode="json", exclude={"schema_version"})


def module_capability_gateway_parameter_schema(capability: str) -> dict[str, object]:
    """Build the static WSS parameter schema from one closed DTO binding."""
    descriptor = module_capability_descriptor(capability)
    parameter_schema = descriptor.parameter_model.model_json_schema()
    properties = deepcopy(parameter_schema.get("properties", {}))
    properties.pop("schema_version", None)
    for name, property_schema in properties.items():
        if name == "target" and isinstance(property_schema, dict):
            property_schema["pattern"] = r"^(?![\s\S]*://)[\s\S]*$"
    required = [
        name
        for name in parameter_schema.get("required", [])
        if name != "schema_version"
    ]
    schema: dict[str, object] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = required
    return schema


__all__ = [
    "MODULE_CAPABILITY_REGISTRY",
    "ModuleCapabilityAuthoringV1",
    "ModuleCapabilityCatalogV1",
    "ModuleCapabilityDescriptor",
    "ModuleCapabilityFeatureFlagV1",
    "ModuleCapabilityNameV1",
    "ModuleCapabilityParameterTypeV1",
    "ModuleCapabilityPlatformV1",
    "ModuleCapabilityPolicyV1",
    "module_capability_catalog",
    "module_capability_descriptor",
    "module_capability_gateway_parameter_schema",
    "validate_module_capability_parameters",
]
