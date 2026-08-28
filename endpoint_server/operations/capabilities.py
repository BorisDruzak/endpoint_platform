"""Closed capability mapping for Endpoint Operation v1."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TypedDict

from endpoint_server.config import Settings
from endpoint_server.gateway.connection_registry import GatewayConnection


CAPABILITY_PROFILES = {"context.diagnostic.collect": "diagnostic_v1"}
SUPPORTED_CAPABILITIES = frozenset(CAPABILITY_PROFILES)
NETWORK_PRIMITIVE_CAPABILITIES = frozenset(
    {"dns.resolve", "network.ping", "tcp.connect"}
)
READ_ONLY_PRIMITIVE_CAPABILITIES = frozenset(
    {"route.get", "adapter.list", "system.service_status"}
)
_MINIMUM_NETWORK_PRIMITIVE_AGENT_VERSION = (3, 2, 27)
_MINIMUM_READ_ONLY_PRIMITIVE_AGENT_VERSION = (3, 2, 29)
_RELEASE_VERSION_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


class CapabilityAvailability(TypedDict):
    capability: str
    available: bool
    transport: str
    risk: str
    consent_required: bool
    parameter_schema_version: str


_BASELINE_CAPABILITIES: tuple[CapabilityAvailability, ...] = (
    {
        "capability": "context.diagnostic.collect",
        "available": True,
        "transport": "gateway_wss",
        "risk": "read_only",
        "consent_required": False,
        "parameter_schema_version": "diagnostic_collection_parameters_v1",
    },
)
_NETWORK_CAPABILITY_METADATA: Mapping[str, CapabilityAvailability] = {
    "dns.resolve": {
        "capability": "dns.resolve",
        "available": True,
        "transport": "gateway_wss",
        "risk": "safe_read",
        "consent_required": False,
        "parameter_schema_version": "dns_resolve_parameters_v1",
    },
    "network.ping": {
        "capability": "network.ping",
        "available": True,
        "transport": "gateway_wss",
        "risk": "safe_read",
        "consent_required": False,
        "parameter_schema_version": "network_ping_parameters_v1",
    },
    "tcp.connect": {
        "capability": "tcp.connect",
        "available": True,
        "transport": "gateway_wss",
        "risk": "safe_read",
        "consent_required": False,
        "parameter_schema_version": "tcp_connect_parameters_v1",
    },
}
_READ_ONLY_CAPABILITY_METADATA: Mapping[str, CapabilityAvailability] = {
    "route.get": {
        "capability": "route.get",
        "available": True,
        "transport": "gateway_wss",
        "risk": "safe_read",
        "consent_required": False,
        "parameter_schema_version": "route_get_parameters_v1",
    },
    "adapter.list": {
        "capability": "adapter.list",
        "available": True,
        "transport": "gateway_wss",
        "risk": "safe_read",
        "consent_required": False,
        "parameter_schema_version": "adapter_list_parameters_v1",
    },
    "system.service_status": {
        "capability": "system.service_status",
        "available": True,
        "transport": "gateway_wss",
        "risk": "safe_read",
        "consent_required": False,
        "parameter_schema_version": "system_service_status_parameters_v1",
    },
}


class UnsupportedOperationCapability(ValueError):
    """The request is outside the closed Endpoint Operation v1 allowlist."""


def network_primitives_enabled(settings: Settings) -> bool:
    """Require both the closed feature flag and a concrete target boundary."""
    return settings.endpoint_network_primitives_enabled and bool(
        settings.endpoint_network_probe_allowed_cidrs
        or settings.endpoint_network_probe_allowed_suffixes
    )


def _has_minimum_network_primitive_version(agent_version: str) -> bool:
    match = _RELEASE_VERSION_PATTERN.fullmatch(agent_version)
    if match is None:
        return False
    return tuple(int(part) for part in match.groups()) >= _MINIMUM_NETWORK_PRIMITIVE_AGENT_VERSION


def _has_minimum_read_only_primitive_version(agent_version: str) -> bool:
    match = _RELEASE_VERSION_PATTERN.fullmatch(agent_version)
    if match is None:
        return False
    return tuple(int(part) for part in match.groups()) >= _MINIMUM_READ_ONLY_PRIMITIVE_AGENT_VERSION


def project_available_capabilities(
    settings: Settings,
    connection: GatewayConnection | None,
) -> list[CapabilityAvailability]:
    """Expose safe availability only for an active compatible typed agent."""
    projected = list(_BASELINE_CAPABILITIES)
    if connection is None or connection.platform not in {"linux_amd64", "windows_amd64"}:
        return projected
    if network_primitives_enabled(settings) and _has_minimum_network_primitive_version(
        connection.agent_version
    ):
        for capability in sorted(
            NETWORK_PRIMITIVE_CAPABILITIES & connection.effective_capabilities
        ):
            projected.append(_NETWORK_CAPABILITY_METADATA[capability])
    if settings.endpoint_read_only_primitives_enabled and _has_minimum_read_only_primitive_version(
        connection.agent_version
    ):
        for capability in sorted(
            READ_ONLY_PRIMITIVE_CAPABILITIES & connection.effective_capabilities
        ):
            if capability == "route.get" and not (
                settings.endpoint_network_probe_allowed_cidrs
                or settings.endpoint_network_probe_allowed_suffixes
            ):
                continue
            projected.append(_READ_ONLY_CAPABILITY_METADATA[capability])
    return projected


def profile_for_capability(capability: str) -> str:
    try:
        return CAPABILITY_PROFILES[capability]
    except KeyError as error:
        raise UnsupportedOperationCapability(
            "unsupported endpoint operation capability"
        ) from error


__all__ = [
    "CAPABILITY_PROFILES",
    "NETWORK_PRIMITIVE_CAPABILITIES",
    "READ_ONLY_PRIMITIVE_CAPABILITIES",
    "SUPPORTED_CAPABILITIES",
    "UnsupportedOperationCapability",
    "network_primitives_enabled",
    "profile_for_capability",
    "project_available_capabilities",
]
