"""Closed capability mapping for Endpoint Operation v1."""

from __future__ import annotations

import re
from typing import TypedDict

from endpoint_contracts.capabilities import (
    MODULE_CAPABILITY_REGISTRY,
    ModuleCapabilityDescriptor,
)
from endpoint_server.config import Settings
from endpoint_server.gateway.connection_registry import GatewayConnection


CAPABILITY_PROFILES = {"context.diagnostic.collect": "diagnostic_v1"}
SUPPORTED_CAPABILITIES = frozenset(CAPABILITY_PROFILES)
NETWORK_PRIMITIVE_CAPABILITIES = frozenset(
    capability
    for capability, descriptor in MODULE_CAPABILITY_REGISTRY.items()
    if descriptor.metadata.feature_flag == "endpoint_network_primitives_enabled"
)
READ_ONLY_PRIMITIVE_CAPABILITIES = frozenset(
    capability
    for capability, descriptor in MODULE_CAPABILITY_REGISTRY.items()
    if descriptor.metadata.feature_flag == "endpoint_read_only_primitives_enabled"
)
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


class UnsupportedOperationCapability(ValueError):
    """The request is outside the closed Endpoint Operation v1 allowlist."""


def network_primitives_enabled(settings: Settings) -> bool:
    """Require both the closed feature flag and a concrete target boundary."""
    return settings.endpoint_network_primitives_enabled and bool(
        settings.endpoint_network_probe_allowed_cidrs
        or settings.endpoint_network_probe_allowed_suffixes
    )


def _has_minimum_agent_version(agent_version: str, minimum: str) -> bool:
    reported = _RELEASE_VERSION_PATTERN.fullmatch(agent_version)
    required = _RELEASE_VERSION_PATTERN.fullmatch(minimum)
    if reported is None or required is None:
        return False
    return tuple(int(part) for part in reported.groups()) >= tuple(
        int(part) for part in required.groups()
    )


def module_capability_is_compatible(
    settings: Settings,
    descriptor: ModuleCapabilityDescriptor,
    *,
    agent_version: str,
    platform: str,
) -> bool:
    """Apply only registry-declared flag, policy, platform, and version gates."""
    metadata = descriptor.metadata
    if platform not in metadata.platforms:
        return False
    if not getattr(settings, metadata.feature_flag):
        return False
    if metadata.policy == "network_target_policy" and not (
        settings.endpoint_network_probe_allowed_cidrs
        or settings.endpoint_network_probe_allowed_suffixes
    ):
        return False
    return _has_minimum_agent_version(agent_version, metadata.minimum_agent_version)


def compatible_module_capabilities(
    settings: Settings,
    connection: GatewayConnection | None,
) -> tuple[str, ...]:
    """Return the fixed primitive names usable by this connected agent only."""
    if connection is None:
        return ()
    return tuple(
        capability
        for capability, descriptor in MODULE_CAPABILITY_REGISTRY.items()
        if capability in connection.effective_capabilities
        and module_capability_is_compatible(
            settings,
            descriptor,
            agent_version=connection.agent_version,
            platform=connection.platform,
        )
    )


def _availability(descriptor: ModuleCapabilityDescriptor) -> CapabilityAvailability:
    metadata = descriptor.metadata
    return {
        "capability": metadata.capability,
        "available": True,
        "transport": "gateway_wss",
        "risk": metadata.risk,
        "consent_required": metadata.consent_required,
        "parameter_schema_version": metadata.parameter_schema_version,
    }


def project_available_capabilities(
    settings: Settings,
    connection: GatewayConnection | None,
) -> list[CapabilityAvailability]:
    """Expose safe availability only for an active compatible typed agent."""
    projected = list(_BASELINE_CAPABILITIES)
    if connection is None:
        return projected
    for capability in compatible_module_capabilities(settings, connection):
        projected.append(_availability(MODULE_CAPABILITY_REGISTRY[capability]))
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
    "compatible_module_capabilities",
    "module_capability_is_compatible",
    "network_primitives_enabled",
    "profile_for_capability",
    "project_available_capabilities",
]
