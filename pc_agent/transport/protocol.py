"""Canonical Gateway protocol values consumed by agent transports."""

from endpoint_contracts import (
    AgentCommandAckV1,
    AgentHeartbeatV1,
    AgentHelloV1,
    AgentResultV1,
    GatewayHelloV1,
    GatewayInboundV1,
)
from endpoint_contracts.capabilities import MODULE_CAPABILITY_REGISTRY


def compatibility_agent_hello(platform: str = "linux_amd64") -> AgentHelloV1:
    """Create the local-only hello required by HTTP pull's shared interface."""
    from uuid import UUID

    return AgentHelloV1(
        schema_version="agent_hello_v1",
        device_id=UUID(int=0),
        agent_instance_id=UUID(int=0),
        agent_version="http-pull",
        launcher_version="http-pull",
        platform=platform,
        boot_id="http-pull",
        capabilities=[
            "context.baseline.collect",
            "context.diagnostic.collect",
            "context.health.collect",
            "context.network.collect",
            "context.session.collect",
            "context.inventory.collect",
            *(
                name for name, descriptor in MODULE_CAPABILITY_REGISTRY.items()
                if platform in descriptor.metadata.platforms
            ),
        ],
        last_result_sequence=0,
        last_policy_revision=0,
    )

__all__ = [
    "AgentCommandAckV1",
    "AgentHeartbeatV1",
    "AgentHelloV1",
    "AgentResultV1",
    "GatewayHelloV1",
    "GatewayInboundV1",
    "compatibility_agent_hello",
]
