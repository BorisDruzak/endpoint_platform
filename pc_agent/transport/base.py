"""Transport contract shared by HTTP-pull and future Gateway WSS adapters."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .protocol import (
    AgentCommandAckV1,
    AgentHeartbeatV1,
    AgentHelloV1,
    AgentResultV1,
    GatewayHelloV1,
    GatewayInboundV1,
)


@runtime_checkable
class GatewayTransport(Protocol):
    """A connected Endpoint Gateway message transport."""

    async def connect(self, hello: AgentHelloV1) -> GatewayHelloV1: ...

    async def receive(self) -> GatewayInboundV1: ...

    async def send_ack(self, ack: AgentCommandAckV1) -> None: ...

    async def send_result(self, result: AgentResultV1) -> None: ...

    async def send_heartbeat(self, heartbeat: AgentHeartbeatV1) -> None: ...

    async def close(self) -> None: ...
