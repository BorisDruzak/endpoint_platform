"""Transport contract shared by HTTP-pull and future Gateway WSS adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .protocol import (
    AgentCommandAckV1,
    AgentHeartbeatV1,
    AgentHelloV1,
    AgentResultV1,
    GatewayHelloV1,
    GatewayInboundV1,
)


class GatewayCredentialRejected(RuntimeError):
    """A device credential was denied and must not retry in-process."""


class GatewayRetryableError(RuntimeError):
    """A transient transport failure that permits a lifecycle reconnect."""


class GatewayTerminalError(RuntimeError):
    """A transport failure that must stop the runtime."""


@dataclass(frozen=True, slots=True)
class GatewayIdle(RuntimeError):
    """A successful transport attempt has no inbound work until a later poll."""

    delay: float

    def __post_init__(self) -> None:
        if self.delay < 0:
            raise ValueError("gateway idle delay must not be negative")


@runtime_checkable
class GatewayTransport(Protocol):
    """A connected Endpoint Gateway message transport."""

    async def connect(self, hello: AgentHelloV1) -> GatewayHelloV1: ...

    async def receive(self) -> GatewayInboundV1: ...

    async def send_ack(self, ack: AgentCommandAckV1) -> None: ...

    async def send_result(self, result: AgentResultV1) -> None: ...

    async def send_heartbeat(self, heartbeat: AgentHeartbeatV1) -> None: ...

    async def close(self) -> None: ...
