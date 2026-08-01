"""Contract checks for transports used by the neutral runtime."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from endpoint_contracts import (
    AgentCommandAckV1,
    AgentHeartbeatV1,
    AgentHelloV1,
    AgentResultV1,
    GatewayHelloV1,
    GatewayInboundV1,
)
from pc_agent.runtime.application import RuntimeApplication, RuntimeDependencies, RuntimeSettings
from pc_agent.runtime.lifecycle import ContinueAfter
from pc_agent.runtime.status import RuntimePhase
from pc_agent.transport.backoff import bounded_exponential_backoff
from pc_agent.transport.base import GatewayTransport


_DEVICE_ID = UUID("00000000-0000-4000-8000-000000000401")
_COMMAND_ID = UUID("00000000-0000-4000-8000-000000000402")


def test_bounded_exponential_backoff_caps_transient_reconnect_delay() -> None:
    """An unbounded reconnect delay could leave an agent unavailable indefinitely."""
    assert [bounded_exponential_backoff(attempt) for attempt in range(8)] == [
        1.0,
        2.0,
        4.0,
        8.0,
        16.0,
        32.0,
        60.0,
        60.0,
    ]


def _hello() -> AgentHelloV1:
    return AgentHelloV1(
        schema_version="agent_hello_v1",
        device_id=_DEVICE_ID,
        agent_instance_id=UUID("00000000-0000-4000-8000-000000000403"),
        agent_version="1.0.0",
        launcher_version="1.0.0",
        platform="linux_amd64",
        boot_id="boot-401",
        capabilities=["context.baseline.collect"],
        last_result_sequence=0,
        last_policy_revision=0,
    )


class _InMemoryGatewayTransport:
    """A transport fake that exercises the public GatewayTransport contract."""

    def __init__(self, events: list[str]) -> None:
        self._events = events

    async def connect(self, hello: AgentHelloV1) -> GatewayHelloV1:
        self._events.append(f"connect:{hello.device_id}")
        return GatewayHelloV1(
            schema_version="gateway_hello_v1",
            session_id=UUID("00000000-0000-4000-8000-000000000404"),
            heartbeat_interval_seconds=30,
            maximum_message_bytes=1024,
            policy_revision=0,
            effective_capabilities=["context.baseline.collect"],
            server_time=datetime(2026, 8, 1, tzinfo=UTC),
        )

    async def receive(self) -> GatewayInboundV1:
        self._events.append("receive")
        return GatewayInboundV1.model_validate(
            {
                "schema_version": "gateway_ws_envelope_v1",
                "sequence": 1,
                "kind": "policy_update",
                "payload": {
                    "schema_version": "policy_update_v1",
                    "policy_revision": 1,
                    "effective_capabilities": ["context.baseline.collect"],
                },
            }
        )

    async def send_ack(self, ack: AgentCommandAckV1) -> None:
        self._events.append(f"ack:{ack.command_id}")

    async def send_result(self, result: AgentResultV1) -> None:
        self._events.append(f"result:{result.command_id}")

    async def send_heartbeat(self, heartbeat: AgentHeartbeatV1) -> None:
        self._events.append(f"heartbeat:{heartbeat.device_id}")

    async def close(self) -> None:
        self._events.append("close")

    async def start(self) -> ContinueAfter | None:
        await self.connect(_hello())
        await self.receive()
        return None


class _Executor:
    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None


@pytest.mark.asyncio
async def test_in_memory_gateway_transport_runs_through_runtime_lifecycle(
    tmp_path,
) -> None:
    """Replacing HTTP pull with a contract fake must retain lifecycle ownership."""
    events: list[str] = []

    def create_transport(*_args: object) -> _InMemoryGatewayTransport:
        return _InMemoryGatewayTransport(events)

    settings = RuntimeSettings(
        data_root=tmp_path / "data",
        install_root=tmp_path / "install",
        ca_file=tmp_path / "endpoint-ca.crt",
        endpoint_origin="https://endpoint.sosnadmin.local",
        transport_mode="gateway_http_pull",
    )
    application = RuntimeApplication(
        settings,
        RuntimeDependencies(
            load_credential=lambda _settings: "c" * 43,
            create_executor=_Executor,
            create_transport=create_transport,
        ),
    )

    transport = _InMemoryGatewayTransport(events)
    assert isinstance(transport, GatewayTransport)
    assert await application.run() == 0
    assert events == [f"connect:{_DEVICE_ID}", "receive", "close"]
    assert application.status.phase is RuntimePhase.STOPPED
