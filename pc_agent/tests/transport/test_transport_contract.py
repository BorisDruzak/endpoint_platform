"""Contract checks for transports used by the neutral runtime."""

from __future__ import annotations

import asyncio
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
from pc_agent.runtime import application as runtime_application
from pc_agent.runtime.application import RuntimeApplication, RuntimeDependencies, RuntimeSettings
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
    assert bounded_exponential_backoff(1024) == 60.0


def test_runtime_settings_reject_unknown_or_legacy_transport_mode(tmp_path) -> None:
    """A legacy Helpdesk setting must not become a silent transport fallback."""
    ca_file = tmp_path / "endpoint-ca.crt"
    ca_file.write_text("test CA", encoding="ascii")
    settings = RuntimeSettings(
        data_root=tmp_path / "data",
        install_root=tmp_path / "install",
        ca_file=ca_file,
        endpoint_origin="https://endpoint.sosnadmin.local",
        transport_mode="helpdesk_websocket",  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="unsupported Endpoint transport mode"):
        settings.validate()


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
        self._events.append("connect")
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
        if getattr(self, "_completed", False):
            raise asyncio.CancelledError()
        return GatewayInboundV1.model_validate(
            {
                "schema_version": "gateway_ws_envelope_v1",
                "sequence": 1,
                "kind": "command",
                "payload": {
                    "schema_version": "agent_command_v1",
                    "command_id": str(_COMMAND_ID),
                    "device_id": str(_DEVICE_ID),
                    "capability": "context.baseline.collect",
                    "parameters": {},
                    "requested_by_service": "transport-test",
                    "idempotency_key": "transport-command-402",
                    "created_at": "2026-08-01T00:00:00+00:00",
                    "deadline_at": "2026-08-01T00:01:00+00:00",
                },
            }
        )

    async def send_ack(self, ack: AgentCommandAckV1) -> None:
        self._events.append(f"ack:{ack.command_id}")

    async def send_result(self, result: AgentResultV1) -> None:
        self._events.append(f"result:{result.command_id}")
        self._completed = True

    async def send_heartbeat(self, heartbeat: AgentHeartbeatV1) -> None:
        self._events.append(f"heartbeat:{heartbeat.device_id}")

    async def close(self) -> None:
        self._events.append("close")


class _Executor:
    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def execute(self, command) -> AgentResultV1:
        return AgentResultV1(
            schema_version="agent_result_v1",
            command_id=command.command_id,
            device_id=command.device_id,
            status="succeeded",
            completed_at=datetime(2026, 8, 1, tzinfo=UTC),
        )


@pytest.mark.asyncio
async def test_in_memory_gateway_transport_runs_through_runtime_lifecycle(
    tmp_path,
) -> None:
    """Replacing HTTP pull with a contract fake must retain lifecycle ownership."""
    events: list[str] = []

    selected = _InMemoryGatewayTransport(events)

    def create_transport(*_args: object) -> _InMemoryGatewayTransport:
        return selected

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
    assert events == [
        "connect",
        "receive",
        f"ack:{_COMMAND_ID}",
        f"result:{_COMMAND_ID}",
        "close",
        "connect",
        "receive",
        "close",
    ]
    assert application.status.phase is RuntimePhase.STOPPED


@pytest.mark.asyncio
async def test_default_selection_drives_http_pull_gateway_contract_through_lifecycle(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Default HTTP selection must not bypass GatewayTransport with start()."""
    events: list[str] = []
    selected = _InMemoryGatewayTransport(events)
    settings = RuntimeSettings(
        data_root=tmp_path / "data",
        install_root=tmp_path / "install",
        ca_file=tmp_path / "endpoint-ca.crt",
        endpoint_origin="https://endpoint.sosnadmin.local",
        transport_mode="gateway_http_pull",
    )
    defaults = runtime_application._default_dependencies()
    monkeypatch.setattr(
        runtime_application,
        "_create_http_pull_transport",
        lambda *_args, **_kwargs: selected,
    )
    application = RuntimeApplication(
        settings,
        RuntimeDependencies(
            load_credential=lambda _settings: "c" * 43,
            create_executor=_Executor,
            create_transport=defaults.create_transport,
        ),
    )

    assert await application.run() == 0
    assert events == [
        "connect",
        "receive",
        f"ack:{_COMMAND_ID}",
        f"result:{_COMMAND_ID}",
        "close",
        "connect",
        "receive",
        "close",
    ]


@pytest.mark.asyncio
async def test_gateway_wss_selection_fails_closed_without_http_pull_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Selecting pending WSS must not invoke the current HTTP transport."""
    settings = RuntimeSettings(
        data_root=tmp_path / "data",
        install_root=tmp_path / "install",
        ca_file=tmp_path / "endpoint-ca.crt",
        endpoint_origin="https://endpoint.sosnadmin.local",
        transport_mode="gateway_wss",
    )
    defaults = runtime_application._default_dependencies()

    def unexpected_http(*_args, **_kwargs):
        raise AssertionError("WSS selection fell back to HTTP pull")

    monkeypatch.setattr(runtime_application, "_create_http_pull_transport", unexpected_http)
    application = RuntimeApplication(
        settings,
        RuntimeDependencies(
            load_credential=lambda _settings: "c" * 43,
            create_executor=_Executor,
            create_transport=defaults.create_transport,
        ),
    )

    assert await application.run() == 1
    assert application.status.phase is RuntimePhase.FAILED
