from __future__ import annotations

import json
from uuid import uuid4

import pytest

from endpoint_server.gateway.connection_registry import (
    ConnectionRegistry,
    GatewayConnection,
    RegistryCapacityExceeded,
)
from endpoint_server.gateway.protocol import GatewayProtocolError, parse_agent_envelope
from endpoint_server.gateway.ws_routes import assert_single_gateway_worker
from endpoint_server.main import create_app

from .conftest import agent_hello, gateway_settings
from .test_ws_reconnect import RecordingSocket


def _hello_envelope() -> dict[str, object]:
    return {
        "schema_version": "gateway_ws_envelope_v1",
        "kind": "agent_hello",
        "sequence": 0,
        "payload": agent_hello(uuid4()),
    }


def test_protocol_rejects_message_larger_than_configured_byte_limit() -> None:
    raw = json.dumps(_hello_envelope()).encode("utf-8")

    with pytest.raises(GatewayProtocolError) as rejected:
        parse_agent_envelope(raw, maximum_message_bytes=len(raw) - 1)

    assert rejected.value.close_code == 1009


@pytest.mark.parametrize(
    "mutation",
    (
        {"kind": "command"},
        {"unexpected": "field"},
        {"sequence": -1},
    ),
)
def test_protocol_rejects_server_messages_unknown_fields_and_negative_sequences(
    mutation: dict[str, object],
) -> None:
    body = _hello_envelope()
    body.update(mutation)

    with pytest.raises(GatewayProtocolError) as rejected:
        parse_agent_envelope(json.dumps(body), maximum_message_bytes=65536)

    assert rejected.value.close_code == 1008


@pytest.mark.asyncio
async def test_process_local_registry_has_a_hard_capacity() -> None:
    registry = ConnectionRegistry(max_connections=1)
    first = GatewayConnection(uuid4(), uuid4(), RecordingSocket())
    second = GatewayConnection(uuid4(), uuid4(), RecordingSocket())
    await registry.register(first)

    with pytest.raises(RegistryCapacityExceeded):
        await registry.register(second)

    assert registry.connection_count == 1


@pytest.mark.parametrize(
    "environment",
    (
        {"WEB_CONCURRENCY": "2"},
        {"UVICORN_WORKERS": "4"},
        {"ENDPOINT_API_WORKERS": "0"},
        {"ENDPOINT_API_WORKERS": "not-an-integer"},
    ),
)
def test_startup_guard_rejects_unsupported_worker_configuration(
    environment: dict[str, str],
) -> None:
    with pytest.raises(RuntimeError, match="exactly one API worker"):
        assert_single_gateway_worker(environment)


def test_startup_guard_accepts_single_worker() -> None:
    assert_single_gateway_worker({"ENDPOINT_API_WORKERS": "1"})


@pytest.mark.asyncio
async def test_lifespan_rejects_a_second_worker_for_the_same_deployment(
    session_provider,
    tmp_path,
) -> None:
    artifact_root = tmp_path / "single-worker-artifacts"
    artifact_root.mkdir()
    settings = gateway_settings(artifact_root=artifact_root)
    first = create_app(settings, session_provider)
    second = create_app(settings, session_provider)

    async with first.router.lifespan_context(first):
        with pytest.raises(RuntimeError, match="exactly one API worker"):
            async with second.router.lifespan_context(second):
                pytest.fail("a second process-local registry became active")


@pytest.mark.asyncio
@pytest.mark.parametrize("blocked", ["send", "close", "lock"])
async def test_replacement_finishes_when_previous_socket_stalls(monkeypatch, caplog, blocked):
    import asyncio

    from endpoint_server.gateway import connection_registry as registry_module

    monkeypatch.setattr(registry_module, "_NOTICE_TIMEOUT_SECONDS", 0.02, raising=False)
    monkeypatch.setattr(registry_module, "_CLOSE_TIMEOUT_SECONDS", 0.02, raising=False)

    class Stalled(RecordingSocket):
        async def send_json(self, message):
            if blocked == "send":
                await asyncio.Future()
            await super().send_json(message)

        async def close(self, code):
            self.closed.append(code)
            if blocked == "close":
                await asyncio.Future()

    registry = ConnectionRegistry()
    socket = Stalled()
    old = GatewayConnection(uuid4(), uuid4(), socket)
    if blocked == "lock":
        await old.send_lock.acquire()
    await registry.register(old)
    replacement = GatewayConnection(old.device_id, uuid4(), RecordingSocket())
    async with asyncio.timeout(0.5):
        assert await registry.register(replacement) is old
    assert await registry.get(old.device_id) is replacement
    assert socket.closed == [4001]
    stage = "close" if blocked == "close" else "notice"
    assert f"reason=session_replaced stage={stage} error=TimeoutError" in caplog.text


@pytest.mark.asyncio
async def test_shutdown_all_dispatches_healthy_sockets_while_first_stalls():
    import asyncio

    healthy_closed = asyncio.Event()

    class Stalled(RecordingSocket):
        async def close(self, code):
            await healthy_closed.wait()

    class Healthy(RecordingSocket):
        async def close(self, code):
            await super().close(code)
            healthy_closed.set()

    registry = ConnectionRegistry()
    healthy = Healthy()
    await registry.register(GatewayConnection(uuid4(), uuid4(), Stalled()))
    await registry.register(GatewayConnection(uuid4(), uuid4(), healthy))
    async with asyncio.timeout(0.5):
        await registry.shutdown_all()
    assert healthy.closed == [1001]
    assert registry.connection_count == 0
