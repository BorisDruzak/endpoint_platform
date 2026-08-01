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
