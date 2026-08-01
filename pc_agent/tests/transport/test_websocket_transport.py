from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import aiohttp
import pytest

from endpoint_contracts import (
    AgentCommandAckV1,
    AgentHeartbeatV1,
    AgentHelloV1,
    AgentResultV1,
    GatewayHelloV1,
)


_DEVICE_ID = UUID("00000000-0000-4000-8000-000000000701")
_SESSION_ID = UUID("00000000-0000-4000-8000-000000000702")
_TOKEN = "w" * 43
_ORIGIN = "https://endpoint.sosnadmin.local"
_WSS_URL = "wss://endpoint.sosnadmin.local/agent/v1/connect"


def test_websocket_transport_is_public_gateway_transport() -> None:
    """Removing the package export or a required method must break consumers."""
    from pc_agent.transport import GatewayTransport, WebSocketGatewayTransport

    required = {
        "connect",
        "receive",
        "send_ack",
        "send_result",
        "send_heartbeat",
        "close",
    }
    assert required.issubset(vars(WebSocketGatewayTransport))
    assert isinstance(
        WebSocketGatewayTransport(
            ca_file=Path("endpoint-ca.pem"),
            credential=_TOKEN,
            endpoint_origin=_ORIGIN,
        ),
        GatewayTransport,
    )


def _agent_hello() -> AgentHelloV1:
    return AgentHelloV1(
        schema_version="agent_hello_v1",
        device_id=_DEVICE_ID,
        agent_instance_id=UUID("00000000-0000-4000-8000-000000000703"),
        agent_version="3.1.76",
        launcher_version="3.1.70",
        platform="linux_amd64",
        boot_id="boot-701",
        capabilities=["context.baseline.collect"],
        last_result_sequence=11,
        last_policy_revision=7,
    )


def _gateway_hello_body() -> dict[str, object]:
    return {
        "schema_version": "gateway_ws_envelope_v1",
        "sequence": 0,
        "kind": "gateway_hello",
        "payload": {
            "schema_version": "gateway_hello_v1",
            "session_id": str(_SESSION_ID),
            "heartbeat_interval_seconds": 30,
            "maximum_message_bytes": 65536,
            "policy_revision": 9,
            "effective_capabilities": ["context.baseline.collect"],
            "server_time": "2026-08-02T04:30:00Z",
        },
    }


class _HandshakeSocket:
    def __init__(
        self,
        response: dict[str, object],
        *,
        subsequent: tuple[dict[str, object], ...] = (),
        response_url: str = _WSS_URL,
        history: tuple[object, ...] = (),
    ) -> None:
        self._messages = [
            SimpleNamespace(
                type=aiohttp.WSMsgType.TEXT,
                data=json.dumps(response),
            )
        ] + [
            SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data=json.dumps(item))
            for item in subsequent
        ]
        self.sent: list[dict[str, object]] = []
        self.closed = False
        self._response = SimpleNamespace(history=history, url=response_url)

    async def send_json(self, body: dict[str, object]) -> None:
        self.sent.append(body)

    async def receive(self):
        return self._messages.pop(0)

    async def close(self) -> None:
        self.closed = True


class _HandshakeSession:
    def __init__(self, socket: _HandshakeSocket) -> None:
        self.socket = socket
        self.calls: list[dict[str, object]] = []
        self.closed = False

    async def ws_connect(self, url: str, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return self.socket

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_connect_sends_exact_agent_hello_and_accepts_exact_gateway_hello(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Dropping or rewriting a canonical hello field must break the handshake."""
    from pc_agent.transport import websocket

    ca_file = tmp_path / "endpoint-ca.pem"
    ca_file.write_text("test CA fixture", encoding="ascii")
    tls_context = object()
    connector = object()
    socket = _HandshakeSocket(_gateway_hello_body())
    session = _HandshakeSession(socket)
    observed: dict[str, object] = {}

    def create_context(*, cafile: str):
        observed["cafile"] = cafile
        return tls_context

    def create_connector(**kwargs):
        observed["connector"] = kwargs
        return connector

    def create_session(**kwargs):
        observed["session"] = kwargs
        return session

    monkeypatch.setattr(websocket.ssl, "create_default_context", create_context)
    monkeypatch.setattr(websocket.aiohttp, "TCPConnector", create_connector)
    monkeypatch.setattr(websocket.aiohttp, "ClientSession", create_session)
    transport = websocket.WebSocketGatewayTransport(
        ca_file=ca_file,
        credential=_TOKEN,
        endpoint_origin=_ORIGIN,
    )

    hello = await transport.connect(_agent_hello())

    assert hello == GatewayHelloV1(
        schema_version="gateway_hello_v1",
        session_id=_SESSION_ID,
        heartbeat_interval_seconds=30,
        maximum_message_bytes=65536,
        policy_revision=9,
        effective_capabilities=["context.baseline.collect"],
        server_time=datetime(2026, 8, 2, 4, 30, tzinfo=UTC),
    )
    assert socket.sent == [
        {
            "schema_version": "gateway_ws_envelope_v1",
            "sequence": 0,
            "kind": "agent_hello",
            "payload": {
                "schema_version": "agent_hello_v1",
                "device_id": str(_DEVICE_ID),
                "agent_instance_id": "00000000-0000-4000-8000-000000000703",
                "agent_version": "3.1.76",
                "launcher_version": "3.1.70",
                "platform": "linux_amd64",
                "boot_id": "boot-701",
                "capabilities": ["context.baseline.collect"],
                "last_result_sequence": 11,
                "last_policy_revision": 7,
            },
        }
    ]
    assert observed["cafile"] == str(ca_file)
    assert observed["connector"] == {"ssl": tls_context}
    assert session.calls == [
        {
            "url": _WSS_URL,
            "headers": {"Authorization": f"Bearer {_TOKEN}"},
            "ssl": tls_context,
            "max_msg_size": 1024 * 1024,
        }
    ]


def test_connect_rejects_ip_substitution_for_configured_hostname() -> None:
    """Replacing the configured DNS name with an IP must fail before I/O."""
    from pc_agent.transport.websocket import gateway_websocket_url

    with pytest.raises(ValueError, match="hostname"):
        gateway_websocket_url("https://192.168.100.19")


@pytest.mark.parametrize(
    "invalid_origin",
    [
        "ws://endpoint.sosnadmin.local",
        "wss://endpoint.sosnadmin.local",
        "http://endpoint.sosnadmin.local",
        "https://endpoint.sosnadmin.local/agent/v1/connect",
        "https://endpoint.sosnadmin.local/agent/v1/updates",
        "https://endpoint.sosnadmin.local?artifact=outside",
    ],
)
def test_gateway_url_rejects_non_https_or_route_resource_configuration(
    invalid_origin: str,
) -> None:
    from pc_agent.transport.websocket import gateway_websocket_url

    with pytest.raises(ValueError, match="HTTPS origin"):
        gateway_websocket_url(invalid_origin)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response_url", "history"),
    [
        (
            "wss://other.sosnadmin.local/agent/v1/connect",
            (SimpleNamespace(status=302),),
        ),
        ("wss://192.168.100.19/agent/v1/connect", ()),
        ("wss://endpoint.sosnadmin.local/agent/v1/updates", ()),
        ("wss://artifacts.sosnadmin.local/agent/v1/connect", ()),
    ],
)
async def test_connect_rejects_redirect_ip_api_or_artifact_url_substitution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    response_url: str,
    history: tuple[object, ...],
) -> None:
    """A completed handshake cannot replace the exact configured WSS URL."""
    from pc_agent.transport import websocket

    ca_file = tmp_path / "endpoint-ca.pem"
    ca_file.write_text("test CA fixture", encoding="ascii")
    socket = _HandshakeSocket(
        _gateway_hello_body(), response_url=response_url, history=history
    )
    session = _HandshakeSession(socket)
    monkeypatch.setattr(
        websocket.ssl, "create_default_context", lambda **_kwargs: object()
    )
    monkeypatch.setattr(websocket.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(
        websocket.aiohttp, "ClientSession", lambda **_kwargs: session
    )
    transport = websocket.WebSocketGatewayTransport(
        ca_file=ca_file,
        credential=_TOKEN,
        endpoint_origin=_ORIGIN,
    )

    with pytest.raises(websocket.GatewayTerminalError, match="exact Endpoint"):
        await transport.connect(_agent_hello())

    assert socket.closed
    assert session.closed


@pytest.mark.asyncio
async def test_connected_transport_receives_command_and_sends_canonical_messages(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Wrong message kinds, payloads, or outgoing sequences must be observable."""
    from pc_agent.transport import websocket

    now = datetime(2026, 8, 2, 5, 0, tzinfo=UTC)
    command_id = UUID("00000000-0000-4000-8000-000000000704")
    command = {
        "schema_version": "gateway_ws_envelope_v1",
        "sequence": 17,
        "kind": "command",
        "payload": {
            "schema_version": "agent_command_v1",
            "command_id": str(command_id),
            "device_id": str(_DEVICE_ID),
            "capability": "context.baseline.collect",
            "parameters": {},
            "requested_by_service": "endpoint-gateway",
            "idempotency_key": "gateway-command-704",
            "created_at": "2026-08-02T05:00:00Z",
            "deadline_at": "2026-08-02T05:05:00Z",
            "correlation": {
                "schema_version": "command_correlation_v1",
                "request_id": None,
                "parent_command_id": None,
            },
        },
    }
    socket = _HandshakeSocket(_gateway_hello_body(), subsequent=(command,))
    session = _HandshakeSession(socket)
    monkeypatch.setattr(
        websocket.ssl, "create_default_context", lambda **_kwargs: object()
    )
    monkeypatch.setattr(websocket.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(
        websocket.aiohttp, "ClientSession", lambda **_kwargs: session
    )
    transport = websocket.WebSocketGatewayTransport(
        ca_file=tmp_path / "endpoint-ca.pem",
        credential=_TOKEN,
        endpoint_origin=_ORIGIN,
    )
    await transport.connect(_agent_hello())

    inbound = await transport.receive()
    assert inbound.root.kind == "command"
    assert inbound.root.sequence == 17
    assert inbound.root.payload.command_id == command_id
    assert inbound.root.payload.parameters == {}

    await transport.send_ack(
        AgentCommandAckV1(
            schema_version="agent_command_ack_v1",
            command_id=command_id,
            device_id=_DEVICE_ID,
            status="acknowledged",
            acknowledged_at=now,
        )
    )
    await transport.send_result(
        AgentResultV1(
            schema_version="agent_result_v1",
            command_id=command_id,
            device_id=_DEVICE_ID,
            status="succeeded",
            result_items=[],
            message=None,
            completed_at=now + timedelta(seconds=1),
        )
    )
    await transport.send_heartbeat(
        AgentHeartbeatV1(
            schema_version="agent_heartbeat_v1",
            device_id=_DEVICE_ID,
            platform="linux",
            agent_version="3.1.76",
            reported_at=now + timedelta(seconds=2),
        )
    )

    assert socket.sent[1:] == [
        {
            "schema_version": "gateway_ws_envelope_v1",
            "sequence": 1,
            "kind": "command_ack",
            "payload": {
                "schema_version": "agent_command_ack_v1",
                "command_id": str(command_id),
                "device_id": str(_DEVICE_ID),
                "status": "acknowledged",
                "acknowledged_at": "2026-08-02T05:00:00Z",
                "message": None,
            },
        },
        {
            "schema_version": "gateway_ws_envelope_v1",
            "sequence": 2,
            "kind": "command_result",
            "payload": {
                "schema_version": "agent_result_v1",
                "command_id": str(command_id),
                "device_id": str(_DEVICE_ID),
                "status": "succeeded",
                "result_items": [],
                "message": None,
                "completed_at": "2026-08-02T05:00:01Z",
            },
        },
        {
            "schema_version": "gateway_ws_envelope_v1",
            "sequence": 3,
            "kind": "heartbeat",
            "payload": {
                "schema_version": "agent_heartbeat_v1",
                "device_id": str(_DEVICE_ID),
                "platform": "linux",
                "agent_version": "3.1.76",
                "reported_at": "2026-08-02T05:00:02Z",
            },
        },
    ]


@pytest.mark.asyncio
async def test_successful_wss_hello_runs_https_update_hook_after_handshake(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Moving the update hook before WSS would violate WSS-first migration."""
    from pc_agent.transport import websocket

    socket = _HandshakeSocket(_gateway_hello_body())
    session = _HandshakeSession(socket)
    observed: list[tuple[object, int]] = []

    async def on_connected(hello: GatewayHelloV1) -> None:
        observed.append((hello.session_id, len(socket.sent)))

    monkeypatch.setattr(
        websocket.ssl, "create_default_context", lambda **_kwargs: object()
    )
    monkeypatch.setattr(websocket.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(
        websocket.aiohttp, "ClientSession", lambda **_kwargs: session
    )
    transport = websocket.WebSocketGatewayTransport(
        ca_file=tmp_path / "endpoint-ca.pem",
        credential=_TOKEN,
        endpoint_origin=_ORIGIN,
        on_connected=on_connected,
    )

    await transport.connect(_agent_hello())

    assert observed == [(_SESSION_ID, 1)]


@pytest.mark.asyncio
async def test_preserved_https_update_and_fallback_session_rejects_redirects(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The same-origin HTTPS path must not follow a bearer-bearing redirect."""
    from pc_agent.transport import http_pull
    from pc_agent.transport.base import GatewayTerminalError

    observed: dict[str, object] = {}

    class SessionContext:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

    monkeypatch.setattr(
        http_pull.ssl, "create_default_context", lambda **_kwargs: object()
    )
    monkeypatch.setattr(http_pull.aiohttp, "TCPConnector", lambda **_kwargs: object())

    def create_session(**kwargs):
        observed.update(kwargs)
        return SessionContext()

    monkeypatch.setattr(http_pull.aiohttp, "ClientSession", create_session)
    transport = http_pull.HttpPullGatewayTransport(
        ca_file=tmp_path / "endpoint-ca.pem",
        credential=_TOKEN,
        endpoint_origin=_ORIGIN,
    )
    await transport.connect(_agent_hello())

    trace = observed["trace_configs"][0]
    with pytest.raises(GatewayTerminalError, match="redirect"):
        await trace.on_request_redirect[0](None, None, None)


@pytest.mark.asyncio
async def test_outbound_message_honors_negotiated_gateway_size_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An oversized canonical result must not be written to the WSS socket."""
    from pc_agent.transport import websocket

    gateway_hello = _gateway_hello_body()
    gateway_hello["payload"]["maximum_message_bytes"] = 1024
    socket = _HandshakeSocket(gateway_hello)
    session = _HandshakeSession(socket)
    monkeypatch.setattr(
        websocket.ssl, "create_default_context", lambda **_kwargs: object()
    )
    monkeypatch.setattr(websocket.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(
        websocket.aiohttp, "ClientSession", lambda **_kwargs: session
    )
    transport = websocket.WebSocketGatewayTransport(
        ca_file=tmp_path / "endpoint-ca.pem",
        credential=_TOKEN,
        endpoint_origin=_ORIGIN,
    )
    await transport.connect(_agent_hello())
    oversized = AgentResultV1(
        schema_version="agent_result_v1",
        command_id=UUID("00000000-0000-4000-8000-000000000705"),
        device_id=_DEVICE_ID,
        status="failed",
        result_items=[],
        message="safe-error-" + ("x" * 1500),
        completed_at=datetime(2026, 8, 2, 6, 0, tzinfo=UTC),
    )

    with pytest.raises(websocket.GatewayTerminalError, match="negotiated limit"):
        await transport.send_result(oversized)

    assert len(socket.sent) == 1
