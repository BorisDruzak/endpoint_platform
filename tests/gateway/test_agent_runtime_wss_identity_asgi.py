"""Headless runtime identity acceptance through the real Gateway ASGI route."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import aiohttp
import certifi
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from endpoint_server.main import create_app
from pc_agent import endpoint_gateway
from pc_agent.enrollment_identity import (
    ENROLLMENT_IDENTITY_FILENAME,
    serialize_enrollment_identity,
)
from pc_agent.runtime import application as runtime_application
from pc_agent.runtime.application import RuntimeApplication, RuntimeSettings
from pc_agent.runtime.status import RuntimePhase
from pc_agent.version import AGENT_VERSION

from .conftest import (
    FixedWebSocketPeerApp,
    GatewayRouteHarness,
    seed_device,
)


_RUNTIME_DEVICE_TOKEN = "w" * 43


class _AsgiWebSocket:
    """Minimal aiohttp socket facade backed by Starlette's in-process client."""

    def __init__(self, client: TestClient, headers: dict[str, str]) -> None:
        self._context = client.websocket_connect("/agent/v1/connect", headers=headers)
        self._websocket = self._context.__enter__()
        self._received_gateway_hello = False
        self.sent_envelopes: list[dict[str, object]] = []
        self.gateway_hello_received = False
        self.close_code: int | None = None
        self._response = SimpleNamespace(
            history=(),
            url="wss://endpoint.sosnadmin.local/agent/v1/connect",
        )

    async def send_json(self, payload: dict[str, object]) -> None:
        self.sent_envelopes.append(payload)
        self._websocket.send_json(payload)

    async def receive(self) -> SimpleNamespace:
        if self._received_gateway_hello:
            # Let the lifecycle finish its connected-loop cancellation path without
            # inventing a gateway message outside the real route.
            raise asyncio.CancelledError()
        try:
            payload = self._websocket.receive_json()
        except WebSocketDisconnect as error:
            self.close_code = error.code
            return SimpleNamespace(type=aiohttp.WSMsgType.CLOSE, data=error.code)
        self._received_gateway_hello = True
        self.gateway_hello_received = payload.get("kind") == "gateway_hello"
        return SimpleNamespace(
            type=aiohttp.WSMsgType.TEXT,
            data=json.dumps(payload),
        )

    async def close(self) -> None:
        context = self._context
        self._context = None
        if context is not None:
            context.__exit__(None, None, None)


class _AsgiClientSession:
    """Minimal ClientSession facade preserving the production WSS transport path."""

    def __init__(self, client: TestClient) -> None:
        self._client = client
        self.sockets: list[_AsgiWebSocket] = []

    async def ws_connect(
        self,
        url: str,
        *,
        headers: dict[str, str],
        **_kwargs: object,
    ) -> _AsgiWebSocket:
        assert url == "wss://endpoint.sosnadmin.local/agent/v1/connect"
        request_headers = {
            **headers,
            "X-Forwarded-For": "192.168.101.20",
            "X-Forwarded-Proto": "https",
        }
        socket = _AsgiWebSocket(self._client, request_headers)
        self.sockets.append(socket)
        return socket

    async def close(self) -> None:
        for socket in self.sockets:
            await socket.close()


def _settings(
    tmp_path: Path,
    *,
    migration_http_pull_fallback: bool = False,
) -> RuntimeSettings:
    data_root = tmp_path / "agent-data"
    data_root.mkdir()
    install_root = tmp_path / "agent-install"
    install_root.mkdir()
    (data_root / "device-credential").write_text(
        _RUNTIME_DEVICE_TOKEN,
        encoding="ascii",
    )
    return RuntimeSettings(
        data_root=data_root,
        install_root=install_root,
        ca_file=Path(certifi.where()),
        endpoint_origin="https://endpoint.sosnadmin.local",
        transport_mode="gateway_wss",
        migration_http_pull_fallback=migration_http_pull_fallback,
    )


@pytest.mark.asyncio
async def test_default_runtime_wss_accepts_persisted_authoritative_device_id(
    gateway_route_harness: GatewayRouteHarness,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The default app must send the credential-bound enrollment Device.id to Task6."""
    device = await seed_device(
        gateway_route_harness.provider,
        token=_RUNTIME_DEVICE_TOKEN,
    )
    settings = _settings(tmp_path)
    identity_path = settings.data_root / ENROLLMENT_IDENTITY_FILENAME
    identity_path.write_bytes(serialize_enrollment_identity(device.id))
    bridge: _AsgiClientSession
    updates: list[object] = []

    async def skip_update_poll(gateway_hello: object) -> None:
        updates.append(gateway_hello)

    def no_http_pull(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("WSS acceptance must not construct an HTTP pull fallback")

    app = create_app(gateway_route_harness.settings, gateway_route_harness.provider)
    with TestClient(FixedWebSocketPeerApp(app)) as client:
        bridge = _AsgiClientSession(client)
        monkeypatch.setattr(
            "pc_agent.transport.websocket.aiohttp.ClientSession",
            lambda **_kwargs: bridge,
        )
        monkeypatch.setattr(
            runtime_application,
            "_https_update_hook",
            lambda *_args, **_kwargs: skip_update_poll,
        )
        monkeypatch.setattr(
            endpoint_gateway,
            "create_http_pull_transport",
            no_http_pull,
        )

        assert await RuntimeApplication(settings).run() == 0

    assert len(bridge.sockets) == 1
    socket = bridge.sockets[0]
    assert socket.gateway_hello_received
    assert updates
    assert socket.sent_envelopes[0]["kind"] == "agent_hello"
    payload = socket.sent_envelopes[0]["payload"]
    assert isinstance(payload, dict)
    assert UUID(str(payload["device_id"])) == device.id
    assert device.id != UUID(int=0)
    assert payload["agent_version"] == AGENT_VERSION
    assert payload["launcher_version"] == AGENT_VERSION


@pytest.mark.asyncio
async def test_default_runtime_wss_rejects_a_non_authoritative_identity_for_valid_bearer(
    gateway_route_harness: GatewayRouteHarness,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The Task6 route must reject any valid UUID not bound to the bearer."""
    await seed_device(gateway_route_harness.provider, token=_RUNTIME_DEVICE_TOKEN)
    settings = _settings(tmp_path)
    non_authoritative_id = UUID("00000000-0000-4000-8000-000000000437")
    (settings.data_root / ENROLLMENT_IDENTITY_FILENAME).write_bytes(
        serialize_enrollment_identity(non_authoritative_id)
    )

    async def skip_update_poll(_gateway_hello: object) -> None:
        return None

    app = create_app(gateway_route_harness.settings, gateway_route_harness.provider)
    with TestClient(FixedWebSocketPeerApp(app)) as client:
        bridge = _AsgiClientSession(client)
        monkeypatch.setattr(
            "pc_agent.transport.websocket.aiohttp.ClientSession",
            lambda **_kwargs: bridge,
        )
        monkeypatch.setattr(
            runtime_application,
            "_https_update_hook",
            lambda *_args, **_kwargs: skip_update_poll,
        )

        application = RuntimeApplication(settings)
        assert await application.run() == 1

    socket = bridge.sockets[0]
    assert not socket.gateway_hello_received
    assert socket.close_code == 4403
    payload = socket.sent_envelopes[0]["payload"]
    assert isinstance(payload, dict)
    assert UUID(str(payload["device_id"])) == non_authoritative_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "identity_payload",
    [
        None,
        b"not valid enrollment json",
        (
            b'{"device_id":"00000000-0000-0000-0000-000000000000",'
            b'"schema_version":"endpoint_enrollment_identity_v1"}'
        ),
    ],
)
async def test_default_runtime_identity_failure_is_terminal_before_wss_or_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    identity_payload: bytes | None,
) -> None:
    """Missing or corrupt enrollment identity must not synthesize a WSS or pull path."""
    settings = _settings(tmp_path, migration_http_pull_fallback=True)
    if identity_payload is not None:
        (settings.data_root / ENROLLMENT_IDENTITY_FILENAME).write_bytes(
            identity_payload
        )
    # An unrelated local identity cannot become a bearer-bound server identity.
    (settings.data_root / "identity.json").write_text(
        '{"machine_id":"00000000-0000-4000-8000-000000000001"}',
        encoding="utf-8",
    )
    constructed: list[str] = []

    def wss_forbidden(**_kwargs: object) -> object:
        constructed.append("wss")
        raise AssertionError("missing enrollment identity reached WSS construction")

    def pull_forbidden(*_args: object, **_kwargs: object) -> object:
        constructed.append("http-pull")
        raise AssertionError("missing enrollment identity reached HTTP pull fallback")

    monkeypatch.setattr(runtime_application, "WebSocketGatewayTransport", wss_forbidden)
    monkeypatch.setattr(
        endpoint_gateway,
        "create_http_pull_transport",
        pull_forbidden,
    )

    application = RuntimeApplication(settings)
    assert await application.run() == 1
    assert application.status.phase is RuntimePhase.FAILED
    assert application.status.last_error == "EnrollmentIdentityError"
    assert constructed == []
