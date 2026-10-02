from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from starlette.websockets import WebSocketDisconnect

from endpoint_server.db.models import DeviceSession
from endpoint_server.main import create_app
from .conftest import FixedWebSocketPeerApp, seed_device
from .test_ws_route_asgi import _headers, _hello_envelope


@pytest.mark.parametrize("features", [[], ["endpoint.recovery-update.v2"]])
def test_minimum_version_rejects_before_online_presence(gateway_route_harness, features):
    provider = gateway_route_harness.provider
    device = asyncio.run(seed_device(provider))
    settings = replace(gateway_route_harness.settings,
        gateway_minimum_agent_versions=((str(device.id), "3.2.80"),))
    app = create_app(settings, provider)
    hello = _hello_envelope(device.id, ["agent.status.read"])
    hello["payload"]["agent_version"] = "3.2.79"
    hello["payload"]["protocol_features"] = features
    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect("/agent/v1/connect", headers=_headers()) as socket:
            socket.send_json(hello)
            if features:
                error = socket.receive_json()
                assert error["kind"] == "error"
                assert error["payload"]["code"] == "agent_upgrade_required"
            with pytest.raises(WebSocketDisconnect) as closed:
                socket.receive_json()
            assert closed.value.code == 1002
    async def sessions():
        async with provider() as session:
            return await session.scalar(select(func.count()).select_from(DeviceSession))
    assert asyncio.run(sessions()) == 0


def test_minimum_version_is_scoped_to_explicit_device(gateway_route_harness):
    provider = gateway_route_harness.provider
    device = asyncio.run(seed_device(provider))
    settings = replace(gateway_route_harness.settings,
        gateway_minimum_agent_versions=(("00000000-0000-4000-8000-000000000001", "9.9.9"),))
    app = create_app(settings, provider)
    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect("/agent/v1/connect", headers=_headers()) as socket:
            socket.send_json(_hello_envelope(device.id, ["agent.status.read"]))
            assert socket.receive_json()["kind"] == "gateway_hello"
