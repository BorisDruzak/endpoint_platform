"""The Gateway must reject activity when continuous policy is disabled."""

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from endpoint_server.context.models import ContextSnapshot
from endpoint_server.main import create_app

from .conftest import FixedWebSocketPeerApp, GatewayRouteHarness, VALID_TOKEN, agent_hello, seed_device


def test_activity_cannot_enter_context_without_policy_gate(gateway_route_harness: GatewayRouteHarness) -> None:
    provider = gateway_route_harness.provider
    device = asyncio.run(seed_device(provider))
    app = create_app(gateway_route_harness.settings, provider)
    hello = agent_hello(device.id)
    hello["capabilities"] = []
    hello["platform"] = "windows_amd64"
    hello["protocol_features"] = ["endpoint.activity.v1"]
    frame = {
        "schema_version": "gateway_ws_envelope_v1", "kind": "activity_observation",
        "sequence": 1, "payload": {
            "schema_version": "activity_observation_v1", "observation_id": str(uuid4()),
            "observed_at": datetime.now(UTC).isoformat(), "user_login": "user",
            "session_state": "ACTIVE", "idle_seconds": 12,
        },
    }
    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect("/agent/v1/connect", headers={
            "Authorization": f"Bearer {VALID_TOKEN}",
            "X-Forwarded-For": "192.168.101.20", "X-Forwarded-Proto": "https",
        }) as websocket:
            websocket.send_json({"schema_version": "gateway_ws_envelope_v1",
                                 "kind": "agent_hello", "sequence": 0, "payload": hello})
            assert websocket.receive_json()["kind"] == "gateway_hello"
            websocket.send_json(frame)
            assert websocket.receive_json()["payload"]["code"] == "activity_disabled"

    async def count() -> int:
        async with provider() as session:
            return await session.scalar(select(func.count()).select_from(ContextSnapshot))

    assert asyncio.run(count()) == 0
