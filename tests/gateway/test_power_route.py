import asyncio
from datetime import UTC, datetime
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from endpoint_server.main import create_app
from endpoint_server.power.models import PowerSourceState
from .conftest import FixedWebSocketPeerApp, VALID_TOKEN, agent_hello, seed_device


@pytest.mark.parametrize("negotiated", [True, False])
def test_power_is_policy_independent_and_negotiated(gateway_route_harness, negotiated):
    harness = gateway_route_harness
    device = asyncio.run(seed_device(harness.provider))

    async def prepare():
        async with harness.engine.begin() as connection:
            await connection.run_sync(
                lambda sync: PowerSourceState.__table__.create(sync)
            )

    asyncio.run(prepare())
    hello = agent_hello(device.id)
    hello["capabilities"] = []
    hello["protocol_features"] = ["endpoint.power-events.v1"] if negotiated else []
    app = create_app(harness.settings, harness.provider)
    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect(
            "/agent/v1/connect",
            headers={
                "Authorization": f"Bearer {VALID_TOKEN}",
                "X-Forwarded-For": "192.168.101.20",
                "X-Forwarded-Proto": "https",
            },
        ) as socket:
            socket.send_json(
                dict(
                    schema_version="gateway_ws_envelope_v1",
                    kind="agent_hello",
                    sequence=0,
                    payload=hello,
                )
            )
            greeting = socket.receive_json()
            assert (
                greeting["payload"].get("protocol_features", [])
                == hello["protocol_features"]
            )
            value = dict(
                schema_version="power_event_batch_v1",
                batch_id=str(uuid4()),
                events=[],
                source_status=dict(
                    schema_version="power_source_status_v1",
                    source="systemd-journal",
                    availability="UNAVAILABLE",
                    reported_at=datetime.now(UTC).isoformat(),
                    loss_count=2,
                ),
            )
            socket.send_json(
                dict(
                    schema_version="gateway_ws_envelope_v1",
                    kind="power_event_batch",
                    sequence=1,
                    payload=value,
                )
            )
            if negotiated:
                ack = socket.receive_json()
                assert (
                    ack["kind"] == "power_event_ack"
                    and ack["payload"]["batch_id"] == value["batch_id"]
                )
                assert ack["payload"]["results"] == []
                socket.send_json(
                    dict(
                        schema_version="gateway_ws_envelope_v1",
                        kind="heartbeat",
                        sequence=2,
                        payload=dict(
                            schema_version="agent_heartbeat_v1",
                            device_id=str(device.id),
                            platform="windows",
                            agent_version="3.2.149",
                            reported_at=datetime.now(UTC).isoformat(),
                        ),
                    )
                )
                socket.send_json(
                    dict(
                        schema_version="gateway_ws_envelope_v1",
                        kind="power_event_batch",
                        sequence=3,
                        payload=value,
                    )
                )
                assert socket.receive_json()["kind"] == "power_event_ack"
            else:
                assert socket.receive_json()["kind"] == "error"
                with pytest.raises(WebSocketDisconnect):
                    socket.receive_json()
