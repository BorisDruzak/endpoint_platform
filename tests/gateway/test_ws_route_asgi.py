from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from endpoint_server.context.models import ContextCollection
from endpoint_server.db.models import Command
from endpoint_server.main import create_app

from .conftest import (
    FixedWebSocketPeerApp,
    GatewayRouteHarness,
    VALID_TOKEN,
    agent_hello,
    seed_device,
)


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {VALID_TOKEN}",
        "X-Forwarded-For": "192.168.101.20",
        "X-Forwarded-Proto": "https",
    }


def _hello_envelope(device_id, capabilities: list[str]) -> dict[str, object]:
    hello = agent_hello(device_id)
    hello["capabilities"] = capabilities
    return {
        "schema_version": "gateway_ws_envelope_v1",
        "kind": "agent_hello",
        "sequence": 0,
        "payload": hello,
    }


def test_route_does_not_send_command_outside_negotiated_capabilities(
    gateway_route_harness: GatewayRouteHarness,
) -> None:
    provider = gateway_route_harness.provider
    device = asyncio.run(seed_device(provider))

    async def seed_collection() -> None:
        async with provider() as session:
            session.add(
                ContextCollection(
                    id=uuid4(),
                    device_id=device.id,
                    profile="baseline_v1",
                    requested_by="gateway-route-test",
                    idempotency_key="negotiated-capability",
                    status="requested",
                    requested_at=datetime.now(UTC),
                )
            )
            await session.commit()

    asyncio.run(seed_collection())
    app = create_app(gateway_route_harness.settings, provider)
    hello = _hello_envelope(device.id, ["agent.status.read"])

    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect(
            "/agent/v1/connect",
            headers=_headers(),
        ) as websocket:
            websocket.send_json(hello)
            gateway_hello = websocket.receive_json()
            assert gateway_hello["payload"]["effective_capabilities"] == [
                "agent.status.read"
            ]
            websocket.send_json(hello)
            response = websocket.receive_json()

    assert response["kind"] == "error"
    assert response["payload"]["code"] == "unexpected_message"

    async def command_count() -> int:
        async with provider() as session:
            from sqlalchemy import func, select

            return await session.scalar(select(func.count()).select_from(Command))

    assert asyncio.run(command_count()) == 0


def test_route_maps_semantically_invalid_context_result_to_safe_error(
    gateway_route_harness: GatewayRouteHarness,
) -> None:
    provider = gateway_route_harness.provider
    device = asyncio.run(seed_device(provider))
    command_id = uuid4()
    now = datetime.now(UTC)

    async def seed_running_command() -> None:
        async with provider() as session:
            session.add(
                Command(
                    id=command_id,
                    command_identifier=f"command-{command_id.hex}",
                    device_id=device.id,
                    command_kind="context.baseline.collect",
                    status="running",
                    expires_at=now + timedelta(minutes=5),
                )
            )
            await session.flush()
            session.add(
                ContextCollection(
                    id=uuid4(),
                    device_id=device.id,
                    profile="baseline_v1",
                    requested_by="gateway-route-test",
                    idempotency_key="invalid-context-result",
                    command_id=command_id,
                    status="collecting",
                    requested_at=now,
                )
            )
            await session.commit()

    asyncio.run(seed_running_command())
    app = create_app(gateway_route_harness.settings, provider)

    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect(
            "/agent/v1/connect",
            headers=_headers(),
        ) as websocket:
            websocket.send_json(
                _hello_envelope(device.id, ["context.baseline.collect"])
            )
            assert websocket.receive_json()["kind"] == "gateway_hello"
            websocket.send_json(
                {
                    "schema_version": "gateway_ws_envelope_v1",
                    "kind": "command_result",
                    "sequence": 7,
                    "payload": {
                        "schema_version": "agent_result_v1",
                        "command_id": str(command_id),
                        "device_id": str(device.id),
                        "status": "succeeded",
                        "result_items": [],
                        "message": None,
                        "completed_at": (now + timedelta(seconds=1)).isoformat(),
                    },
                }
            )
            try:
                response = websocket.receive_json()
            except WebSocketDisconnect as disconnect:
                raise AssertionError(
                    f"route closed without a safe error: {disconnect.code}"
                ) from disconnect
            assert response["kind"] == "error"
            assert response["payload"] == {
                "schema_version": "gateway_error_v1",
                "code": "state_rejected",
                "message": "Gateway message rejected",
                "retryable": False,
            }
            try:
                websocket.receive_json()
            except WebSocketDisconnect as disconnect:
                assert disconnect.code == 1008
            else:
                raise AssertionError("semantic rejection did not close the connection")
