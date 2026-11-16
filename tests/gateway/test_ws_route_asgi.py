from __future__ import annotations

import asyncio
import ipaddress
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Event
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from endpoint_contracts.gateway_ws import COMMAND_JOURNAL_FEATURE, COMMAND_JOURNAL_HEADER
from endpoint_server.context.models import ContextCollection
from endpoint_server.db.models import Command, DeviceSession
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


def test_replacement_hello_precedes_stalled_asgi_notice_and_close(
    gateway_route_harness, caplog,
):
    provider = gateway_route_harness.provider
    device = asyncio.run(seed_device(provider))
    hello = _hello_envelope(device.id, ["agent.status.read"])
    app = create_app(gateway_route_harness.settings, provider)
    peer_app = FixedWebSocketPeerApp(app)
    close_cancelled = Event()
    stages = []

    @app.get("/_test/registered-session")
    async def registered_session():
        connection = await app.state.gateway_connection_registry.get(device.id)
        return str(connection.session_id) if connection is not None else None

    async def stall_until_gateway_timeout():
        await asyncio.sleep(3)
        pytest.fail("The Gateway did not cancel the stalled ASGI operation")

    async def with_stalled_old_socket(scope, receive, send):
        old_peer = (b"x-test-stall-cleanup", b"yes") in scope.get("headers", ())

        async def observe_send(message):
            kind = None
            if message["type"] == "websocket.send":
                kind = json.loads(message["text"])["kind"]
            if old_peer and kind == "server_shutdown_notice":
                stages.append("notice_started")
                try:
                    await stall_until_gateway_timeout()
                finally:
                    stages.append("notice_cancelled")
            if old_peer and message["type"] == "websocket.close" and message["code"] == 4001:
                try:
                    await stall_until_gateway_timeout()
                finally:
                    close_cancelled.set()
            if not old_peer and kind == "gateway_hello":
                stages.append("replacement_hello")
            await send(message)

        await peer_app(scope, receive, observe_send)

    async def durable_sessions():
        async with provider() as session:
            rows = await session.scalars(select(DeviceSession).where(
                DeviceSession.device_id == device.id,
            ))
            return {str(row.id): row.closed_at for row in rows}

    with TestClient(with_stalled_old_socket) as client:
        headers = {**_headers(), "X-Test-Stall-Cleanup": "yes"}
        with client.websocket_connect("/agent/v1/connect", headers=_headers()) as new_socket:
            with client.websocket_connect("/agent/v1/connect", headers=headers) as old_socket:
                old_socket.send_json(hello)
                old_session = old_socket.receive_json()["payload"]["session_id"]
                new_socket.send_json(hello)
                replacement = new_socket.receive_json()
                assert replacement["kind"] == "gateway_hello"
                new_session = replacement["payload"]["session_id"]
                assert new_session != old_session
                assert close_cancelled.wait(5), "Old socket close did not reach its deadline"
                current = asyncio.run(durable_sessions())
                assert set(current) == {old_session, new_session}
                assert current[old_session] is not None
                assert current[new_session] is None
            assert client.get("/_test/registered-session").json() == new_session

    assert stages == ["notice_started", "replacement_hello", "notice_cancelled"]
    assert "reason=session_replaced stage=notice error=TimeoutError" in caplog.text
    assert "reason=session_replaced stage=close error=TimeoutError" in caplog.text


@pytest.mark.parametrize("existing", [False, True])
def test_authenticated_hello_persists_foundation_and_heartbeat_only_changes_core(
    gateway_route_harness, existing,
):
    from endpoint_server.db.models import DeviceInstance
    provider = gateway_route_harness.provider
    device = asyncio.run(seed_device(provider))
    hello = _hello_envelope(device.id, ["agent.status.read"])
    hello["payload"]["agent_version"] = "3.2.82"
    hello["payload"]["launcher_version"] = "3.2.83+foundation.1"
    if existing:
        async def seed_instance():
            async with provider() as session:
                session.add(DeviceInstance(id=uuid4(), device_id=device.id,
                    instance_identifier=hello["payload"]["agent_instance_id"],
                    agent_version="3.2.81", last_seen_at=datetime(2025, 1, 1, tzinfo=UTC)))
                await session.commit()
        asyncio.run(seed_instance())
    app = create_app(gateway_route_harness.settings, provider)
    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect("/agent/v1/connect", headers=_headers()) as socket:
            socket.send_json(hello)
            assert socket.receive_json()["kind"] == "gateway_hello"
            async def read_instance():
                async with provider() as session:
                    return await session.scalar(select(DeviceInstance).where(DeviceInstance.device_id == device.id))
            before = asyncio.run(read_instance())
            assert before.launcher_version == "3.2.83+foundation.1"
            socket.send_json({
                "schema_version": "gateway_ws_envelope_v1", "kind": "heartbeat", "sequence": 1,
                "payload": {"schema_version": "agent_heartbeat_v1", "device_id": str(device.id),
                            "platform": "linux", "agent_version": "3.2.82+core.2",
                            "reported_at": "2026-10-03T00:00:00Z"},
            })
            # The error response orders our read after the preceding heartbeat.
            socket.send_json(hello)
            assert socket.receive_json()["kind"] == "error"
            after = asyncio.run(read_instance())
            assert after.agent_version == "3.2.82+core.2"
            assert after.last_seen_at > before.last_seen_at
            assert after.launcher_version == "3.2.83+foundation.1"


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


def test_route_queues_and_delivers_supported_connect_refresh(
    gateway_route_harness: GatewayRouteHarness,
) -> None:
    provider = gateway_route_harness.provider
    device = asyncio.run(seed_device(provider))
    app = create_app(gateway_route_harness.settings, provider)

    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect("/agent/v1/connect", headers=_headers()) as websocket:
            websocket.send_json(
                _hello_envelope(
                    device.id,
                    ["context.baseline.collect", "context.inventory.collect", "context.network.collect"],
                )
            )
            assert websocket.receive_json()["kind"] == "gateway_hello"
            command = websocket.receive_json()

    assert command["kind"] == "command"
    assert command["payload"]["capability"] in {
        "context.baseline.collect", "context.inventory.collect", "context.network.collect",
    }

    async def queued_profiles() -> list[str]:
        async with provider() as session:
            from sqlalchemy import select

            return list(
                await session.scalars(
                    select(ContextCollection.profile)
                    .where(ContextCollection.device_id == device.id)
                    .order_by(ContextCollection.profile)
                )
            )

    assert asyncio.run(queued_profiles()) == ["baseline_v1", "inventory_v1", "network_v1"]


@pytest.mark.parametrize("expired", [False, True])
def test_route_sends_negotiated_command_start_or_cancel(gateway_route_harness, expired):
    provider = gateway_route_harness.provider
    device = asyncio.run(seed_device(provider))
    app = create_app(gateway_route_harness.settings, provider)
    hello = _hello_envelope(device.id, ["context.baseline.collect"])
    hello["payload"]["protocol_features"] = [COMMAND_JOURNAL_FEATURE]
    headers = {**_headers(), COMMAND_JOURNAL_HEADER: "1"}
    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect("/agent/v1/connect", headers=headers) as socket:
            assert (COMMAND_JOURNAL_HEADER.encode(), b"1") in socket.extra_headers
            socket.send_json(hello)
            assert socket.receive_json()["payload"]["protocol_features"] == [COMMAND_JOURNAL_FEATURE]
            command = socket.receive_json()["payload"]
            if expired:
                async def expire_command():
                    from uuid import UUID
                    async with provider() as session:
                        stored = await session.get(Command, UUID(command["command_id"]))
                        stored.expires_at = datetime.now(UTC) - timedelta(seconds=1)
                        await session.commit()
                asyncio.run(expire_command())
            socket.send_json({
                "schema_version": "gateway_ws_envelope_v1", "kind": "command_ack", "sequence": 1,
                "payload": {
                    "schema_version": "agent_command_ack_v1", "command_id": command["command_id"],
                    "device_id": str(device.id), "status": "running",
                    "acknowledged_at": datetime.now(UTC).isoformat(),
                },
            })
            decision = socket.receive_json()
            assert decision["kind"] == ("command_cancel" if expired else "command_start")
            assert decision["payload"]["command_id"] == command["command_id"]


def test_route_negotiates_typed_network_capability_only_after_full_server_opt_in(
    gateway_route_harness: GatewayRouteHarness,
) -> None:
    provider = gateway_route_harness.provider
    device = asyncio.run(seed_device(provider))
    hello = _hello_envelope(device.id, ["network.ping"])

    disabled_app = create_app(gateway_route_harness.settings, provider)
    with TestClient(FixedWebSocketPeerApp(disabled_app)) as client:
        with client.websocket_connect(
            "/agent/v1/connect",
            headers=_headers(),
        ) as websocket:
            websocket.send_json(hello)
            assert websocket.receive_json()["payload"]["effective_capabilities"] == []

    enabled_settings = replace(
        gateway_route_harness.settings,
        endpoint_network_primitives_enabled=True,
        endpoint_network_probe_allowed_cidrs=(
            ipaddress.ip_network("10.20.0.0/16"),
        ),
    )
    enabled_app = create_app(enabled_settings, provider)
    with TestClient(FixedWebSocketPeerApp(enabled_app)) as client:
        with client.websocket_connect(
            "/agent/v1/connect",
            headers=_headers(),
        ) as websocket:
            websocket.send_json(hello)
            assert websocket.receive_json()["payload"]["effective_capabilities"] == [
                "network.ping"
            ]


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
