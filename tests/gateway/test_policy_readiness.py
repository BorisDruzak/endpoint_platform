"""Only an authenticated, opted-in hello receives an explicit policy obligation."""

import asyncio
from dataclasses import replace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from starlette.websockets import WebSocketDisconnect

from endpoint_server.db.base import Base
from endpoint_server.gateway import ws_routes
from endpoint_server.main import create_app
from endpoint_server.policy.models import (
    PolicyApplication,
    PolicyAssignment,
    PolicyDefinition,
    PolicyDeviceState,
    PolicyVersion,
)
from endpoint_server.policy.service import (
    assign_default_policy,
    assign_device_policy,
    create_policy_version,
    resolve_effective_policy,
)
from tests.contracts.test_endpoint_policy_v1 import POLICY_ID, _policy

from .conftest import FixedWebSocketPeerApp, agent_hello, seed_device
from .test_policy_wss import _headers

FEATURE = "endpoint.policy-readiness.v1"


def _prepare(harness, assignment):
    device = asyncio.run(seed_device(harness.provider))

    async def prepare():
        async with harness.engine.begin() as connection:
            await connection.run_sync(lambda sync: Base.metadata.create_all(sync, tables=[
                PolicyDefinition.__table__, PolicyVersion.__table__,
                PolicyAssignment.__table__, PolicyDeviceState.__table__,
                PolicyApplication.__table__,
            ]))
        if assignment == "none":
            return
        other = (
            await seed_device(harness.provider, token="other-device-token")
            if assignment == "other_device" else device
        )
        async with harness.provider() as session:
            session.add(PolicyDefinition(id=POLICY_ID, name="Readiness test"))
            await session.flush()
            version = await create_policy_version(
                session, POLICY_ID, _policy(), actor_id=uuid4(),
            )
            if assignment == "default":
                await assign_default_policy(session, version.id, actor_id=uuid4())
            else:
                await assign_device_policy(session, other.id, version.id, actor_id=uuid4())
            await session.commit()

    asyncio.run(prepare())
    return device


def _hello(device_id, *, negotiated=True):
    hello = agent_hello(device_id)
    hello.update(
        agent_version="3.2.156" if negotiated else "3.2.155",
        launcher_version="3.2.156" if negotiated else "3.2.155",
        capabilities=[],
        protocol_features=["endpoint.policy.v1"] + ([FEATURE] if negotiated else []),
    )
    return {
        "schema_version": "gateway_ws_envelope_v1", "kind": "agent_hello",
        "sequence": 0, "payload": hello,
    }


@pytest.mark.parametrize("enabled,assignment,expected", [
    (False, "none", "not_required"),
    (False, "default", "not_required"),
    (True, "none", "not_required"),
    (True, "other_device", "not_required"),
    (True, "default", "required"),
    (True, "device", "required"),
])
def test_readiness_uses_actual_authenticated_device_and_existing_policy(
    gateway_route_harness, monkeypatch, enabled, assignment, expected,
):
    harness = gateway_route_harness
    device = _prepare(harness, assignment)
    queried = []

    async def observe_resolution(session, device_id):
        queried.append(device_id)
        return await resolve_effective_policy(session, device_id)

    monkeypatch.setattr(ws_routes, "resolve_effective_policy", observe_resolution, raising=False)
    app = create_app(replace(harness.settings, endpoint_policy_enabled=enabled), harness.provider)
    with (
        TestClient(FixedWebSocketPeerApp(app)) as client,
        client.websocket_connect("/agent/v1/connect", headers=_headers()) as socket,
    ):
        hello = _hello(device.id)
        socket.send_json(hello)
        greeting = socket.receive_json()
        assert greeting["kind"] == "gateway_hello"
        assert greeting["payload"]["protocol_features"] == [FEATURE]
        assert greeting["payload"]["policy_readiness"] == expected
        if expected == "required":
            assert socket.receive_json()["kind"] == "endpoint_policy_delivery"
        socket.send_json(hello)
        assert socket.receive_json()["payload"]["code"] == "unexpected_message"

    assert queried == ([device.id] if enabled else [])

    async def assignments():
        async with harness.provider() as session:
            return await session.scalar(select(func.count()).select_from(PolicyAssignment))

    assert asyncio.run(assignments()) == (0 if assignment == "none" else 1)


@pytest.mark.parametrize("enabled,assignment", [(False, "none"), (True, "none"), (True, "default")])
@pytest.mark.parametrize("full_155_features", [False, True])
def test_legacy_155_gateway_wire_does_not_gain_readiness(
    gateway_route_harness, monkeypatch, enabled, assignment, full_155_features,
):
    harness = gateway_route_harness
    device = _prepare(harness, assignment)

    async def forbidden_readiness_query(*args):
        pytest.fail("legacy peer must not request a readiness resolution")

    monkeypatch.setattr(ws_routes, "resolve_effective_policy", forbidden_readiness_query, raising=False)
    app = create_app(replace(harness.settings, endpoint_policy_enabled=enabled), harness.provider)
    with (
        TestClient(FixedWebSocketPeerApp(app)) as client,
        client.websocket_connect("/agent/v1/connect", headers=_headers()) as socket,
    ):
        hello = _hello(device.id, negotiated=False)
        if full_155_features:
            hello["payload"]["protocol_features"] = [
                "endpoint.policy.v1", "endpoint.activity.v1",
                "endpoint.security-events.v1", "endpoint.browser-status.v1",
                "endpoint.sensor-health.v1", "endpoint.recovery-update.v2",
                "endpoint.telemetry-results.v1", "endpoint.power-events.v1",
            ]
        socket.send_json(hello)
        greeting = socket.receive_json()
        assert greeting["kind"] == "gateway_hello"
        expected_keys = {
            "schema_version", "session_id", "heartbeat_interval_seconds",
            "maximum_message_bytes", "policy_revision", "effective_capabilities",
            "server_time",
        }
        if full_155_features:
            expected_keys.add("protocol_features")
            assert greeting["payload"]["protocol_features"] == [
                "endpoint.telemetry-results.v1", "endpoint.power-events.v1",
            ]
        assert set(greeting["payload"]) == expected_keys
        if enabled and assignment == "default":
            assert socket.receive_json()["kind"] == "endpoint_policy_delivery"


@pytest.mark.parametrize("failure", ["database", "timeout"])
def test_readiness_query_failure_never_sends_a_no_policy_hello(
    gateway_route_harness, monkeypatch, failure,
):
    harness = gateway_route_harness
    device = _prepare(harness, "none")
    queried = []

    async def failed_resolution(session, device_id):
        queried.append(device_id)
        if failure == "timeout":
            raise TimeoutError("test policy query unavailable")
        raise OperationalError("test policy query", {}, RuntimeError("unavailable"))

    monkeypatch.setattr(ws_routes, "resolve_effective_policy", failed_resolution, raising=False)
    app = create_app(replace(harness.settings, endpoint_policy_enabled=True), harness.provider)
    with (
        TestClient(FixedWebSocketPeerApp(app)) as client,
        client.websocket_connect("/agent/v1/connect", headers=_headers()) as socket,
    ):
        socket.send_json(_hello(device.id))
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_json()
        assert closed.value.code in {1011, 4000}
    assert queried == [device.id]
