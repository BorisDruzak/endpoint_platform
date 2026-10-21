"""The Gateway must reject activity when continuous policy is disabled."""

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import pytest
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


@pytest.mark.parametrize("phase", [
    "before_delivery", "pending", "disabled", "foreground_disabled", "browser_disabled",
])
@pytest.mark.parametrize('platform,version', [('windows_amd64', '3.2.121'), ('linux_amd64', '3.2.122')])
def test_policy_transition_discards_ineligible_activity_without_closing_wss(
    gateway_route_harness: GatewayRouteHarness, phase: str, platform: str, version: str,
) -> None:
    from dataclasses import replace
    from endpoint_server.db.base import Base
    from endpoint_server.db.models import ActivityCursor, ActivityDaily, ActivityInterval
    from endpoint_server.policy.models import (
        PolicyApplication, PolicyAssignment, PolicyDefinition, PolicyDeviceState, PolicyVersion,
    )
    from endpoint_server.policy.service import assign_default_policy, create_policy_version
    from tests.contracts.test_endpoint_policy_v1 import POLICY_ID, _policy

    harness = gateway_route_harness
    provider = harness.provider
    device = asyncio.run(seed_device(provider))

    async def seed_policy():
        async with harness.engine.begin() as connection:
            await connection.run_sync(lambda sync: Base.metadata.create_all(sync, tables=[
                PolicyDefinition.__table__, PolicyVersion.__table__, PolicyAssignment.__table__,
                PolicyDeviceState.__table__, PolicyApplication.__table__,
                ActivityCursor.__table__, ActivityDaily.__table__, ActivityInterval.__table__,
            ]))
        async with provider() as session:
            session.add(PolicyDefinition(id=POLICY_ID, name="Activity transition"))
            await session.flush()
            version = await create_policy_version(session, POLICY_ID, _policy(), actor_id=uuid4())
            await assign_default_policy(session, version.id, actor_id=uuid4())
            await session.commit()

    async def assign_second():
        document = _policy(policy_version=2)
        if phase == "disabled":
            document["activity"]["enabled"] = False
        elif phase in {"foreground_disabled", "browser_disabled"}:
            key = "foreground_application" if phase == "foreground_disabled" else "browser_context"
            document["activity"][key] = False
        async with provider() as session:
            version = await create_policy_version(session, POLICY_ID, document, actor_id=uuid4())
            await assign_default_policy(session, version.id, actor_id=uuid4())
            await session.commit()

    asyncio.run(seed_policy())
    app = create_app(replace(harness.settings, endpoint_policy_enabled=True), provider)
    hello = agent_hello(device.id)
    hello.update(platform=platform, agent_version=version, capabilities=[],
                 protocol_features=["endpoint.policy.v1", "endpoint.activity.v1"])
    hello_frame = {"schema_version": "gateway_ws_envelope_v1", "kind": "agent_hello",
                   "sequence": 0, "payload": hello}
    sequence = 0

    def frame(kind, payload):
        nonlocal sequence
        sequence += 1
        return {"schema_version": "gateway_ws_envelope_v1", "kind": kind,
                "sequence": sequence, "payload": payload}

    def ack(delivery):
        policy = delivery["payload"]["policy"]
        now = datetime.now(UTC).isoformat()
        return frame("endpoint_policy_ack", {
            "schema_version": "endpoint_policy_ack_v1", "policy_id": policy["policy_id"],
            "policy_version": policy["policy_version"],
            "policy_digest": delivery["payload"]["policy_digest"],
            "received_at": now, "applied_at": now, "status": "APPLIED",
        })

    def heartbeat():
        return frame("heartbeat", {
            "schema_version": "agent_heartbeat_v1", "device_id": str(device.id),
            "platform": platform.split('_')[0], "agent_version": version,
            "reported_at": datetime.now(UTC).isoformat(),
        })

    def activity(*, restricted=False):
        value = {
            "schema_version": "activity_observation_v1", "observation_id": str(uuid4()),
            "observed_at": datetime.now(UTC).isoformat(), "user_login": "DOMAIN\\user",
            "session_state": "ACTIVE", "idle_seconds": 1,
        }
        if restricted and phase == "foreground_disabled":
            value["foreground"] = {"process_name": "browser.exe", "application_category": "browser"}
        if restricted and phase == "browser_disabled":
            value["browser"] = {"browser_family": "chrome", "sensor_state": "NEVER_SEEN"}
        return frame("activity_observation", value)

    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect("/agent/v1/connect", headers={
            "Authorization": f"Bearer {VALID_TOKEN}", "X-Forwarded-For": "192.168.101.20",
            "X-Forwarded-Proto": "https",
        }) as socket:
            socket.send_json(hello_frame)
            assert socket.receive_json()["kind"] == "gateway_hello"
            socket.send_json(ack(socket.receive_json()))
            asyncio.run(assign_second())
            if phase != "before_delivery":
                socket.send_json(heartbeat())
                changed = socket.receive_json()
                assert changed["kind"] == "endpoint_policy_delivery"
                if phase != "pending":
                    socket.send_json(ack(changed))
            socket.send_json(activity(restricted=True))
            if phase == "before_delivery":
                socket.send_json(heartbeat())
                changed = socket.receive_json()
                assert changed["kind"] == "endpoint_policy_delivery"
            if phase in {"before_delivery", "pending"}:
                socket.send_json(ack(changed))
            if phase != "disabled":
                socket.send_json(activity())
            # A response to this later protocol error proves the policy-gated
            # Activity did not terminate the connection or block the new ACK.
            socket.send_json(hello_frame)
            assert socket.receive_json()["payload"]["code"] == "unexpected_message"

    async def verify():
        async with provider() as session:
            state = await session.scalar(select(PolicyDeviceState).where(
                PolicyDeviceState.device_id == device.id))
            assert state.status == "APPLIED"
            assert (await session.get(PolicyVersion, state.policy_version_id)).version == 2
            expected = 0 if phase == "disabled" else 1
            assert await session.scalar(select(func.count()).select_from(ContextSnapshot)) == expected
            assert await session.scalar(select(func.count()).select_from(ActivityInterval)) == expected

    asyncio.run(verify())
