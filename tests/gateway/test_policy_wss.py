"""The real Gateway keeps old Agents safe while delivering opted-in policy."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import select

from endpoint_server.db.base import Base
from endpoint_server.main import create_app
from endpoint_server.policy.models import (
    PolicyApplication, PolicyAssignment, PolicyDefinition, PolicyDeviceState, PolicyVersion,
)
from endpoint_server.policy.service import assign_default_policy, create_policy_version
from tests.contracts.test_endpoint_policy_v1 import POLICY_ID, _policy

from .conftest import (
    FixedWebSocketPeerApp, GatewayRouteHarness, VALID_TOKEN,
    agent_hello, seed_device,
)


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {VALID_TOKEN}",
        "X-Forwarded-For": "192.168.101.20",
        "X-Forwarded-Proto": "https",
    }


def _envelope(device_id, *, features: list[str], agent_version: str) -> dict[str, object]:
    hello = agent_hello(device_id)
    hello.update(
        platform="windows_amd64", agent_version=agent_version,
        launcher_version=agent_version, capabilities=[],
    )
    if features:
        hello["protocol_features"] = features
    return {
        "schema_version": "gateway_ws_envelope_v1", "kind": "agent_hello",
        "sequence": 0, "payload": hello,
    }


def test_wss_policy_sync_preserves_legacy_and_records_real_ack(
    gateway_route_harness: GatewayRouteHarness,
) -> None:
    provider = gateway_route_harness.provider
    device = asyncio.run(seed_device(provider))

    async def seed_policy() -> None:
        async with gateway_route_harness.engine.begin() as connection:
            await connection.run_sync(lambda sync: Base.metadata.create_all(sync, tables=[
                PolicyDefinition.__table__, PolicyVersion.__table__,
                PolicyAssignment.__table__, PolicyDeviceState.__table__,
                PolicyApplication.__table__,
            ]))
        async with provider() as session:
            session.add(PolicyDefinition(id=POLICY_ID, name="Municipal Default"))
            await session.flush()
            version = await create_policy_version(session, POLICY_ID, _policy(), actor_id=uuid4())
            await assign_default_policy(session, version.id, actor_id=uuid4())
            await session.commit()

    asyncio.run(seed_policy())
    settings = replace(gateway_route_harness.settings, endpoint_policy_enabled=True)
    app = create_app(settings, provider)

    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect("/agent/v1/connect", headers=_headers()) as websocket:
            legacy = _envelope(device.id, features=[], agent_version="3.2.67")
            websocket.send_json(legacy)
            assert websocket.receive_json()["kind"] == "gateway_hello"
            websocket.send_json(legacy)
            assert websocket.receive_json()["payload"]["code"] == "unexpected_message"

        with client.websocket_connect("/agent/v1/connect", headers=_headers()) as websocket:
            websocket.send_json(_envelope(
                device.id, features=["endpoint.policy.v1"], agent_version="3.2.68",
            ))
            assert websocket.receive_json()["kind"] == "gateway_hello"
            delivery = websocket.receive_json()
            assert delivery["kind"] == "endpoint_policy_delivery"
            policy = delivery["payload"]["policy"]
            assert policy["policy_id"] == str(POLICY_ID)
            now = datetime.now(UTC).isoformat()
            websocket.send_json({
                "schema_version": "gateway_ws_envelope_v1", "kind": "endpoint_policy_ack",
                "sequence": 1,
                "payload": {
                    "schema_version": "endpoint_policy_ack_v1",
                    "policy_id": policy["policy_id"],
                    "policy_version": policy["policy_version"],
                    "policy_digest": delivery["payload"]["policy_digest"],
                    "received_at": now, "applied_at": now, "status": "APPLIED",
                },
            })
            async def assign_second_version() -> None:
                async with provider() as session:
                    second = await create_policy_version(
                        session, POLICY_ID, _policy(policy_version=2), actor_id=uuid4(),
                    )
                    await assign_default_policy(session, second.id, actor_id=uuid4())
                    await session.commit()

            asyncio.run(assign_second_version())
            websocket.send_json({
                "schema_version": "gateway_ws_envelope_v1", "kind": "heartbeat",
                "sequence": 2, "payload": {
                    "schema_version": "agent_heartbeat_v1", "device_id": str(device.id),
                    "platform": "windows", "agent_version": "3.2.68",
                    "reported_at": datetime.now(UTC).isoformat(),
                },
            })
            changed = websocket.receive_json()
            assert changed["kind"] == "endpoint_policy_delivery"
            assert changed["payload"]["policy"]["policy_version"] == 2
            now = datetime.now(UTC).isoformat()
            websocket.send_json({
                "schema_version": "gateway_ws_envelope_v1", "kind": "endpoint_policy_ack",
                "sequence": 3,
                "payload": {
                    "schema_version": "endpoint_policy_ack_v1",
                    "policy_id": str(POLICY_ID), "policy_version": 2,
                    "policy_digest": changed["payload"]["policy_digest"],
                    "received_at": now, "applied_at": now, "status": "APPLIED",
                },
            })
            websocket.send_json(_envelope(device.id, features=[], agent_version="3.2.67"))
            assert websocket.receive_json()["payload"]["code"] == "unexpected_message"

    async def read_status() -> str:
        async with provider() as session:
            state = await session.scalar(
                select(PolicyDeviceState).where(PolicyDeviceState.device_id == device.id)
            )
            assert state is not None
            return state.status

    assert asyncio.run(read_status()) == "APPLIED"
