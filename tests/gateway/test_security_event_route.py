"""SecurityEvent WSS dispatch is gated by negotiated Agent feature."""

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
    PolicyAssignment,
    PolicyDefinition,
    PolicyDeviceState,
    PolicyVersion,
)
from endpoint_server.policy.service import assign_default_policy, create_policy_version
from endpoint_server.security.models import SecurityEvent
from tests.contracts.test_endpoint_policy_v1 import POLICY_ID, _policy

from .conftest import (
    FixedWebSocketPeerApp,
    GatewayRouteHarness,
    VALID_TOKEN,
    agent_hello,
    seed_device,
)


def test_route_rejects_security_batch_without_feature_negotiation(
    gateway_route_harness: GatewayRouteHarness,
) -> None:
    device = asyncio.run(seed_device(gateway_route_harness.provider))
    app = create_app(gateway_route_harness.settings, gateway_route_harness.provider)
    hello = agent_hello(device.id)
    hello["platform"] = "windows_amd64"
    hello["capabilities"] = []
    batch = {
        "schema_version": "gateway_ws_envelope_v1",
        "sequence": 1,
        "kind": "security_event_batch",
        "payload": {
            "schema_version": "agent_security_event_batch_v1",
            "batch_id": str(uuid4()),
            "events": [
                {
                    "schema_version": "security_event_v1",
                    "event_identifier": str(uuid4()),
                    "event_type": "USB_DEVICE_CONNECTED",
                    "channel": "USB",
                    "severity": "INFO",
                    "occurred_at": datetime.now(UTC).isoformat(),
                    "policy_id": str(uuid4()),
                    "policy_version": 1,
                    "safe_metadata": {"removable": True},
                }
            ],
        },
    }
    headers = {
        "Authorization": f"Bearer {VALID_TOKEN}",
        "X-Forwarded-For": "192.168.101.20",
        "X-Forwarded-Proto": "https",
    }
    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect(
            "/agent/v1/connect", headers=headers
        ) as websocket:
            websocket.send_json(
                {
                    "schema_version": "gateway_ws_envelope_v1",
                    "kind": "agent_hello",
                    "sequence": 0,
                    "payload": hello,
                }
            )
            assert websocket.receive_json()["kind"] == "gateway_hello"
            websocket.send_json(batch)
            error = websocket.receive_json()
            assert error["kind"] == "error"
            assert error["payload"]["code"] == "security_events_disabled"


def test_route_acks_committed_security_event_and_idempotent_replay(
    gateway_route_harness: GatewayRouteHarness,
) -> None:
    provider = gateway_route_harness.provider
    device = asyncio.run(seed_device(provider))

    async def seed_policy() -> None:
        async with gateway_route_harness.engine.begin() as connection:
            await connection.run_sync(
                lambda sync: Base.metadata.create_all(
                    sync,
                    tables=[
                        PolicyDefinition.__table__,
                        PolicyVersion.__table__,
                        PolicyAssignment.__table__,
                        PolicyDeviceState.__table__,
                        SecurityEvent.__table__,
                    ],
                )
            )
        async with provider() as session:
            session.add(PolicyDefinition(id=POLICY_ID, name="Security Default"))
            await session.flush()
            version = await create_policy_version(
                session, POLICY_ID, _policy(), actor_id=uuid4()
            )
            await assign_default_policy(session, version.id, actor_id=uuid4())
            await session.commit()

    asyncio.run(seed_policy())
    settings = replace(gateway_route_harness.settings, endpoint_policy_enabled=True)
    app = create_app(settings, provider)
    hello = agent_hello(device.id)
    hello.update(
        platform="windows_amd64",
        agent_version="3.2.68",
        launcher_version="3.2.68",
        capabilities=[],
        protocol_features=["endpoint.policy.v1", "endpoint.security-events.v1"],
    )
    headers = {
        "Authorization": f"Bearer {VALID_TOKEN}",
        "X-Forwarded-For": "192.168.101.20",
        "X-Forwarded-Proto": "https",
    }
    event_id = uuid4()
    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect(
            "/agent/v1/connect", headers=headers
        ) as websocket:
            websocket.send_json(
                {
                    "schema_version": "gateway_ws_envelope_v1",
                    "kind": "agent_hello",
                    "sequence": 0,
                    "payload": hello,
                }
            )
            assert websocket.receive_json()["kind"] == "gateway_hello"
            delivery = websocket.receive_json()
            assert delivery["kind"] == "endpoint_policy_delivery"
            now = datetime.now(UTC).isoformat()
            websocket.send_json(
                {
                    "schema_version": "gateway_ws_envelope_v1",
                    "kind": "endpoint_policy_ack",
                    "sequence": 1,
                    "payload": {
                        "schema_version": "endpoint_policy_ack_v1",
                        "policy_id": str(POLICY_ID),
                        "policy_version": 1,
                        "policy_digest": delivery["payload"]["policy_digest"],
                        "received_at": now,
                        "applied_at": now,
                        "status": "APPLIED",
                    },
                }
            )
            for sequence in (2, 3):
                batch_id = uuid4()
                websocket.send_json(
                    {
                        "schema_version": "gateway_ws_envelope_v1",
                        "kind": "security_event_batch",
                        "sequence": sequence,
                        "payload": {
                            "schema_version": "agent_security_event_batch_v1",
                            "batch_id": str(batch_id),
                            "events": [
                                {
                                    "schema_version": "security_event_v1",
                                    "event_identifier": str(event_id),
                                    "event_type": "USB_DEVICE_CONNECTED",
                                    "channel": "USB",
                                    "severity": "INFO",
                                    "occurred_at": now,
                                    "policy_id": str(POLICY_ID),
                                    "policy_version": 1,
                                    "safe_metadata": {"removable": True},
                                }
                            ],
                        },
                    }
                )
                ack = websocket.receive_json()
                assert ack["kind"] == "security_event_ack"
                assert ack["sequence"] == sequence
                assert ack["payload"]["batch_id"] == str(batch_id)
                assert ack["payload"]["event_identifiers"] == [str(event_id)]

    async def count_events() -> int:
        async with provider() as session:
            return len((await session.scalars(select(SecurityEvent))).all())

    assert asyncio.run(count_events()) == 1
