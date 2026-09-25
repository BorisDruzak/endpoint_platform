"""Browser status WSS frames require separate negotiated capability."""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from endpoint_server.db.base import Base
from endpoint_server.main import create_app
from endpoint_server.policy.models import BrowserStatusCurrent
from endpoint_server.policy.models import (
    PolicyApplication, PolicyAssignment, PolicyDefinition, PolicyDeviceState, PolicyVersion,
)
from endpoint_server.policy.service import assign_default_policy, create_policy_version
from tests.contracts.test_browser_status_v1 import _report
from tests.contracts.test_endpoint_policy_v1 import POLICY_ID, _policy

from .conftest import (
    FixedWebSocketPeerApp, GatewayRouteHarness, VALID_TOKEN, agent_hello, seed_device,
)


def test_route_rejects_browser_status_when_policy_feature_is_disabled(
    gateway_route_harness: GatewayRouteHarness,
) -> None:
    provider = gateway_route_harness.provider
    device = asyncio.run(seed_device(provider))

    async def create_status_table() -> None:
        async with gateway_route_harness.engine.begin() as connection:
            await connection.run_sync(lambda sync: Base.metadata.create_all(
                sync, tables=[BrowserStatusCurrent.__table__],
            ))

    asyncio.run(create_status_table())
    app = create_app(gateway_route_harness.settings, provider)
    hello = agent_hello(device.id)
    hello.update(
        platform="windows_amd64", capabilities=[],
        protocol_features=["endpoint.browser-status.v1"],
    )
    report = _report()
    report["observed_at"] = datetime.now(UTC).isoformat()
    report["observation_id"] = str(uuid4())
    report["policy_id"] = str(report["policy_id"])
    frame = {
        "schema_version": "gateway_ws_envelope_v1", "kind": "browser_status_report",
        "sequence": 1, "payload": report,
    }
    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect("/agent/v1/connect", headers={
            "Authorization": f"Bearer {VALID_TOKEN}",
            "X-Forwarded-For": "192.168.101.20", "X-Forwarded-Proto": "https",
        }) as websocket:
            websocket.send_json({
                "schema_version": "gateway_ws_envelope_v1", "kind": "agent_hello",
                "sequence": 0, "payload": hello,
            })
            assert websocket.receive_json()["kind"] == "gateway_hello"
            websocket.send_json(frame)
            assert websocket.receive_json()["payload"]["code"] == "browser_status_disabled"

    async def count() -> int:
        async with provider() as session:
            return await session.scalar(select(func.count()).select_from(BrowserStatusCurrent))

    assert asyncio.run(count()) == 0


def test_route_persists_two_browser_facts_after_policy_ack(
    gateway_route_harness: GatewayRouteHarness,
) -> None:
    provider = gateway_route_harness.provider
    device = asyncio.run(seed_device(provider))

    async def seed_policy() -> None:
        async with gateway_route_harness.engine.begin() as connection:
            await connection.run_sync(lambda sync: Base.metadata.create_all(sync, tables=[
                PolicyDefinition.__table__, PolicyVersion.__table__,
                PolicyAssignment.__table__, PolicyDeviceState.__table__,
                PolicyApplication.__table__, BrowserStatusCurrent.__table__,
            ]))
        async with provider() as session:
            session.add(PolicyDefinition(id=POLICY_ID, name="Browser Default"))
            await session.flush()
            version = await create_policy_version(
                session, POLICY_ID, _policy(), actor_id=uuid4(),
            )
            await assign_default_policy(session, version.id, actor_id=uuid4())
            await session.commit()

    asyncio.run(seed_policy())
    settings = replace(gateway_route_harness.settings, endpoint_policy_enabled=True)
    app = create_app(settings, provider)
    hello = agent_hello(device.id)
    hello.update(
        platform="windows_amd64", capabilities=[],
        agent_version="3.2.70", launcher_version="3.2.70",
        protocol_features=["endpoint.policy.v1", "endpoint.browser-status.v1"],
    )
    now = datetime.now(UTC).isoformat()
    report = _report()
    report.update(
        policy_id=str(POLICY_ID), observed_at=now,
        observation_id=str(uuid4()),
    )

    async def rows() -> list[BrowserStatusCurrent]:
        async with provider() as session:
            return (await session.scalars(select(BrowserStatusCurrent))).all()

    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect("/agent/v1/connect", headers={
            "Authorization": f"Bearer {VALID_TOKEN}",
            "X-Forwarded-For": "192.168.101.20", "X-Forwarded-Proto": "https",
        }) as websocket:
            websocket.send_json({
                "schema_version": "gateway_ws_envelope_v1", "kind": "agent_hello",
                "sequence": 0, "payload": hello,
            })
            assert websocket.receive_json()["kind"] == "gateway_hello"
            delivery = websocket.receive_json()
            assert delivery["kind"] == "endpoint_policy_delivery"
            websocket.send_json({
                "schema_version": "gateway_ws_envelope_v1", "kind": "endpoint_policy_ack",
                "sequence": 1, "payload": {
                    "schema_version": "endpoint_policy_ack_v1",
                    "policy_id": str(POLICY_ID), "policy_version": 1,
                    "policy_digest": delivery["payload"]["policy_digest"],
                    "received_at": now, "applied_at": now, "status": "APPLIED",
                },
            })
            websocket.send_json({
                "schema_version": "gateway_ws_envelope_v1",
                "kind": "browser_status_report", "sequence": 2,
                "payload": report,
            })
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if {row.browser_family for row in asyncio.run(rows())} == {"chrome", "yandex"}:
                    break
                time.sleep(0.01)
            else:
                assert {row.browser_family for row in asyncio.run(rows())} == {"chrome", "yandex"}
