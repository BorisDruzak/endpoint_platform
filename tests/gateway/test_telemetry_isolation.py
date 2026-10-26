"""Optional domain failures leave heartbeat and command delivery on the same WSS."""
import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from endpoint_server.db.base import Base
from endpoint_server.db.models import DeviceSession
from endpoint_server.context.models import ContextCollection, ContextSnapshot
from endpoint_server.main import create_app
from endpoint_server.policy.models import (
    BrowserStatusCurrent, PolicyApplication, PolicyAssignment, PolicyDefinition,
    PolicyDeviceState, PolicySensorHealthCurrent, PolicyVersion,
)
from endpoint_server.policy.service import assign_default_policy, create_policy_version
from endpoint_server.security.models import SecurityEvent
from tests.contracts.test_browser_status_v1 import _report
from tests.contracts.test_endpoint_policy_v1 import POLICY_ID, _policy
from .test_sensor_health_route import _frame
from .conftest import FixedWebSocketPeerApp, VALID_TOKEN, agent_hello, seed_device


@pytest.mark.parametrize("negotiated", [False, True])
@pytest.mark.parametrize("failure", ["stale", "future", "policy_mismatch"])
@pytest.mark.parametrize("kind,feature,model", [
    ("activity_observation", "endpoint.activity.v1", ContextSnapshot),
    ("browser_status_report", "endpoint.browser-status.v1", BrowserStatusCurrent),
    ("policy_sensor_health_report", "endpoint.sensor-health.v1", PolicySensorHealthCurrent),
    ("security_event_batch", "endpoint.security-events.v1", SecurityEvent),
])
def test_rejection_keeps_session_for_heartbeat_and_command(
    gateway_route_harness, kind, feature, model, failure, negotiated,
):
    harness = gateway_route_harness
    device = asyncio.run(seed_device(harness.provider))

    async def prepare():
        async with harness.engine.begin() as connection:
            await connection.run_sync(lambda sync: Base.metadata.create_all(sync, tables=[
                PolicyDefinition.__table__, PolicyVersion.__table__, PolicyAssignment.__table__,
                PolicyDeviceState.__table__, PolicyApplication.__table__,
                BrowserStatusCurrent.__table__, PolicySensorHealthCurrent.__table__,
                SecurityEvent.__table__,
            ]))
        async with harness.provider() as session:
            session.add(PolicyDefinition(id=POLICY_ID, name="Isolation test"))
            await session.flush()
            version = await create_policy_version(session, POLICY_ID, _policy(), actor_id=uuid4())
            await assign_default_policy(session, version.id, actor_id=uuid4())
            await session.commit()
    asyncio.run(prepare())
    app = create_app(replace(harness.settings, endpoint_policy_enabled=True), harness.provider)
    hello = agent_hello(device.id)
    hello.update(platform="windows_amd64", agent_version="3.2.149", capabilities=["context.health.collect"],
                 protocol_features=["endpoint.policy.v1", feature] + (
                     ["endpoint.telemetry-results.v1"] if negotiated else []))
    now = datetime.now(UTC)
    observed = now + ({"stale": -timedelta(hours=25), "future": timedelta(minutes=10)}.get(failure, timedelta()))
    if kind == "activity_observation":
        payload = {"schema_version": "activity_observation_v1", "observation_id": str(uuid4()),
                   "observed_at": observed.isoformat(), "user_login": "test", "session_state": "ACTIVE", "idle_seconds": 2}
    elif kind == "browser_status_report":
        payload = _report()
        payload.update(policy_id=str(POLICY_ID), observation_id=str(uuid4()), observed_at=observed.isoformat())
    elif kind == "security_event_batch":
        payload = {"schema_version": "agent_security_event_batch_v1", "batch_id": str(uuid4()), "events": [{
            "schema_version": "security_event_v1", "event_identifier": str(uuid4()), "event_type": "USB_DEVICE_CONNECTED",
            "channel": "USB", "severity": "INFO", "occurred_at": observed.isoformat(), "policy_id": str(POLICY_ID),
            "policy_version": 2 if failure == "policy_mismatch" else 1, "safe_metadata": {"removable": True},
        }]}
    else:
        payload = _frame(observed.isoformat())["payload"]
    if failure == "policy_mismatch" and kind not in {"activity_observation", "security_event_batch"}:
        payload["policy_version"] = 2

    async def inspect_session(session_id):
        async with harness.provider() as session:
            row = await session.get(DeviceSession, session_id)
            return row.last_seen_at, row.closed_at, await session.scalar(select(func.count()).select_from(model))

    with TestClient(FixedWebSocketPeerApp(app)) as client:
        with client.websocket_connect("/agent/v1/connect", headers={
            "Authorization": f"Bearer {VALID_TOKEN}", "X-Forwarded-For": "192.168.101.20", "X-Forwarded-Proto": "https",
        }) as socket:
            def send(kind, payload, sequence):
                socket.send_json({"schema_version": "gateway_ws_envelope_v1", "kind": kind, "sequence": sequence, "payload": payload})
            send("agent_hello", hello, 0)
            greeting = socket.receive_json()
            assert greeting["kind"] == "gateway_hello"
            assert greeting["payload"].get("protocol_features", []) == (["endpoint.telemetry-results.v1"] if negotiated else [])
            if not negotiated:
                assert "protocol_features" not in greeting["payload"]
            from uuid import UUID
            session_id = UUID(greeting["payload"]["session_id"])
            delivery = socket.receive_json()
            send("endpoint_policy_ack", {
                "schema_version": "endpoint_policy_ack_v1", "policy_id": str(POLICY_ID), "policy_version": 1,
                "policy_digest": delivery["payload"]["policy_digest"], "received_at": now.isoformat(),
                "applied_at": now.isoformat() if failure != "policy_mismatch" else None,
                "status": "APPLIED" if failure != "policy_mismatch" else "ERROR",
                "error_code": None if failure != "policy_mismatch" else "POLICY_CONFLICT",
            }, 1)
            before = asyncio.run(inspect_session(session_id))[0]
            send(kind, payload, 2)
            if negotiated:
                result = socket.receive_json()
                assert result["kind"] == "telemetry_result"
                assert result["payload"]["report_id"] == payload.get("observation_id", payload.get("batch_id"))
                assert result["payload"]["report_sequence"] == 2
                assert result["payload"]["report_kind"] == kind
                assert result["payload"]["disposition"] == "rejected"
            # Request a supported context command only after rejecting telemetry.
            async def queue_command():
                async with harness.provider() as session:
                    session.add(ContextCollection(id=uuid4(), device_id=device.id, profile="health_v1", requested_by="isolation-test",
                        idempotency_key=str(uuid4()), status="requested", requested_at=datetime.now(UTC)))
                    await session.commit()
            asyncio.run(queue_command())
            send("heartbeat", {"schema_version": "agent_heartbeat_v1", "device_id": str(device.id), "platform": "windows",
                               "agent_version": "3.2.149", "reported_at": datetime.now(UTC).isoformat()}, 3)
            command = socket.receive_json()
            assert command["kind"] == "command"
            assert command["payload"]["capability"] == "context.health.collect"
            send("agent_hello", hello, 4)
            assert socket.receive_json()["payload"]["code"] == "unexpected_message"
            after, _, count = asyncio.run(inspect_session(session_id))
            assert after > before
            assert count == 0
