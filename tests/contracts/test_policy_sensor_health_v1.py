"""Policy sensor health is bounded local evidence, never Agent compliance."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from endpoint_contracts.sensor_health import PolicySensorHealthReportV1
from endpoint_contracts.gateway_ws import AgentHelloV1, GatewayWsEnvelopeV1


NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)


def _report() -> dict[str, object]:
    return {
        "schema_version": "policy_sensor_health_report_v1",
        "observation_id": uuid4(), "policy_id": uuid4(), "policy_version": 1,
        "observed_at": NOW,
        "activity_listener_state": "READY",
        "user_sensor_last_seen_at": NOW - timedelta(seconds=15),
        "security_spool_state": "READY",
        "usb_source_state": "READY", "print_source_state": "READY",
    }


def test_report_has_only_bounded_sensor_facts_and_typed_wss_envelope() -> None:
    report = PolicySensorHealthReportV1.model_validate(_report())
    assert report.user_sensor_last_seen_at == NOW - timedelta(seconds=15)
    assert "compliance" not in report.model_dump()
    envelope = GatewayWsEnvelopeV1.model_validate({
        "schema_version": "gateway_ws_envelope_v1", "sequence": 1,
        "kind": "policy_sensor_health_report", "payload": _report(),
    })
    assert envelope.root.kind == "policy_sensor_health_report"


def test_sensor_health_is_a_fifth_distinct_negotiated_feature() -> None:
    hello = {
        "schema_version": "agent_hello_v1",
        "device_id": uuid4(), "agent_instance_id": uuid4(),
        "agent_version": "3.2.70", "launcher_version": "3.2.70",
        "platform": "windows_amd64", "boot_id": "sensor-health-test",
        "capabilities": [], "last_result_sequence": 0, "last_policy_revision": 0,
        "protocol_features": [
            "endpoint.policy.v1", "endpoint.activity.v1",
            "endpoint.security-events.v1", "endpoint.browser-status.v1",
            "endpoint.sensor-health.v1",
        ],
    }
    assert len(AgentHelloV1.model_validate(hello).protocol_features) == 5
    with pytest.raises(ValidationError):
        AgentHelloV1.model_validate({
            **hello,
            "protocol_features": hello["protocol_features"] + ["endpoint.sensor-health.v1"],
        })


@pytest.mark.parametrize("field,value", [
    ("activity_listener_state", "ACTIVE"),
    ("usb_source_state", "secret"),
    ("policy_version", 0),
    ("observed_at", NOW.replace(tzinfo=None)),
    ("user_sensor_last_seen_at", NOW + timedelta(minutes=6)),
])
def test_report_rejects_invalid_or_unbounded_facts(field: str, value: object) -> None:
    payload = _report()
    payload[field] = value
    with pytest.raises(ValidationError):
        PolicySensorHealthReportV1.model_validate(payload)
    payload = _report()
    payload["clipboard_text"] = "forbidden"
    with pytest.raises(ValidationError, match="clipboard_text"):
        PolicySensorHealthReportV1.model_validate(payload)
