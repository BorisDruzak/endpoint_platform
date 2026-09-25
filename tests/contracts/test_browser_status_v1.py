"""Browser health is two independent bounded facts, never Agent compliance."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4
import json

import pytest
from pydantic import ValidationError

from endpoint_contracts.browser_status import BrowserStatusReportV1
from endpoint_contracts.gateway_ws import AgentHelloV1, GatewayWsEnvelopeV1
from endpoint_server.gateway.protocol import parse_agent_envelope


NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)


def _family(family: str) -> dict[str, object]:
    return {
        "browser_family": family,
        "browser_state": "DETECTED",
        "running_state": "CLOSED",
        "policy_owner": "ENDPOINT",
        "installation_policy_state": "APPLIED",
        "native_host_state": "READY",
        "extension_version": None,
        "extension_last_seen_at": None,
        "last_running_at": None,
    }


def _report() -> dict[str, object]:
    return {
        "schema_version": "browser_status_report_v1",
        "observation_id": uuid4(),
        "policy_id": uuid4(),
        "policy_version": 1,
        "observed_at": NOW,
        "browsers": [_family("chrome"), _family("yandex")],
    }


def test_report_keeps_chrome_and_yandex_separate_and_strict() -> None:
    report = BrowserStatusReportV1.model_validate(_report())
    assert [item.browser_family for item in report.browsers] == ["chrome", "yandex"]
    assert report.browsers[0].extension_last_seen_at is None
    assert "compliance" not in report.model_dump()
    bad = _report()
    bad["browsers"][0]["document_title"] = "secret"
    with pytest.raises(ValidationError, match="document_title"):
        BrowserStatusReportV1.model_validate(bad)


@pytest.mark.parametrize("case", ["extra", "duplicate", "absent_running"])
def test_report_rejects_duplicate_or_inconsistent_browser_facts(case: str) -> None:
    value = _report()
    if case == "extra":
        value["browsers"].append(_family("chrome"))
    elif case == "duplicate":
        value["browsers"][1] = _family("chrome")
    else:
        value["browsers"][0]["browser_state"] = "ABSENT"
        value["browsers"][0]["running_state"] = "RUNNING"
    with pytest.raises(ValidationError):
        BrowserStatusReportV1.model_validate(value)


def test_extension_heartbeat_requires_version_and_cannot_be_in_future() -> None:
    value = _report()
    value["browsers"][0]["extension_last_seen_at"] = NOW + timedelta(minutes=6)
    with pytest.raises(ValidationError):
        BrowserStatusReportV1.model_validate(value)
    value["browsers"][0]["extension_last_seen_at"] = NOW
    with pytest.raises(ValidationError):
        BrowserStatusReportV1.model_validate(value)
    value["browsers"][0]["extension_version"] = "0.1.0"
    assert BrowserStatusReportV1.model_validate(value).browsers[0].extension_version == "0.1.0"


def test_report_requires_timezone_aware_observation() -> None:
    value = _report()
    value["observed_at"] = NOW.replace(tzinfo=None)
    with pytest.raises(ValidationError):
        BrowserStatusReportV1.model_validate(value)


def test_status_is_a_separately_negotiated_typed_gateway_frame() -> None:
    hello = AgentHelloV1.model_validate({
        "schema_version": "agent_hello_v1",
        "device_id": uuid4(), "agent_instance_id": uuid4(),
        "agent_version": "3.2.70", "launcher_version": "3.2.70",
        "platform": "windows_amd64", "boot_id": "browser-status-test",
        "capabilities": [], "last_result_sequence": 0, "last_policy_revision": 0,
        "protocol_features": ["endpoint.browser-status.v1"],
    })
    assert hello.protocol_features == ["endpoint.browser-status.v1"]
    envelope = GatewayWsEnvelopeV1.model_validate({
        "schema_version": "gateway_ws_envelope_v1", "sequence": 1,
        "kind": "browser_status_report", "payload": _report(),
    })
    assert envelope.root.kind == "browser_status_report"
    parsed = parse_agent_envelope(
        json.dumps(envelope.model_dump(mode="json")), maximum_message_bytes=65536,
    )
    assert parsed.kind == "browser_status_report"
