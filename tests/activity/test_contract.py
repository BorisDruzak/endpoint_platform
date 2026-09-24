"""The activity wire format carries state and bounded identities, never content."""

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from endpoint_contracts.activity import ActivityObservationV1
from endpoint_contracts.gateway_ws import GatewayWsEnvelopeV1
from endpoint_server.gateway.protocol import GatewayProtocolError, parse_agent_envelope


def _payload() -> dict[str, object]:
    return {
        "schema_version": "activity_observation_v1",
        "observation_id": str(uuid4()),
        "observed_at": datetime(2026, 9, 25, tzinfo=UTC).isoformat(),
        "user_login": "ivanova.aa",
        "session_state": "ACTIVE",
        "idle_seconds": 48,
        "foreground": {"process_name": "chrome.exe", "application_category": "browser"},
        "browser": None,
    }


@pytest.mark.parametrize("state", ["ACTIVE", "IDLE", "LOCKED", "DISCONNECTED", "UNKNOWN"])
def test_activity_states_are_typed(state: str) -> None:
    data = _payload()
    data["session_state"] = state
    if state not in {"ACTIVE", "IDLE"}:
        data["idle_seconds"] = None
        data["foreground"] = None
    assert ActivityObservationV1.model_validate(data).session_state == state


@pytest.mark.parametrize("field,value", [
    ("window_title", "Secret document"),
    ("query", "password=secret"),
    ("path", "/private"),
])
def test_content_fields_are_rejected(field: str, value: str) -> None:
    data = _payload()
    data[field] = value
    with pytest.raises(ValidationError):
        ActivityObservationV1.model_validate(data)


@pytest.mark.parametrize("name", ["C:\\Windows\\calc.exe", "/usr/bin/chrome", "chrome.exe\nsecret"])
def test_foreground_is_a_process_name_not_a_path_or_title(name: str) -> None:
    data = _payload()
    data["foreground"]["process_name"] = name
    with pytest.raises(ValidationError):
        ActivityObservationV1.model_validate(data)


@pytest.mark.parametrize("origin", [
    "https://example.test/private", "https://example.test/?token=secret",
    "https://user:secret@example.test", "file:///private",
])
def test_browser_origin_excludes_content_and_credentials(origin: str) -> None:
    data = _payload()
    data["browser"] = {
        "browser_family": "chrome", "origin": origin, "domain": "example.test",
        "sensor_state": "ACTIVE", "extension_version": "1.0.0",
        "last_seen_at": data["observed_at"],
    }
    with pytest.raises(ValidationError):
        ActivityObservationV1.model_validate(data)


def test_activity_envelope_is_agent_direction_and_strict() -> None:
    frame = {"schema_version": "gateway_ws_envelope_v1", "kind": "activity_observation",
             "sequence": 1, "payload": _payload()}
    encoded = GatewayWsEnvelopeV1.model_validate(frame).model_dump_json()
    assert parse_agent_envelope(encoded, maximum_message_bytes=16384).payload.session_state == "ACTIVE"
    frame["payload"]["window_title"] = "secret"
    with pytest.raises(GatewayProtocolError):
        parse_agent_envelope(json.dumps(frame), maximum_message_bytes=16384)
