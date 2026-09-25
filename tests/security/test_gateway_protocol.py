"""Gateway accepts only negotiated, bounded Agent SecurityEvent envelopes."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from endpoint_server.gateway.protocol import GatewayProtocolError, parse_agent_envelope


def _security_envelope() -> dict[str, object]:
    return {
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
                    "occurred_at": datetime(2026, 9, 25, tzinfo=UTC).isoformat(),
                    "policy_id": str(uuid4()),
                    "policy_version": 1,
                    "safe_metadata": {"removable": True},
                }
            ],
        },
    }


def test_gateway_protocol_accepts_typed_security_batch() -> None:
    raw = json.dumps(_security_envelope())
    assert (
        parse_agent_envelope(raw, maximum_message_bytes=65536).kind
        == "security_event_batch"
    )


def test_gateway_protocol_rejects_oversize_security_frame() -> None:
    raw = json.dumps(_security_envelope())
    with pytest.raises(GatewayProtocolError) as error:
        parse_agent_envelope(raw, maximum_message_bytes=len(raw.encode("utf-8")) - 1)
    assert error.value.close_code == 1009


def test_security_envelope_has_its_own_64_kib_wire_limit() -> None:
    raw = json.dumps(_security_envelope()) + (" " * 65536)
    with pytest.raises(GatewayProtocolError) as error:
        parse_agent_envelope(raw, maximum_message_bytes=1024 * 1024)
    assert error.value.close_code == 1009
