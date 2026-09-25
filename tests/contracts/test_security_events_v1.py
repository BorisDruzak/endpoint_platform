"""SecurityEvent transport accepts only bounded audit metadata."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from endpoint_contracts.gateway_ws import GatewayInboundV1, GatewayWsEnvelopeV1
from endpoint_contracts.security_events import (
    AgentSecurityEventBatchV1,
    SecurityEventAckV1,
)


NOW = datetime(2026, 9, 25, tzinfo=timezone.utc)


def _event(event_type: str, metadata: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "security_event_v1",
        "event_identifier": str(uuid4()),
        "event_type": event_type,
        "channel": {
            "USB_DEVICE_CONNECTED": "USB",
            "USB_DEVICE_DISCONNECTED": "USB",
            "PRINT_JOB": "PRINT",
            "BROWSER_UPLOAD": "BROWSER",
            "BROWSER_PASTE": "BROWSER",
        }[event_type],
        "severity": "INFO",
        "occurred_at": NOW,
        "user_login": "ivanova.aa",
        "policy_id": str(uuid4()),
        "policy_version": 1,
        "safe_metadata": metadata,
    }


def _batch(event: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "agent_security_event_batch_v1",
        "batch_id": str(uuid4()),
        "events": [event],
    }


@pytest.mark.parametrize(
    ("event_type", "metadata"),
    [
        (
            "USB_DEVICE_CONNECTED",
            {
                "vendor": "Acme",
                "product": "Drive",
                "device_class": "mass_storage",
                "removable": True,
                "serial_hash": "a" * 64,
            },
        ),
        ("USB_DEVICE_DISCONNECTED", {"device_class": "other", "removable": False}),
        ("PRINT_JOB", {"printer_identity": "Office-1", "page_count": 2, "copies": 1}),
        (
            "BROWSER_UPLOAD",
            {
                "domain": "example.org",
                "origin": "https://example.org",
                "browser_family": "chrome",
                "file_count": 2,
                "total_bytes": 100,
                "mime_categories": ["document"],
            },
        ),
        (
            "BROWSER_PASTE",
            {
                "domain": "example.org",
                "origin": "https://example.org",
                "browser_family": "yandex",
                "clipboard_types": ["text"],
            },
        ),
    ],
)
def test_event_types_have_bounded_metadata(
    event_type: str, metadata: dict[str, object]
) -> None:
    parsed = AgentSecurityEventBatchV1.model_validate(
        _batch(_event(event_type, metadata))
    )
    assert parsed.events[0].event_type == event_type


@pytest.mark.parametrize(
    ("event_type", "metadata", "forbidden"),
    [
        ("USB_DEVICE_CONNECTED", {"removable": True}, "descriptor"),
        ("PRINT_JOB", {"printer_identity": "Office-1"}, "document_name"),
        (
            "BROWSER_UPLOAD",
            {
                "domain": "example.org",
                "origin": "https://example.org",
                "browser_family": "chrome",
                "file_count": 1,
                "total_bytes": 0,
                "mime_categories": ["other"],
            },
            "file_name",
        ),
        (
            "BROWSER_PASTE",
            {
                "domain": "example.org",
                "origin": "https://example.org",
                "browser_family": "chrome",
                "clipboard_types": ["text"],
            },
            "clipboard_value",
        ),
    ],
)
def test_event_metadata_rejects_content_and_unknown_fields(
    event_type: str, metadata: dict[str, object], forbidden: str
) -> None:
    metadata[forbidden] = "PRIVATE-MARKER"
    with pytest.raises(ValidationError):
        AgentSecurityEventBatchV1.model_validate(_batch(_event(event_type, metadata)))


def test_batch_rejects_unknown_fields_duplicate_ids_and_over_50_events() -> None:
    event = _event("USB_DEVICE_CONNECTED", {"removable": True})
    for invalid in (
        {**_batch(event), "raw_transport": "PRIVATE-MARKER"},
        {**_batch(event), "events": [event, event]},
        {
            **_batch(event),
            "events": [{**event, "event_identifier": str(uuid4())} for _ in range(51)],
        },
    ):
        with pytest.raises(ValidationError):
            AgentSecurityEventBatchV1.model_validate(invalid)


def test_event_cannot_claim_wrong_channel_or_arbitrary_severity() -> None:
    event = _event("PRINT_JOB", {"printer_identity": "Office-1"})
    for field, value in (("channel", "BROWSER"), ("severity", "CRITICAL")):
        with pytest.raises(ValidationError):
            AgentSecurityEventBatchV1.model_validate(_batch({**event, field: value}))


def test_browser_event_requires_normalized_origin_without_path() -> None:
    event = _event(
        "BROWSER_PASTE",
        {
            "domain": "example.org",
            "origin": "https://example.org/private",
            "browser_family": "chrome",
            "clipboard_types": ["text"],
        },
    )
    with pytest.raises(ValidationError):
        AgentSecurityEventBatchV1.model_validate(_batch(event))


def test_ack_has_bounded_unique_persisted_identifiers() -> None:
    event_id = uuid4()
    ack = SecurityEventAckV1(
        schema_version="security_event_ack_v1",
        batch_id=uuid4(),
        event_identifiers=[event_id],
        persisted_at=NOW,
    )
    assert ack.event_identifiers == [event_id]
    with pytest.raises(ValidationError):
        SecurityEventAckV1(
            schema_version="security_event_ack_v1",
            batch_id=uuid4(),
            event_identifiers=[event_id, event_id],
            persisted_at=NOW,
        )


def test_security_batch_and_ack_have_distinct_gateway_envelopes() -> None:
    event = _event("USB_DEVICE_CONNECTED", {"removable": True})
    batch = _batch(event)
    parsed = GatewayWsEnvelopeV1.model_validate(
        {
            "schema_version": "gateway_ws_envelope_v1",
            "sequence": 1,
            "kind": "security_event_batch",
            "payload": batch,
        }
    )
    assert (
        parsed.root.payload.batch_id
        == AgentSecurityEventBatchV1.model_validate(batch).batch_id
    )
    ack = {
        "schema_version": "security_event_ack_v1",
        "batch_id": batch["batch_id"],
        "event_identifiers": [event["event_identifier"]],
        "persisted_at": NOW,
    }
    inbound = GatewayInboundV1.model_validate(
        {
            "schema_version": "gateway_ws_envelope_v1",
            "sequence": 2,
            "kind": "security_event_ack",
            "payload": ack,
        }
    )
    assert inbound.root.payload.event_identifiers == [
        AgentSecurityEventBatchV1.model_validate(batch).events[0].event_identifier
    ]
    with pytest.raises(ValidationError):
        GatewayInboundV1.model_validate(
            {
                "schema_version": "gateway_ws_envelope_v1",
                "sequence": 1,
                "kind": "security_event_batch",
                "payload": batch,
            }
        )
