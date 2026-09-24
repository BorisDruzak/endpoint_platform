"""Event Log profiles bound the sensitive read surface."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError


def test_event_query_rejects_arbitrary_channel_and_excessive_bounds() -> None:
    from endpoint_contracts.eventlog_primitives import EventQueryParametersV1

    good = dict(schema_version="eventlog_query_parameters_v1", profile="system", lookback_minutes=60, severity="error", max_events=32)
    assert EventQueryParametersV1.model_validate(good).max_events == 32
    for change in ({"profile": "Security"}, {"channel": "Security"}, {"lookback_minutes": 61}, {"max_events": 33}, {"severity": "critical-or-anything"}):
        with pytest.raises(ValidationError):
            EventQueryParametersV1.model_validate({**good, **change})


def test_event_summary_excludes_raw_message_and_xml() -> None:
    from endpoint_contracts.eventlog_primitives import EventFactV1

    good = dict(timestamp=datetime.now(UTC), severity="error", event_id=123, provider="System", message_code="event_123")
    assert EventFactV1.model_validate(good).event_id == 123
    for private in ({"message": "user secret"}, {"raw_xml": "<secret/>"}):
        with pytest.raises(ValidationError):
            EventFactV1.model_validate({**good, **private})


def test_eventlog_descriptors_advertise_only_implemented_platform() -> None:
    from endpoint_contracts.capabilities import MODULE_CAPABILITY_REGISTRY

    for capability in ("eventlog.query", "eventlog.recent_errors"):
        descriptor = MODULE_CAPABILITY_REGISTRY[capability].metadata
        assert descriptor.policy == "event_profile"
        assert descriptor.platforms == ["windows_amd64"]
