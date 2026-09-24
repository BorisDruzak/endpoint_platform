"""Event Log projection keeps metadata and drops messages/XML."""

from __future__ import annotations

from datetime import UTC, datetime

from endpoint_contracts.eventlog_primitives import EventQueryParametersV1, RecentErrorsParametersV1


def test_event_query_filters_and_projects_only_safe_metadata() -> None:
    from pc_agent.primitives.eventlog.handlers import event_query

    now = datetime.now(UTC)
    rows = [{"timestamp": now.isoformat(), "severity": "error", "event_id": 123, "provider": "Service", "message": "password=secret", "raw_xml": "<secret/>"}]
    result = event_query(
        EventQueryParametersV1(schema_version="eventlog_query_parameters_v1", profile="system", lookback_minutes=30, severity="error", max_events=32),
        query_profile=lambda profile: rows,
        platform_name="windows",
    )
    assert result.status == "succeeded" and result.event_count == 1
    payload = str(result.model_dump(mode="json"))
    assert "secret" not in payload
    assert "raw_xml" not in payload
    assert result.events[0].message_code == "event_123"


def test_recent_errors_caps_results_at_twenty() -> None:
    from pc_agent.primitives.eventlog.handlers import recent_errors

    now = datetime.now(UTC)
    rows = [{"timestamp": now.isoformat(), "severity": "error", "event_id": n, "provider": "Service"} for n in range(100)]
    result = recent_errors(
        RecentErrorsParametersV1(schema_version="eventlog_recent_errors_parameters_v1", profile="system", lookback_minutes=60),
        query_profile=lambda profile: rows,
        platform_name="windows",
    )
    assert result.event_count == 20


def test_alt_event_query_is_explicitly_unsupported() -> None:
    from pc_agent.primitives.eventlog.handlers import event_query

    result = event_query(
        EventQueryParametersV1(schema_version="eventlog_query_parameters_v1", profile="system", lookback_minutes=30, severity="error", max_events=10),
        query_profile=lambda profile: [],
        platform_name="linux",
    )
    assert result.status == "failed" and result.error_code == "eventlog_unsupported"
