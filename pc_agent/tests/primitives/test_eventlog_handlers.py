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


def test_unknown_platform_event_query_is_explicitly_unsupported() -> None:
    from pc_agent.primitives.eventlog.handlers import event_query

    result = event_query(
        EventQueryParametersV1(schema_version="eventlog_query_parameters_v1", profile="system", lookback_minutes=30, severity="error", max_events=10),
        query_profile=lambda profile: [],
        platform_name="other",
    )
    assert result.status == "failed" and result.error_code == "eventlog_unsupported"


def test_linux_event_query_uses_existing_safe_contract() -> None:
    from pc_agent.primitives.eventlog.handlers import event_query

    result = event_query(
        EventQueryParametersV1(schema_version="eventlog_query_parameters_v1", profile="system", lookback_minutes=30, severity="error", max_events=10),
        query_profile=lambda _: [{"timestamp": datetime.now(UTC), "severity": "error", "event_id": 3, "provider": "cups.service", "message": "private document"}],
        platform_name="linux",
    )
    assert result.status == "succeeded" and result.event_count == 1
    assert "private" not in result.model_dump_json()


def test_linux_journal_never_requests_messages_and_projects_metadata(monkeypatch) -> None:
    import json
    from pc_agent.platform.linux import journal

    def run(argv, timeout, limit, *, check_exit):
        assert argv[0] == "journalctl" and check_exit
        assert "--output-fields=__REALTIME_TIMESTAMP,PRIORITY,_SYSTEMD_UNIT,_TRANSPORT" in argv
        assert "MESSAGE" not in " ".join(argv)
        assert "--lines=64" in argv and "--priority=0..3" in argv
        assert timeout <= 10 and limit <= 65536
        return (json.dumps({"__REALTIME_TIMESTAMP": str(int(datetime.now(UTC).timestamp() * 1000000)), "PRIORITY": "3", "_SYSTEMD_UNIT": "cups.service", "MESSAGE": "secret"}) + "\n").encode()

    monkeypatch.setattr(journal, "_execute_bounded_command", run)
    rows = journal.query_profile("print")
    assert len(rows) == 1 and rows[0]["provider"] == "cups.service"
    assert "secret" not in str(rows) and "MESSAGE" not in str(rows)


def test_linux_journal_rejects_truncated_invalid_and_untrusted_metadata(monkeypatch) -> None:
    import pytest
    from pc_agent.platform.linux import journal

    for output in (b"{" * 65536, b"not json\n", b'{"PRIORITY":["3","6"]}\n'):
        monkeypatch.setattr(journal, "_execute_bounded_command", lambda *a, **k: output)
        with pytest.raises(ValueError):
            journal.query_profile("system")


def test_linux_journal_unknown_profile_is_rejected_before_running(monkeypatch) -> None:
    import pytest
    from pc_agent.platform.linux import journal

    monkeypatch.setattr(journal, "_execute_bounded_command", lambda *a, **k: pytest.fail("invalid query executed"))
    with pytest.raises(ValueError):
        journal.query_profile("system --all")
