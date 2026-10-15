"""Diagnostic output must preserve behavior and exclude exception contents."""
import importlib,json

import pytest


def diagnostics():
    name = "tools.canary.fixtures.diagnostics"
    assert importlib.util.find_spec(name) is not None, "fixture diagnostics is missing"
    return importlib.import_module(name)


@pytest.fixture(autouse=True)
def local_sink_only(monkeypatch):
    module = diagnostics()
    native_writer = module._write_event
    monkeypatch.setattr(module, "_enabled", True, raising=False)
    monkeypatch.setattr(module, "_write_event", lambda value: None)
    return native_writer


def test_calls_outside_fixture_scope_never_write_native_events(monkeypatch):
    module = diagnostics()
    events = []
    monkeypatch.setattr(module, "_enabled", False, raising=False)
    monkeypatch.setattr(module, "_write_event", events.append)
    module.report_diagnostic("authority_start")
    assert events == []


def test_event_schema_is_bounded_and_never_serializes_exception_message(monkeypatch):
    module = diagnostics()
    events = []
    monkeypatch.setattr(module, "_write_event", events.append)
    monkeypatch.setattr(module, "_remaining", 32)
    error = OSError("private token password credential contents")
    error.winerror = 5
    module.report_diagnostic("authority_refused", error=error)
    assert len(events) == 1
    value = json.loads(events[0])
    assert value == {"schema": "fixture_diagnostic_v1", "stage": "authority_refused", "type": "OSError", "winerror": 5}
    assert len(events[0]) < 1024 and "private" not in events[0]
    module.report_diagnostic("password from arbitrary input", error=error)
    assert len(events) == 1


def test_sink_failure_and_event_limit_never_change_execution(monkeypatch):
    module = diagnostics()
    events = []
    monkeypatch.setattr(module, "_remaining", 2)
    def fail(value):
        events.append(value)
        raise OSError("private sink failure")
    monkeypatch.setattr(module, "_write_event", fail)
    for _ in range(50):
        module.report_diagnostic("authority_start")
    assert len(events) == 2


def test_runtime_trace_delegates_original_status_and_restores_method(monkeypatch):
    module = diagnostics()
    from pc_agent.runtime.status import RuntimePhase, RuntimeStatus
    events = []
    monkeypatch.setattr(module, "_write_event", events.append)
    monkeypatch.setattr(module, "_remaining", 32)
    original = RuntimeStatus.transition
    error = PermissionError("private runtime content")
    with module.runtime_trace():
        state = RuntimeStatus()
        state.transition(RuntimePhase.FAILED, error=error)
        assert state.phase is RuntimePhase.FAILED and state.last_error == "PermissionError"
    assert RuntimeStatus.transition is original
    assert json.loads(events[0])["stage"] == "runtime_failed"
    assert "private" not in events[0]


def test_runtime_trace_restores_original_on_exception(monkeypatch):
    module = diagnostics()
    from pc_agent.runtime.status import RuntimeStatus
    monkeypatch.setattr(module, "_write_event", lambda value: None)
    original = RuntimeStatus.transition
    with pytest.raises(RuntimeError, match="unchanged"):
        with module.runtime_trace():
            raise RuntimeError("unchanged")
    assert RuntimeStatus.transition is original


def test_diagnostic_phase_formatting_cannot_change_original_transition():
    module = diagnostics()
    from pc_agent.runtime.status import RuntimeStatus
    marker = object()
    with module.runtime_trace():
        state = RuntimeStatus()
        state.transition(marker)
        assert state.phase is marker


def test_native_event_handle_closes_even_if_report_fails(monkeypatch, local_sink_only):
    from types import SimpleNamespace
    import sys
    closed = []
    def fail(*args):
        raise OSError("unchanged native error")
    monkeypatch.setitem(sys.modules, "win32evtlog", SimpleNamespace(
        EVENTLOG_INFORMATION_TYPE=4, RegisterEventSource=lambda host, name: 17,
        ReportEvent=fail, DeregisterEventSource=closed.append))
    with pytest.raises(OSError, match="unchanged native error"):
        local_sink_only('{"schema":"fixture_diagnostic_v1"}')
    assert closed == [17]
