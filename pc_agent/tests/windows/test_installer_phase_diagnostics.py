"""Native failure context must be bounded and omit exception/private values."""
import json
import sys
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import installer_phase_diagnostics as diagnostics


@pytest.fixture
def event_sink(monkeypatch):
    calls = []
    closed = []
    api = SimpleNamespace(
        EVENTLOG_ERROR_TYPE=1,
        RegisterEventSource=lambda server, source: (server, source),
        ReportEvent=lambda *args: calls.append(args),
        DeregisterEventSource=lambda handle: closed.append(handle),
    )
    monkeypatch.setitem(sys.modules, "win32evtlog", api)
    return calls, closed, api


def native_error():
    namespace = {}
    exec(compile("def fail():\n raise ValueError('private-sentinel-password')\n",
                 "pc_agent/platform/windows/installer_fence.py", "exec"), namespace)
    try:
        namespace["fail"]()
    except ValueError as error:
        return error


def test_event_contains_source_frame_without_exception_values(event_sink):
    calls, closed, _ = event_sink
    diagnostics.report_installer_phase_failure("msi-enter", native_error())
    assert len(calls) == len(closed) == 1
    assert calls[0][:5] == ((None, "Endpoint Platform Installer"), 1, 0, 1001, None)
    text = calls[0][5][0]
    value = json.loads(text)
    assert value["schema_version"] == "endpoint_native_phase_failure_v1"
    assert value["phase"] == "msi-enter"
    assert value["exceptions"][0]["safe_code"] == "UNKNOWN"
    assert value["exceptions"][0]["frames"] == [
        {"file": "installer_fence.py", "function": "fail", "line": 2},
    ]
    assert "private-sentinel" not in text
    assert "pc_agent/" not in text
    assert calls[0][6] is None


@pytest.mark.parametrize("point", ["register", "write", "close"])
def test_failed_event_delivery_never_replaces_installer_result(event_sink, point):
    calls, closed, api = event_sink
    def fail(*args):
        raise OSError("private-event-error")
    setattr(api, {"register": "RegisterEventSource", "write": "ReportEvent", "close": "DeregisterEventSource"}[point], fail)
    diagnostics.report_installer_phase_failure("msi-enter", native_error())
    if point == "write":
        assert len(closed) == 1


def test_event_bounds_chained_errors_and_keeps_native_error_number(event_sink):
    calls, _, _ = event_sink
    cause = OSError("private-native-error")
    cause.winerror = 5
    native = cause
    for _ in range(20):
        next_error = ValueError("PROVENANCE_CONFLICT")
        next_error.__cause__ = cause
        cause = next_error
    diagnostics.report_installer_phase_failure("msi-enter", cause)
    value = json.loads(calls[0][5][0])
    assert len(value["exceptions"]) == 3
    assert len(calls[0][5][0].encode()) <= 8192
    error = ValueError("PROVENANCE_CONFLICT")
    error.__cause__ = native
    diagnostics.report_installer_phase_failure("msi-enter", error)
    assert json.loads(calls[1][5][0])["exceptions"][-1]["winerror"] == 5


def test_error_string_failure_does_not_escape_diagnostic(event_sink):
    calls, _, _ = event_sink
    class PrivateError(Exception):
        def __str__(self):
            raise RuntimeError("private-str-error")
    diagnostics.report_installer_phase_failure("msi-enter", PrivateError())
    value = json.loads(calls[0][5][0])
    assert value["exceptions"][0]["type"] == "Exception"
    assert value["exceptions"][0]["safe_code"] == "UNKNOWN"
