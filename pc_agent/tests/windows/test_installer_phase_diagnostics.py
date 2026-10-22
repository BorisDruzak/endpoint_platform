"""Native failure context must be bounded and omit exception/private values."""
import json
import os
import sys
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import installer_phase_diagnostics as diagnostics
from pc_agent.tests.windows.test_installer_fence import native_protected_root


@pytest.fixture
def event_sink(monkeypatch):
    calls = []
    closed = []
    api = SimpleNamespace(
        EVENTLOG_ERROR_TYPE=1,
        EVENTLOG_INFORMATION_TYPE=4,
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


def test_phase_timing_is_disabled_without_protected_opt_in(monkeypatch, event_sink, tmp_path):
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path/'Agent', tmp_path/'data/pending.json')
    with diagnostics.profile_installer_phase('reconcile', paths):
        pass
    assert event_sink[0] == []


def test_phase_timing_contains_only_bounded_code_locations(monkeypatch, event_sink, tmp_path):
    monkeypatch.setattr(diagnostics, '_profiling_enabled', lambda _: True)
    private = 'private-sentinel-password'
    with diagnostics.profile_installer_phase('reconcile', None):
        assert private.upper() != private
    calls, closed, _ = event_sink
    assert len(calls) == len(closed) == 1
    assert calls[0][1:4] == (4, 0, 1002)
    raw = calls[0][5][0]
    value = json.loads(raw)
    assert value['schema_version'] == 'endpoint_native_phase_timing_v1'
    assert value['phase'] == 'reconcile'
    assert len(raw.encode()) <= 8192
    assert 'private-sentinel' not in raw and str(tmp_path) not in raw
    assert len(value['functions']) <= 24
    assert all(set(row) == {'file','function','line','calls','self_seconds','total_seconds'}
               for row in value['functions'])


def test_timing_delivery_failure_preserves_original_exception(monkeypatch, event_sink):
    monkeypatch.setattr(diagnostics, '_profiling_enabled', lambda _: True)
    def broken(*args):
        raise OSError('private-event-error')
    event_sink[2].ReportEvent = broken
    error = ValueError('original')
    with pytest.raises(ValueError) as observed:
        with diagnostics.profile_installer_phase('prepare', None):
            raise error
    assert observed.value is error


def test_untrusted_timing_flag_cannot_enable_profiling(monkeypatch, tmp_path):
    from pc_agent.platform.windows import installer_fence as fence
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path/'Agent', tmp_path/'data/pending.json')
    root = fence.state_root(paths);root.mkdir()
    (root/'diagnostic-phase-timing.enabled').write_bytes(b'profile-v1\n')
    monkeypatch.setattr(fence, 'assert_state_security', lambda *a, **kw: (_ for _ in ()).throw(ValueError()))
    assert diagnostics._profiling_enabled(paths) is False


def test_timing_export_failure_cannot_replace_phase_error(monkeypatch):
    monkeypatch.setattr(diagnostics, '_profiling_enabled', lambda _: True)
    def broken(*args):
        raise RuntimeError('diagnostic-export-error')
    monkeypatch.setattr(diagnostics, '_report_phase_timing', broken)
    error = ValueError('original')
    with pytest.raises(ValueError) as observed:
        with diagnostics.profile_installer_phase('prepare', None):
            raise error
    assert observed.value is error


def test_timing_initialization_failure_still_runs_body(monkeypatch):
    monkeypatch.setattr(diagnostics, '_profiling_enabled', lambda _: True)
    def broken():
        raise RuntimeError('diagnostic-start-error')
    monkeypatch.setitem(sys.modules, 'cProfile', SimpleNamespace(Profile=broken))
    entered = False
    with diagnostics.profile_installer_phase('prepare', None):
        entered = True
    assert entered


@pytest.mark.skipif(os.name != 'nt', reason='real protected ProgramFiles diagnostic switch')
def test_only_exact_private_native_flag_enables_timing(native_protected_root):
    from pc_agent.platform.windows import installer_fence as fence
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(native_protected_root/'Agent', native_protected_root/'data/pending.json')
    root = fence.state_root(paths);root.mkdir()
    fence.protect_state(root)
    flag = root/'diagnostic-phase-timing.enabled'
    flag.write_bytes(b'profile-v1\n');fence.protect_state(flag, secret=True)
    assert diagnostics._profiling_enabled(paths) is True
    flag.write_bytes(b'not-enabled')
    assert diagnostics._profiling_enabled(paths) is False
