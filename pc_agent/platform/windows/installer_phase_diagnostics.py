"""Bounded native-helper diagnostics, separate from installer authority."""
from __future__ import annotations

import json
import os
import re
from contextlib import contextmanager

from pc_agent.version import AGENT_VERSION

_CODES = frozenset({"UPDATE_IN_PROGRESS", "UPDATE_STATE_INVALID", "PROVENANCE_CONFLICT",
                    "OWNER_AUTH_FAILED", "MSI_EVIDENCE_FAILED", "RECOVERY_REQUIRED"})
_TYPES = frozenset({"OSError", "PermissionError", "TimeoutError", "ValueError", "RuntimeError",
                    "error", "AttributeError", "TypeError", "ImportError", "ModuleNotFoundError",
                    "FileNotFoundError"})


def _exception_context(error):
    try:
        detail = str(error)
    except Exception:
        detail = None
    code = detail if detail in _CODES else "UNKNOWN"
    frames = []
    trace = error.__traceback__
    for _ in range(64):
        if trace is None:
            break
        filename = trace.tb_frame.f_code.co_filename.replace("\\", "/")
        function = trace.tb_frame.f_code.co_name
        name = filename.rsplit("/", 1)[-1]
        if (("/pc_agent/platform/windows/" in "/" + filename or "/endpoint_contracts/" in "/" + filename)
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,59}\.py", name)
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", function)):
            frames.append({"file": name, "function": function, "line": trace.tb_lineno})
        trace = trace.tb_next
    native_code = getattr(error, "winerror", None)
    return {"type": type(error).__name__ if type(error).__name__ in _TYPES else "Exception",
            "safe_code": code,
            "winerror": native_code if type(native_code) is int and 0 <= native_code < 2**32 else None,
            "frames": frames[-6:]}


def report_installer_phase_failure(phase: str, error: BaseException) -> None:
    """Report bounded code locations; never messages, arguments, locals or paths.

    RegisterEventSource defaults an unknown source to Application without adding
    a registry source. This deliberately avoids NTEventLogHandler's registration
    and any write to installer state during a read-only or failed native phase.
    The event is diagnostic evidence and cannot authorize native completion.
    """
    handle = None
    try:
        exceptions = []
        seen = set()
        for _ in range(3):
            if error is None or id(error) in seen:
                break
            seen.add(id(error))
            exceptions.append(_exception_context(error))
            error = error.__cause__ or error.__context__
        value = {"schema_version": "endpoint_native_phase_failure_v1", "version": AGENT_VERSION,
                 "phase": phase if isinstance(phase, str) and re.fullmatch(r"[a-z][a-z-]{0,47}", phase) else "invalid",
                 "pid": os.getpid(), "exceptions": exceptions}
        payload = json.dumps(value, separators=(",", ":"), allow_nan=False)
        if len(payload.encode("utf-8")) > 8192:
            return
        import win32evtlog
        handle = win32evtlog.RegisterEventSource(None, "Endpoint Platform Installer")
        win32evtlog.ReportEvent(handle, win32evtlog.EVENTLOG_ERROR_TYPE, 0, 1001, None, [payload], None)
    except Exception:
        pass
    finally:
        if handle is not None:
            try:
                win32evtlog.DeregisterEventSource(handle)
            except Exception:
                pass


def _profiling_enabled(paths):
    """A protected, operator-created diagnostic switch; never grants authority."""
    try:
        from . import installer_fence as fence
        flag = fence.state_root(paths) / 'diagnostic-phase-timing.enabled'
        if not flag.exists():
            return False
        fence.assert_state_security(flag, secret=True)
        return flag.stat().st_size == 11 and flag.read_bytes() == b'profile-v1\n'
    except Exception:
        return False


def _report_phase_timing(phase, profile, seconds):
    handle = None
    try:
        functions = []
        for row in sorted(profile.getstats(), key=lambda item: item.inlinetime, reverse=True)[:24]:
            code = row.code
            filename = getattr(code, 'co_filename', '~').replace('\\', '/').rsplit('/', 1)[-1]
            name = getattr(code, 'co_name', code if isinstance(code, str) else 'unknown')
            functions.append({'file': re.sub(r'[^A-Za-z0-9_.~-]', '_', filename)[:96],
                'function': re.sub(r'[^A-Za-z0-9_ .<>-]', '_', name)[:120],
                'line': getattr(code, 'co_firstlineno', 0), 'calls': row.callcount,
                'self_seconds': round(row.inlinetime, 6), 'total_seconds': round(row.totaltime, 6)})
        value = {'schema_version': 'endpoint_native_phase_timing_v1', 'version': AGENT_VERSION,
            'phase': phase if isinstance(phase, str) and re.fullmatch(r'[a-z][a-z-]{0,47}', phase) else 'invalid',
            'pid': os.getpid(), 'seconds_with_profiling': round(seconds, 6), 'functions': functions}
        payload = json.dumps(value, separators=(',', ':'), allow_nan=False)
        if len(payload.encode('utf-8')) > 8192:
            return
        import win32evtlog
        handle = win32evtlog.RegisterEventSource(None, 'Endpoint Platform Installer')
        win32evtlog.ReportEvent(handle, win32evtlog.EVENTLOG_INFORMATION_TYPE, 0, 1002, None, [payload], None)
    except Exception:
        pass
    finally:
        if handle is not None:
            try:
                win32evtlog.DeregisterEventSource(handle)
            except Exception:
                pass


@contextmanager
def profile_installer_phase(phase, paths):
    """Opt-in self timing only: no attach, arguments, locals or result capture.

    The caller retains the full authenticated phase scope. Diagnostics cannot
    replace its exception/result, issue grants or authorize native completion.
    Measurements with this switch enabled are not performance acceptance.
    """
    profile = None
    try:
        if _profiling_enabled(paths):
            import cProfile
            import sys
            import time
            if sys.getprofile() is None:
                profile = cProfile.Profile()
                started = time.perf_counter()
                profile.enable()
    except Exception:
        if profile is not None:
            try:
                profile.disable()
            except Exception:
                pass
            profile = None
    try:
        yield
    finally:
        if profile is not None:
            try:
                profile.disable()
                _report_phase_timing(phase, profile, time.perf_counter() - started)
            except Exception:
                pass
