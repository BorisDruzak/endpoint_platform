"""Bounded local events for the nonproduction fixture; no runtime authority."""
from contextlib import contextmanager
import json
import re
import traceback

_remaining = 32
_enabled = False
_STAGES = frozenset({"authority_start", "authority_resolved", "authority_refused",
    "native_exception", "runtime_exception", "runtime_exit", *(
        "runtime_" + name for name in ("created", "starting", "connecting", "running",
            "reconnecting", "stopping", "stopped", "update_pending", "credential_rejected", "failed"))})
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_CONDITIONS = frozenset({"service_identity", "service_ancestry", "service_token",
    "fixed_image", "legacy_conflict", "legacy_product", "legacy_component",
    "legacy_component_path", "native_observation_unavailable", "image_acl",
    "thread_token_unavailable", "thread_impersonation", "unsupported_token",
    "logon_identity", "process_identity", "process_parent_unavailable",
    "process_not_live", "process_image_unavailable", "not_service_child",
    "noncanonical_image_path", "image_hardlink", "reparse_or_wrong_type",
    "unsupported_image_ace", "image_identity_changed", "changed_native_identity"})


def _write_event(value):
    import win32evtlog
    # The original installed service already owns this Application event source.
    # Do not install a source, registry value, service, task or audit policy.
    handle = win32evtlog.RegisterEventSource(None, "EndpointAgent")
    try:
        win32evtlog.ReportEvent(handle, win32evtlog.EVENTLOG_INFORMATION_TYPE,
            0, 62081, None, [value], None)
    finally:
        win32evtlog.DeregisterEventSource(handle)


def report_diagnostic(stage, *, error=None, exit_code=None):
    """Diagnostic failure must never change the fixture's original result."""
    global _remaining
    try:
        if not _enabled or stage not in _STAGES or _remaining <= 0:
            return
        _remaining -= 1
        value = {"schema": "fixture_diagnostic_v1", "stage": stage}
        if error is not None:
            kind = type(error).__name__
            if _NAME.fullmatch(kind):
                value["type"] = kind
            for field in ("winerror", "hresult"):
                number = getattr(error, field, None)
                if type(number) is int and -(2**31) <= number < 2**32:
                    value[field] = number
            if kind == "Rejected" and len(error.args) == 1 and error.args[0] in _CONDITIONS:
                value["condition"] = error.args[0]
            frames = []
            for frame in traceback.extract_tb(error.__traceback__)[-4:]:
                file = frame.filename.replace("\\", "/").rsplit("/", 1)[-1]
                if re.fullmatch(r"[A-Za-z0-9_.-]{1,90}", file) and (
                    _NAME.fullmatch(frame.name) or frame.name == "<module>"
                ):
                    frames.append({"file": file, "function": frame.name, "line": frame.lineno})
            if frames:
                value["frames"] = frames
        if type(exit_code) is int and -(2**31) <= exit_code < 2**32:
            value["exit_code"] = exit_code
        encoded = json.dumps(value, separators=(",", ":"))
        if len(encoded) <= 1024:
            _write_event(encoded)
    except Exception:
        pass


@contextmanager
def diagnostic_scope(enabled):
    global _enabled, _remaining
    before = _enabled, _remaining
    _enabled, _remaining = bool(enabled), 32
    try:
        yield
    finally:
        _enabled, _remaining = before


@contextmanager
def runtime_trace():
    """Delegate unchanged lifecycle transitions and restore the process-local hook."""
    from pc_agent.runtime.status import RuntimeStatus
    original = RuntimeStatus.transition

    def transition(self, phase, *, error=None):
        result = original(self, phase, error=error)
        try:
            report_diagnostic("runtime_" + phase.value, error=error)
        except Exception:
            pass
        return result

    RuntimeStatus.transition = transition
    try:
        yield
    finally:
        RuntimeStatus.transition = original
