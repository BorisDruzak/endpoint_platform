"""Manual-only bounded diagnostics with redaction before output truncation."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import re

from endpoint_contracts.context import DeviceContextDiagnosticV1

from .probe import JOURNAL_COMMAND, PROCESS_COMMAND
from .stable_keys import bounded_text


DIAGNOSTIC_PROCESS_LIMIT = 64
DIAGNOSTIC_LOG_BYTES = 8192
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passphrase|token|secret|api[_-]?key|cookie)\s*([:=])\s*[^\s,;]+"
)
_BEARER_AUTHORIZATION = re.compile(r"(?i)\bauthorization\s*([:=])\s*bearer\s+[^\s,;]+")
_OTHER_AUTHORIZATION = re.compile(r"(?i)\bauthorization\s*([:=])(?!\s*bearer\b)[^\r\n,;]+")


def collect_diagnostic(
    probe: object,
    *,
    reason: str,
    collected_at: datetime | None = None,
) -> DeviceContextDiagnosticV1:
    if _is_windows(probe):
        return _collect_windows_diagnostic(probe, reason=reason, collected_at=collected_at)
    warnings: list[str] = []
    processes = _processes(probe, warnings)
    log_excerpt = _log_excerpt(probe, warnings)
    return DeviceContextDiagnosticV1(
        schema_version="device_context_v1",
        profile="diagnostic_v1",
        collected_at=collected_at or datetime.now(timezone.utc),
        sections={
            "reason": bounded_text(reason, fallback="manual diagnostic", limit=256),
            "processes": processes,
            "log_excerpt": log_excerpt,
        },
        warnings=list(dict.fromkeys(warnings))[:16],
    )


def _collect_windows_diagnostic(
    probe: object,
    *,
    reason: str,
    collected_at: datetime | None,
) -> DeviceContextDiagnosticV1:
    warnings: list[str] = []
    return DeviceContextDiagnosticV1(
        schema_version="device_context_v1",
        profile="diagnostic_v1",
        collected_at=collected_at or datetime.now(timezone.utc),
        sections={
            "reason": bounded_text(reason, fallback="manual diagnostic", limit=256),
            "processes": _windows_processes(probe, warnings),
            "log_excerpt": None,
        },
        warnings=list(dict.fromkeys(warnings))[:16],
    )


def _windows_processes(probe: object, warnings: list[str]) -> list[dict[str, str]]:
    command = ("tasklist", "/FO", "CSV", "/NH")
    try:
        output = str(probe.run(command, 2.0, 32_768))
    except TimeoutError:
        warnings.append("command_timed_out")
        return []
    except (OSError, ValueError):
        warnings.append("command_failed")
        return []
    try:
        rows = list(csv.reader(output.splitlines()))
    except csv.Error:
        warnings.append("command_failed")
        return []
    if len(rows) > DIAGNOSTIC_PROCESS_LIMIT:
        warnings.append("data_truncated")
    return [
        {"name": bounded_text(row[0] if row else "", fallback="unknown", limit=128), "state": "running"}
        for row in rows[:DIAGNOSTIC_PROCESS_LIMIT]
        if row
    ]


def _is_windows(probe: object) -> bool:
    from pc_agent.platform.windows.identity import is_windows_context

    return is_windows_context(probe)


def _processes(probe: object, warnings: list[str]) -> list[dict[str, str]]:
    try:
        output = str(probe.run(PROCESS_COMMAND, 2.0, 32_768))
    except TimeoutError:
        warnings.append("command_timed_out")
        return []
    except (OSError, ValueError):
        warnings.append("command_failed")
        return []
    records: list[dict[str, str]] = []
    for line in output.splitlines():
        fields = line.split(maxsplit=1)
        if not fields:
            continue
        records.append(
            {
                "name": bounded_text(fields[0], fallback="unknown", limit=128),
                "state": _process_state(fields[1] if len(fields) > 1 else ""),
            }
        )
    if len(records) > DIAGNOSTIC_PROCESS_LIMIT:
        warnings.append("data_truncated")
    return records[:DIAGNOSTIC_PROCESS_LIMIT]


def _process_state(value: str) -> str:
    code = value[:1].upper()
    if code == "R":
        return "running"
    if code in {"S", "I", "D"}:
        return "sleeping"
    if code in {"T", "Z"}:
        return "stopped"
    return "unknown"


def _log_excerpt(probe: object, warnings: list[str]) -> str | None:
    try:
        raw = str(probe.run(JOURNAL_COMMAND, 2.0, DIAGNOSTIC_LOG_BYTES * 2))
    except TimeoutError:
        warnings.append("command_timed_out")
        return None
    except (OSError, ValueError):
        warnings.append("command_failed")
        return None
    redacted = _BEARER_AUTHORIZATION.sub(r"Authorization\1 Bearer <redacted>", raw)
    redacted = _OTHER_AUTHORIZATION.sub(r"Authorization\1<redacted>", redacted)
    redacted = _SENSITIVE_ASSIGNMENT.sub(r"\1\2<redacted>", redacted)
    if redacted != raw:
        warnings.append("redaction_applied")
    excerpt, truncated = _truncate_utf8(redacted, DIAGNOSTIC_LOG_BYTES)
    if truncated:
        warnings.append("data_truncated")
    return excerpt or None


def _truncate_utf8(value: str, limit: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True
