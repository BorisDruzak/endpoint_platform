"""Manual-only bounded diagnostics with redaction before output truncation."""

from __future__ import annotations

from datetime import datetime, timezone
import re

from endpoint_contracts.context import DeviceContextDiagnosticV1

from .probe import JOURNAL_COMMAND, PROCESS_COMMAND
from .stable_keys import bounded_text


DIAGNOSTIC_PROCESS_LIMIT = 64
DIAGNOSTIC_LOG_BYTES = 8192
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passphrase|token|secret|api[_-]?key|authorization|cookie)\s*([:=])\s*[^\s,;]+"
)


def collect_diagnostic(
    probe: object,
    *,
    reason: str,
    collected_at: datetime | None = None,
) -> DeviceContextDiagnosticV1:
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
    redacted = _SENSITIVE_ASSIGNMENT.sub(r"\1\2<redacted>", raw)
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
