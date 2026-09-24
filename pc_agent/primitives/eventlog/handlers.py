"""Fixed Windows Event Log profiles; never collect message or raw XML."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
import json
import os
import re
import subprocess

from pydantic import ValidationError

from endpoint_contracts.eventlog_primitives import (
    EventFactV1,
    EventQueryParametersV1,
    EventQueryResultV1,
    RecentErrorsParametersV1,
    RecentErrorsResultV1,
)
from pc_agent.primitives.service_printer.handlers import _powershell


def _fixed_script(channel: str) -> str:
    # Called only for literal, Agent-owned channels below. No command content
    # depends on a Gateway parameter.
    return (
        "$log=Get-WinEvent -ListLog '" + channel +
        "' -ErrorAction Stop;if(-not $log.IsEnabled){throw 'eventlog_disabled'};"
        "$items=@(Get-WinEvent -FilterHashtable @{LogName='" + channel +
        "';StartTime=(Get-Date).AddMinutes(-60)} -MaxEvents 200 -ErrorAction SilentlyContinue "
        "| ForEach-Object {[pscustomobject]@{timestamp=$_.TimeCreated.ToUniversalTime().ToString('o');"
        "level=[int]$_.Level;event_id=[int]$_.Id;provider=[string]$_.ProviderName}});"
        "ConvertTo-Json -InputObject $items -Depth 3 -Compress"
    )


_PROFILE_SCRIPTS = {
    "system": _fixed_script("System"),
    "application": _fixed_script("Application"),
    "print": _fixed_script("Microsoft-Windows-PrintService/Operational"),
    "endpoint": _fixed_script("Application"),
}
_LEVELS = {1: "error", 2: "error", 3: "warning", 4: "information"}


def _windows_profile(profile: str) -> list[dict[str, object]]:
    value = json.loads(_powershell(_PROFILE_SCRIPTS[profile], limit=65536))
    if not isinstance(value, list):
        raise ValueError("invalid Event Log metadata shape")
    return [row for row in value if isinstance(row, dict)]


def _safe_event(raw: dict[str, object]) -> EventFactV1 | None:
    try:
        stamp = raw.get("timestamp")
        when = stamp if isinstance(stamp, datetime) else datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
        level = raw.get("level")
        severity = raw.get("severity") if raw.get("severity") in {"error", "warning", "information"} else _LEVELS.get(level)
        if severity is None:
            return None
        event_id = int(raw.get("event_id"))
        if event_id < 0 or event_id > 2**32 - 1:
            return None
        provider = re.sub(r"[\x00-\x1f\x7f]", "", str(raw.get("provider") or "")).strip()[:128] or "unknown"
        return EventFactV1(
            timestamp=when, severity=severity, event_id=event_id,
            provider=provider, message_code=f"event_{event_id}",
        )
    except (TypeError, ValueError, OverflowError, ValidationError):
        return None


def _select(
    raw_events: list[dict[str, object]], *, profile: str, lookback_minutes: int,
    severity: str, maximum: int, now: datetime,
) -> list[EventFactV1]:
    since = now - timedelta(minutes=lookback_minutes)
    events: list[EventFactV1] = []
    for raw in raw_events[:200]:
        event = _safe_event(raw)
        if event is None or event.timestamp < since or event.timestamp > now + timedelta(minutes=1):
            continue
        if profile == "endpoint" and "endpoint" not in event.provider.casefold():
            continue
        if event.severity != severity:
            continue
        events.append(event)
        if len(events) >= maximum:
            break
    return events


def event_query(
    parameters: EventQueryParametersV1,
    *, query_profile: Callable[[str], list[dict[str, object]]] = _windows_profile,
    platform_name: str | None = None,
) -> EventQueryResultV1:
    now = datetime.now(UTC)
    if (platform_name or ("windows" if os.name == "nt" else "linux")) != "windows":
        return EventQueryResultV1(schema_version="eventlog_query_result_v1", event_count=0, status="failed", error_code="eventlog_unsupported", collected_at=now)
    try:
        events = _select(
            query_profile(parameters.profile), profile=parameters.profile,
            lookback_minutes=parameters.lookback_minutes,
            severity=parameters.severity, maximum=parameters.max_events, now=now,
        )
        return EventQueryResultV1(schema_version="eventlog_query_result_v1", events=events, event_count=len(events), status="succeeded", collected_at=now)
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return EventQueryResultV1(schema_version="eventlog_query_result_v1", event_count=0, status="failed", error_code="eventlog_query_failed", collected_at=now)


def recent_errors(
    parameters: RecentErrorsParametersV1,
    *, query_profile: Callable[[str], list[dict[str, object]]] = _windows_profile,
    platform_name: str | None = None,
) -> RecentErrorsResultV1:
    now = datetime.now(UTC)
    if (platform_name or ("windows" if os.name == "nt" else "linux")) != "windows":
        return RecentErrorsResultV1(schema_version="eventlog_recent_errors_result_v1", event_count=0, status="failed", error_code="eventlog_unsupported", collected_at=now)
    try:
        events = _select(
            query_profile(parameters.profile), profile=parameters.profile,
            lookback_minutes=parameters.lookback_minutes,
            severity="error", maximum=20, now=now,
        )
        return RecentErrorsResultV1(schema_version="eventlog_recent_errors_result_v1", events=events, event_count=len(events), status="succeeded", collected_at=now)
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return RecentErrorsResultV1(schema_version="eventlog_recent_errors_result_v1", event_count=0, status="failed", error_code="eventlog_query_failed", collected_at=now)
