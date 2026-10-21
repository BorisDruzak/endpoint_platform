"""Fixed journald profiles: request only metadata, never MESSAGE or command lines."""
from __future__ import annotations

from datetime import UTC, datetime
import json
import re

from pc_agent.context_profiles.probe import _execute_bounded_command

_LIMIT = 65536
_PROFILES = {
    "system": (),
    "application": ("_TRANSPORT=stdout", "+", "_TRANSPORT=syslog"),
    "print": ("--unit=cups.service",),
    "endpoint": ("--unit=endpoint-agent.service",),
}
_UNIT = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")


def query_profile(profile: str, *, severity: str = "error") -> list[dict[str, object]]:
    priorities = {"error": "0..3", "warning": "4", "information": "5..6"}
    if profile not in _PROFILES or severity not in priorities:
        raise ValueError("JOURNAL_PROFILE_INVALID")
    raw = _execute_bounded_command((
        "journalctl", "--system", "--no-pager", "--quiet", "--output=json",
        "--output-fields=__REALTIME_TIMESTAMP,PRIORITY,_SYSTEMD_UNIT,_TRANSPORT",
        "--since=-60min", f"--priority={priorities[severity]}", "--lines=64", "--reverse",
        *_PROFILES[profile],
    ), 8.0, _LIMIT, check_exit=True)
    if len(raw) >= _LIMIT:
        raise ValueError("JOURNAL_OUTPUT_LIMIT")
    rows: list[dict[str, object]] = []
    for line in raw.decode("utf-8", errors="strict").splitlines():
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("JOURNAL_ROW_INVALID")
        stamp, priority = value.get("__REALTIME_TIMESTAMP"), value.get("PRIORITY")
        if not isinstance(stamp, str) or not stamp.isascii() or not stamp.isdigit() or len(stamp) > 20 or priority not in tuple(str(n) for n in range(8)):
            raise ValueError("JOURNAL_METADATA_INVALID")
        severity = "error" if int(priority) <= 3 else "warning" if priority == "4" else "information"
        provider = value.get("_SYSTEMD_UNIT")
        if not isinstance(provider, str) or _UNIT.fullmatch(provider) is None:
            provider = "kernel" if value.get("_TRANSPORT") == "kernel" else "system-journal"
        # Instance names may contain user-controlled identifiers. Retain only
        # the service template instead of a potentially private instance value.
        provider = re.sub(r"@.*(?=\.[^.]+$)", "@", provider)
        rows.append({
            "timestamp": datetime.fromtimestamp(int(stamp) / 1000000, UTC),
            "severity": severity, "event_id": 0, "provider": provider,
            "message_code": f"journal_priority_{priority}",
        })
    return rows
