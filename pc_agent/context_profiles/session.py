"""Bounded dynamic interactive-session context without credential material."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone

from endpoint_contracts.context import DeviceContextSessionV1


def collect_session(
    probe: object, *, collected_at: datetime | None = None
) -> DeviceContextSessionV1:
    """Return only an injected/native interactive session observation.

    A service account is not evidence of an interactive user.  Platforms that
    cannot provide a bounded session observation therefore report null/false.
    """
    value = _session_info(probe)
    return DeviceContextSessionV1(
        schema_version="device_context_v1",
        profile="session_v1",
        collected_at=collected_at or datetime.now(timezone.utc),
        sections={
            "current_user_login": value.get("current_user_login"),
            "interactive_session_present": bool(value.get("interactive_session_present")),
        },
        warnings=[] if value else ["probe_unavailable"],
    )


def _session_info(probe: object) -> Mapping[str, object]:
    candidate = getattr(probe, "session_info", None)
    if not callable(candidate):
        return {}
    try:
        value = candidate()
    except (OSError, ValueError, TimeoutError):
        return {}
    return value if isinstance(value, Mapping) else {}
