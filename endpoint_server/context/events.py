"""Bounded context change facts that survive snapshot retention."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from uuid import uuid4

from .models import ContextSnapshot, DeviceEvent


def events_for_change(
    before: ContextSnapshot | None,
    after: ContextSnapshot,
    *,
    diff: object | None = None,
) -> list[DeviceEvent]:
    if before is None:
        return []
    codes: list[str] = []
    if after.profile in {"baseline_v1", "inventory_v1"} and diff is not None:
        codes = [change.code for change in diff.changes]
    elif after.profile == "network_v1":
        codes = ["NETWORK_CHANGED"]
    elif after.profile == "session_v1":
        old = before.normalized_projection.get("sections", {})
        new = after.normalized_projection.get("sections", {})
        if isinstance(old, Mapping) and isinstance(new, Mapping):
            old_present = bool(old.get("interactive_session_present"))
            new_present = bool(new.get("interactive_session_present"))
            if not old_present and new_present:
                codes = ["SESSION_STARTED"]
            elif old_present and not new_present:
                codes = ["SESSION_ENDED"]
            elif old.get("current_user_login") != new.get("current_user_login"):
                codes = ["SESSION_USER_CHANGED"]
    events = []
    for code in dict.fromkeys(codes):
        source_key = f"context:{after.id.hex}:{code}"
        events.append(DeviceEvent(
            id=uuid4(), device_id=after.device_id,
            event_identifier=source_key, event_kind=code,
            category="context", profile=after.profile,
            occurred_at=after.collected_at, source_key=source_key,
            summary_code=code, details={},
            before_hash=before.semantic_hash, after_hash=after.semantic_hash,
        ))
    return events


__all__ = ["events_for_change"]
