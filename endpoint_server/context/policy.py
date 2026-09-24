"""Canonical server-owned retention periods and per-profile storage modes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Literal


RAW_CONTEXT_TTL = timedelta(hours=1)
OPERATION_RESULT_TTL = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class ContextRetentionPolicy:
    profile: str
    mode: Literal["current_previous_pinned", "hot", "diagnostic"]
    ttl: timedelta | None


CONTEXT_RETENTION_POLICIES = {
    "baseline_v1": ContextRetentionPolicy("baseline_v1", "current_previous_pinned", None),
    "inventory_v1": ContextRetentionPolicy("inventory_v1", "current_previous_pinned", None),
    "health_v1": ContextRetentionPolicy("health_v1", "hot", timedelta(hours=24)),
    "session_v1": ContextRetentionPolicy("session_v1", "hot", timedelta(hours=24)),
    "network_v1": ContextRetentionPolicy("network_v1", "hot", timedelta(hours=24)),
    "activity_v1": ContextRetentionPolicy("activity_v1", "hot", timedelta(hours=24)),
    "diagnostic_v1": ContextRetentionPolicy("diagnostic_v1", "diagnostic", timedelta(hours=24)),
}
