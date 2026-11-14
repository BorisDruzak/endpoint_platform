"""Summary of one bounded event deletion batch."""

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class EventRetentionBatch:
    deleted: int
    oldest_due_age_seconds: float

    @classmethod
    def from_deleted(cls, timestamps: list[datetime], *, cutoff: datetime) -> "EventRetentionBatch":
        if not timestamps:
            return cls(0, 0.0)
        oldest = min(timestamps)
        # SQLite stores the server's UTC timestamps without their offset.
        oldest = oldest.replace(tzinfo=UTC) if oldest.tzinfo is None else oldest
        cutoff = cutoff.replace(tzinfo=UTC) if cutoff.tzinfo is None else cutoff
        return cls(len(timestamps), max(0.0, (cutoff - oldest).total_seconds()))
