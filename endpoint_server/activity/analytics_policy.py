"""Server-only retention and calendar configuration; never enables sensors."""
from dataclasses import dataclass
from typing import Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


@dataclass(frozen=True, slots=True)
class AnalyticsPolicy:
    detail_days: int = 14
    aggregate_days: int = 90
    max_gap_seconds: int = 45
    organization_timezone: str = 'Asia/Yekaterinburg'

    def __post_init__(self):
        if not 1 <= self.detail_days <= 90:
            raise ValueError('ACTIVITY_ANALYTICS_DETAIL_DAYS must be between 1 and 90')
        if not self.detail_days <= self.aggregate_days <= 365:
            raise ValueError('ACTIVITY_ANALYTICS_AGGREGATE_DAYS must cover detail retention and be <= 365')
        if not 15 <= self.max_gap_seconds <= 60:
            raise ValueError('ACTIVITY_ANALYTICS_MAX_GAP_SECONDS must be between 15 and 60')
        try:
            ZoneInfo(self.organization_timezone)
        except (ValueError, ZoneInfoNotFoundError) as error:
            raise ValueError('ACTIVITY_ANALYTICS_TIMEZONE must be an IANA timezone') from error

    @property
    def timezones(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((self.organization_timezone, 'UTC')))

    @classmethod
    def from_environment(cls, values: Mapping[str, str]):
        return cls(
            detail_days=int(values.get('ACTIVITY_ANALYTICS_DETAIL_DAYS', '14')),
            aggregate_days=int(values.get('ACTIVITY_ANALYTICS_AGGREGATE_DAYS', '90')),
            max_gap_seconds=int(values.get('ACTIVITY_ANALYTICS_MAX_GAP_SECONDS', '45')),
            organization_timezone=values.get('ACTIVITY_ANALYTICS_TIMEZONE', 'Asia/Yekaterinburg'),
        )
