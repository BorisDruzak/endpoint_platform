"""Bounded administrative analytics request and response contracts."""
from datetime import date, datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

State = Literal['ACTIVE', 'IDLE', 'LOCKED', 'DISCONNECTED', 'UNKNOWN']


class Model(BaseModel):
    model_config = ConfigDict(extra='forbid')


class ReportQuery(Model):
    period: Literal['today', 'yesterday', '7d', '30d', 'custom'] = 'today'
    since: date | None = None
    until: date | None = None
    timezone: str | None = Field(default=None, max_length=64)


class Application(Model):
    label: str
    category: str
    seconds: float


class Metrics(Model):
    seconds: dict[State, float]
    observed_span_seconds: float
    coverage: float | None
    applications: list[Application]
    categories: dict[str, float]
    overlap_seconds: float
    pending: bool
    updated_at: datetime | None


class DeviceInfo(Model):
    id: str
    name: str
    online: bool


class Employee(Model):
    user_key: str | None
    user_login: str | None
    devices: list[DeviceInfo]
    state: State
    fresh: bool
    last_observed_at: datetime | None
    metrics: Metrics | None
    reason: str | None = None


class Meta(Model):
    today: date
    since: date
    until: date
    timezone: str
    timezones: list[str]
    detail_available_from: date
    aggregate_available_from: date
    max_gap_seconds: int
    generated_at: datetime
    collection_enabled: bool


class Overview(Model):
    data: list[Employee]
    total: int
    offset: int
    limit: int
    summary: dict[str, int]
    meta: Meta


class Daily(Model):
    day: date
    metrics: Metrics | None
    timeline_available: bool


class UserReport(Model):
    data: Employee
    daily: list[Daily]
    meta: Meta


class Segment(Model):
    started_at: datetime
    ended_at: datetime
    seconds: float
    state: State
    process_name: str | None
    application_category: str | None
    device_id: str | None
    overlap: bool
    attributed: bool


class ConnectionGap(Model):
    device_id: str
    started_at: datetime
    ended_at: datetime


class Timeline(Model):
    day: date
    timezone: str
    started_at: datetime
    ended_at: datetime
    data: list[Segment]
    connection_gaps: list[ConnectionGap]
    devices: list[DeviceInfo]
    limited_session_identity: bool = True
