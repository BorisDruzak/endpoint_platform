"""Compact, content-free measured intervals and durable daily rollups."""
from datetime import date, datetime
from uuid import UUID

from sqlalchemy import Boolean, CheckConstraint, Date, DateTime, ForeignKey, Index, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base
from endpoint_server.db.ownership import OwnershipRecord


class ActivityInterval(OwnershipRecord, Base):
    __tablename__ = 'activity_intervals'
    __table_args__ = (
        CheckConstraint('ended_at >= started_at', name='ck_activity_interval_bounds'),
        CheckConstraint("session_state IN ('ACTIVE','IDLE','LOCKED','DISCONNECTED','UNKNOWN')", name='ck_activity_interval_state'),
        Index('ix_activity_intervals_user_time', 'user_key', 'started_at', 'ended_at'),
        Index('ix_activity_intervals_device_time', 'device_id', 'started_at'),
        Index('ix_activity_intervals_retention', 'ended_at', 'id'),
    )
    device_id: Mapped[UUID] = mapped_column(ForeignKey('devices.id', ondelete='CASCADE'))
    user_key: Mapped[str | None] = mapped_column(String(300))
    user_login: Mapped[str | None] = mapped_column(String(256))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    session_state: Mapped[str] = mapped_column(String(16))
    process_name: Mapped[str | None] = mapped_column(String(128))
    application_category: Mapped[str | None] = mapped_column(String(32))
    browser_family: Mapped[str | None] = mapped_column(String(32))
    policy_version_id: Mapped[UUID | None] = mapped_column()


class ActivityCursor(OwnershipRecord, Base):
    __tablename__ = 'activity_cursors'
    __table_args__ = (UniqueConstraint('device_id', name='uq_activity_cursor_device'),
                      Index('ix_activity_cursor_user', 'user_key'),)
    device_id: Mapped[UUID] = mapped_column(ForeignKey('devices.id', ondelete='CASCADE'))
    user_key: Mapped[str | None] = mapped_column(String(300))
    user_login: Mapped[str | None] = mapped_column(String(256))
    interval_id: Mapped[UUID | None] = mapped_column(ForeignKey('activity_intervals.id', ondelete='SET NULL'))
    observation_id: Mapped[UUID] = mapped_column()
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    session_state: Mapped[str] = mapped_column(String(16))


class ActivityDaily(OwnershipRecord, Base):
    __tablename__ = 'activity_daily'
    __table_args__ = (
        UniqueConstraint('user_key', 'timezone', 'day', name='uq_activity_daily_user_zone_day'),
        Index('ix_activity_daily_report', 'timezone', 'day', 'user_key'),
        Index('ix_activity_daily_dirty', 'dirty', 'updated_at'),
    )
    user_key: Mapped[str] = mapped_column(String(300))
    timezone: Mapped[str] = mapped_column(String(64))
    day: Mapped[date] = mapped_column(Date)
    dirty: Mapped[bool] = mapped_column(Boolean, default=True, server_default='true')
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
