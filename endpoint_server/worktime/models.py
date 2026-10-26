"""WorkTime records have no Activity foreign keys or short telemetry retention."""
from datetime import date, datetime
from uuid import UUID

from sqlalchemy import Boolean, CheckConstraint, Date, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base
from endpoint_server.db.ownership import OwnershipRecord


class WorkState(Base):
    """One serialization row per confirmed person, shared across every device."""
    __tablename__ = 'worktime_state'
    __table_args__ = (CheckConstraint("status IN ('WORKING','BREAK','OFF_PC','ENDED')", name='ck_worktime_state_status'),)
    person_id: Mapped[UUID] = mapped_column(ForeignKey('confirmed_identities.person_id', ondelete='RESTRICT'), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), default='ENDED')
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notification_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    retention_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    records_expired_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PersonnelRecord(OwnershipRecord):
    person_id: Mapped[UUID] = mapped_column(ForeignKey('worktime_state.person_id', ondelete='RESTRICT'), index=True)
    actor_id: Mapped[UUID] = mapped_column()
    idempotency_key: Mapped[UUID] = mapped_column()
    fingerprint: Mapped[str] = mapped_column(String(64))


class WorkEvent(PersonnelRecord, Base):
    __tablename__ = 'worktime_events'
    __table_args__ = (UniqueConstraint('person_id', 'idempotency_key', name='uq_worktime_event_key'),
        CheckConstraint("status IN ('WORKING','BREAK','OFF_PC','ENDED')", name='ck_worktime_event_status'),
        Index('ix_worktime_event_person_time', 'person_id', 'occurred_at'))
    action: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Schedule(PersonnelRecord, Base):
    __tablename__ = 'worktime_schedules'
    __table_args__ = (UniqueConstraint('person_id', 'idempotency_key', name='uq_worktime_schedule_key'),)
    effective_from: Mapped[date] = mapped_column(Date)
    definition: Mapped[dict] = mapped_column(JSON)


class Category(OwnershipRecord, Base):
    __tablename__ = 'worktime_categories'
    code: Mapped[str] = mapped_column(String(40), unique=True)
    label: Mapped[str] = mapped_column(String(100))
    requires_comment: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class ExplanationRequest(OwnershipRecord, Base):
    __tablename__ = 'worktime_explanation_requests'
    __table_args__ = (UniqueConstraint('person_id', 'started_at', 'ended_at', name='uq_worktime_request_interval'),
        CheckConstraint('ended_at > started_at', name='ck_worktime_request_bounds'))
    person_id: Mapped[UUID] = mapped_column(ForeignKey('worktime_state.person_id', ondelete='RESTRICT'), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(32), default='measured_return')


class Explanation(PersonnelRecord, Base):
    __tablename__ = 'worktime_explanations'
    __table_args__ = (UniqueConstraint('person_id', 'idempotency_key', name='uq_worktime_explanation_key'),
        CheckConstraint('ended_at > started_at', name='ck_worktime_explanation_bounds'))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    category_code: Mapped[str] = mapped_column(String(40))
    comment: Mapped[str] = mapped_column(Text)
    request_id: Mapped[UUID | None] = mapped_column(ForeignKey('worktime_explanation_requests.id', ondelete='RESTRICT'), unique=True)


class Correction(PersonnelRecord, Base):
    __tablename__ = 'worktime_corrections'
    __table_args__ = (UniqueConstraint('person_id', 'idempotency_key', name='uq_worktime_correction_key'),
        CheckConstraint('ended_at > started_at', name='ck_worktime_correction_bounds'),
        CheckConstraint("status IN ('WORKING','BREAK','OFF_PC','ENDED')", name='ck_worktime_correction_status'))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text)


class Approval(OwnershipRecord, Base):
    __tablename__ = 'worktime_approvals'
    __table_args__ = (CheckConstraint("decision IN ('approved','rejected')", name='ck_worktime_approval_decision'),)
    correction_id: Mapped[UUID] = mapped_column(ForeignKey('worktime_corrections.id', ondelete='RESTRICT'), unique=True)
    actor_id: Mapped[UUID] = mapped_column()
    decision: Mapped[str] = mapped_column(String(16))
    comment: Mapped[str] = mapped_column(Text)
    idempotency_key: Mapped[UUID] = mapped_column(unique=True)
    fingerprint: Mapped[str] = mapped_column(String(64))


class ActivityBinding(OwnershipRecord, Base):
    """Explicit operator-verified temporal OS account mapping; never a login guess."""
    __tablename__ = 'worktime_activity_bindings'
    __table_args__ = (CheckConstraint('valid_until > valid_from', name='ck_worktime_binding_bounds'),
        Index('ix_worktime_binding_lookup', 'person_id', 'valid_from', 'valid_until'))
    person_id: Mapped[UUID] = mapped_column(ForeignKey('worktime_state.person_id', ondelete='RESTRICT'))
    device_id: Mapped[UUID] = mapped_column(ForeignKey('devices.id', ondelete='RESTRICT'))
    user_key: Mapped[str] = mapped_column(String(300))
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    verified_by: Mapped[UUID] = mapped_column()
    proof_reference: Mapped[str] = mapped_column(String(256))


class Audit(OwnershipRecord, Base):
    __tablename__ = 'worktime_audit'
    person_id: Mapped[UUID | None] = mapped_column(index=True)
    actor_id: Mapped[UUID] = mapped_column()
    action: Mapped[str] = mapped_column(String(64))
    record_id: Mapped[UUID] = mapped_column()


class RetentionPolicy(OwnershipRecord, Base):
    __tablename__ = 'worktime_retention_policies'
    __table_args__ = (CheckConstraint('retention_days IS NULL OR retention_days >= 1', name='ck_worktime_retention_days'),
        CheckConstraint('inactivity_threshold_seconds >= 1200',name='ck_worktime_inactivity_threshold'))
    actor_id: Mapped[UUID] = mapped_column()
    retention_days: Mapped[int | None] = mapped_column(Integer)
    inactivity_threshold_seconds: Mapped[int] = mapped_column(Integer, default=1200)
    rationale: Mapped[str] = mapped_column(Text)


class Timesheet(OwnershipRecord, Base):
    """Immutable approved monthly version, independent of live source retention."""
    __tablename__ = 'worktime_timesheets'
    __table_args__ = (
        UniqueConstraint('person_id','month','version',name='uq_worktime_timesheet_version'),
        UniqueConstraint('person_id','idempotency_key',name='uq_worktime_timesheet_key'),
        CheckConstraint('version >= 1',name='ck_worktime_timesheet_version'),
        CheckConstraint('finalized_by != person_id',name='ck_worktime_timesheet_independent'),
    )
    person_id: Mapped[UUID] = mapped_column(ForeignKey('worktime_state.person_id',ondelete='RESTRICT'),index=True)
    month: Mapped[date] = mapped_column(Date)
    version: Mapped[int] = mapped_column(Integer)
    timezone: Mapped[str] = mapped_column(String(64))
    finalized_by: Mapped[UUID] = mapped_column()
    finalized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)
    source_digest: Mapped[str] = mapped_column(String(64))
    totals: Mapped[dict] = mapped_column(JSON)
    idempotency_key: Mapped[UUID] = mapped_column()
    fingerprint: Mapped[str] = mapped_column(String(64))


class TimesheetDay(OwnershipRecord, Base):
    """Finalized daily totals and personnel annotations belonging to one version."""
    __tablename__ = 'worktime_timesheet_days'
    __table_args__ = (
        UniqueConstraint('timesheet_id','day',name='uq_worktime_timesheet_day'),
        CheckConstraint('work_seconds >= 0 AND work_seconds <= 86400',name='ck_worktime_timesheet_day_work'),
        CheckConstraint('off_pc_seconds >= 0 AND off_pc_seconds <= work_seconds',name='ck_worktime_timesheet_day_offpc'),
        CheckConstraint('break_seconds >= 0 AND break_seconds <= 86400',name='ck_worktime_timesheet_day_break'),
        CheckConstraint('scheduled_seconds >= 0 AND scheduled_seconds <= 86400',name='ck_worktime_timesheet_day_schedule'),
    )
    timesheet_id: Mapped[UUID] = mapped_column(ForeignKey('worktime_timesheets.id',ondelete='RESTRICT'),index=True)
    day: Mapped[date] = mapped_column(Date)
    work_seconds: Mapped[int] = mapped_column(Integer)
    off_pc_seconds: Mapped[int] = mapped_column(Integer)
    break_seconds: Mapped[int] = mapped_column(Integer)
    scheduled_seconds: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict] = mapped_column(JSON)
