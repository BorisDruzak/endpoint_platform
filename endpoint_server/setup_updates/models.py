"""Setup update ownership is separate from both Core OTA and enrollment media."""
from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, JSON, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base
from endpoint_server.db.ownership import OwnershipRecord


class SetupRelease(OwnershipRecord, Base):
    __tablename__ = 'setup_update_releases'
    release_identifier: Mapped[str] = mapped_column(String(128), unique=True)
    version: Mapped[str] = mapped_column(String(64))
    artifact_name: Mapped[str] = mapped_column(String(256), unique=True)
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(BigInteger)
    source_revision: Mapped[str] = mapped_column(String(40))
    msi_sha256: Mapped[str] = mapped_column(String(64))
    tray_sha256: Mapped[str] = mapped_column(String(64))
    sensor_sha256: Mapped[str] = mapped_column(String(64))


class SetupClientPresence(OwnershipRecord, Base):
    __tablename__ = 'setup_update_clients'
    device_id: Mapped[UUID] = mapped_column(ForeignKey('devices.id', ondelete='CASCADE'), unique=True)
    client_version: Mapped[str] = mapped_column(String(32))
    foundation_version: Mapped[str | None] = mapped_column(String(64))
    core_version: Mapped[str | None] = mapped_column(String(64))
    ready: Mapped[bool] = mapped_column(Boolean)
    safe_code: Mapped[str | None] = mapped_column(String(128))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SetupAssignment(OwnershipRecord, Base):
    __tablename__ = 'setup_update_assignments'
    __table_args__ = (
        Index('uq_setup_update_active_device', 'device_id', unique=True,
              postgresql_where=text("status IN ('assigned','downloading','verified','installing','verifying','recovery_required')"),
              sqlite_where=text("status IN ('assigned','downloading','verified','installing','verifying','recovery_required')")),
    )
    device_id: Mapped[UUID] = mapped_column(ForeignKey('devices.id', ondelete='CASCADE'), index=True)
    release_id: Mapped[UUID] = mapped_column(ForeignKey('setup_update_releases.id'))
    status: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(String(256))
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_id: Mapped[UUID | None] = mapped_column()
    safe_code: Mapped[str | None] = mapped_column(String(128))
    last_report: Mapped[dict | None] = mapped_column(JSON)
    source_foundation_version: Mapped[str | None] = mapped_column(String(64))
    source_core_version: Mapped[str | None] = mapped_column(String(64))
    source_client_version: Mapped[str | None] = mapped_column(String(32))


class SetupPreparation(OwnershipRecord, Base):
    __tablename__ = 'setup_update_preparations'
    __table_args__ = (Index('uq_setup_preparation_active_device', 'device_id', unique=True,
        postgresql_where=text("status IN ('preparing_client','restoring_core')"),
        sqlite_where=text("status IN ('preparing_client','restoring_core')")),)
    device_id: Mapped[UUID] = mapped_column(ForeignKey('devices.id', ondelete='CASCADE'), index=True)
    release_id: Mapped[UUID] = mapped_column(ForeignKey('setup_update_releases.id'))
    bridge_rollout_id: Mapped[UUID] = mapped_column(ForeignKey('update_rollouts.id'))
    return_build_id: Mapped[UUID | None] = mapped_column(ForeignKey('update_builds.id'))
    return_rollout_id: Mapped[UUID | None] = mapped_column(ForeignKey('update_rollouts.id'))
    assignment_id: Mapped[UUID | None] = mapped_column(ForeignKey('setup_update_assignments.id'))
    status: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(String(256))
    requested_by: Mapped[str] = mapped_column(String(128))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    safe_code: Mapped[str | None] = mapped_column(String(128))


class SetupFleetQualification(OwnershipRecord, Base):
    """An exact artifact/source proof; enrollment publication alone is insufficient."""
    __tablename__ = 'setup_fleet_qualifications'
    __table_args__ = (UniqueConstraint('release_id', 'sha256', 'source_foundation', name='uq_setup_fleet_qualification'),)
    release_id: Mapped[UUID] = mapped_column(ForeignKey('setup_update_releases.id'))
    sha256: Mapped[str] = mapped_column(String(64))
    source_foundation: Mapped[str] = mapped_column(String(64))
    evidence_assignment_id: Mapped[UUID] = mapped_column(ForeignKey('setup_update_assignments.id'))
    qualified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    qualified_by: Mapped[str] = mapped_column(String(128))
    evidence_code: Mapped[str] = mapped_column(String(128))


class SetupFleetPolicy(OwnershipRecord, Base):
    __tablename__ = 'setup_fleet_policy'
    __table_args__ = (
        CheckConstraint("policy_key = 'windows-full-setup'", name='ck_setup_fleet_singleton'),
        CheckConstraint('revision > 0', name='ck_setup_fleet_revision'),
        CheckConstraint('max_parallel BETWEEN 1 AND 2', name='ck_setup_fleet_parallel'),
        CheckConstraint("scope IN ('all_active','selected')", name='ck_setup_fleet_scope'),
    )
    policy_key: Mapped[str] = mapped_column(String(32), unique=True, default='windows-full-setup')
    revision: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    release_id: Mapped[UUID | None] = mapped_column(ForeignKey('setup_update_releases.id'))
    scope: Mapped[str] = mapped_column(String(32), default='all_active')
    device_ids: Mapped[list] = mapped_column(JSON, default=list)
    max_parallel: Mapped[int] = mapped_column(Integer, default=1)
    reason: Mapped[str] = mapped_column(String(256))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_by: Mapped[str] = mapped_column(String(128))
    safe_code: Mapped[str | None] = mapped_column(String(128))


class SetupFleetDecision(OwnershipRecord, Base):
    __tablename__ = 'setup_fleet_decisions'
    __table_args__ = (
        UniqueConstraint('policy_id', 'policy_revision', 'device_id', 'target_sha256', name='uq_setup_fleet_decision'),
        Index('ix_setup_fleet_decision_scan', 'policy_id', 'policy_revision', 'evaluated_at'),
    )
    policy_id: Mapped[UUID] = mapped_column(ForeignKey('setup_fleet_policy.id'))
    policy_revision: Mapped[int] = mapped_column(Integer)
    device_id: Mapped[UUID] = mapped_column(ForeignKey('devices.id', ondelete='CASCADE'))
    release_id: Mapped[UUID] = mapped_column(ForeignKey('setup_update_releases.id'))
    target_sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    safe_code: Mapped[str] = mapped_column(String(128))
    job_id: Mapped[UUID | None] = mapped_column()
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

