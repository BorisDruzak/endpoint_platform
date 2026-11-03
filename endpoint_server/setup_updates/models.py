"""Setup update ownership is separate from both Core OTA and enrollment media."""
from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, JSON, String, UniqueConstraint, text
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
              postgresql_where=text("status IN ('assigned','downloading','verified','installing','verifying')"),
              sqlite_where=text("status IN ('assigned','downloading','verified','installing','verifying')")),
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

