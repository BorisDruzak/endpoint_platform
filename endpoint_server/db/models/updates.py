"""Update build, rollout, target, and report ownership models."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base

from .common import OwnershipRecord


class UpdateBuild(OwnershipRecord, Base):
    __tablename__ = "update_builds"
    __table_args__ = (
        UniqueConstraint(
            "platform",
            "channel",
            "version",
            name="uq_update_builds_platform_channel_version",
        ),
        CheckConstraint("size > 0", name="ck_update_builds_size_positive"),
    )

    build_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    platform: Mapped[str] = mapped_column(String(64), nullable=False)
    channel: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_identifier: Mapped[str] = mapped_column(String(256), nullable=False)
    artifact_url: Mapped[str] = mapped_column(Text, nullable=False)
    artifact_name: Mapped[str] = mapped_column(String(256), nullable=False)
    archive_type: Mapped[str] = mapped_column(String(16), nullable=False)
    sha256_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    release_notes: Mapped[str | None] = mapped_column(Text)


class UpdateRollout(OwnershipRecord, Base):
    __tablename__ = "update_rollouts"
    __table_args__ = (
        CheckConstraint(
            "mode IN ('canary', 'bulk', 'rollback')",
            name="ck_update_rollouts_mode",
        ),
        CheckConstraint(
            "status IN ('draft', 'active', 'paused', 'completed', 'cancelled')",
            name="ck_update_rollouts_status",
        ),
        Index("ix_update_rollouts_build_id", "build_id"),
    )

    rollout_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    build_id: Mapped[UUID] = mapped_column(
        ForeignKey("update_builds.id", ondelete="CASCADE"), nullable=False
    )
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UpdateTarget(OwnershipRecord, Base):
    __tablename__ = "update_targets"
    __table_args__ = (
        UniqueConstraint("rollout_id", "device_id", name="uq_update_targets_device"),
        CheckConstraint(
            "status IN "
            "('assigned', 'requested', 'scheduled', 'applied', 'failed', "
            "'rolled_back', 'cancelled')",
            name="ck_update_targets_status",
        ),
        Index(
            "uq_update_targets_active_device",
            "device_id",
            unique=True,
            postgresql_where=text("status IN ('assigned', 'requested', 'scheduled')"),
        ),
    )

    rollout_id: Mapped[UUID] = mapped_column(
        ForeignKey("update_rollouts.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    target_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    operation_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    safe_reason: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UpdateReport(OwnershipRecord, Base):
    __tablename__ = "update_reports"
    __table_args__ = (
        UniqueConstraint(
            "update_target_id",
            "report_key",
            name="uq_update_reports_target_report_key",
        ),
    )

    update_target_id: Mapped[UUID] = mapped_column(
        ForeignKey("update_targets.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    report_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    report_key: Mapped[str] = mapped_column(String(128), nullable=False)
    reported_version: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    safe_code: Mapped[str | None] = mapped_column(String(128))
