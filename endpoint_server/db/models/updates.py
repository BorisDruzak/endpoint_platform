"""Update build, rollout, target, and report ownership models."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base

from .common import OwnershipRecord


class UpdateBuild(OwnershipRecord, Base):
    __tablename__ = "update_builds"

    build_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    platform: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_identifier: Mapped[str] = mapped_column(String(256), nullable=False)
    sha256_digest: Mapped[str] = mapped_column(String(64), nullable=False)


class UpdateRollout(OwnershipRecord, Base):
    __tablename__ = "update_rollouts"

    rollout_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    build_id: Mapped[UUID] = mapped_column(
        ForeignKey("update_builds.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UpdateTarget(OwnershipRecord, Base):
    __tablename__ = "update_targets"
    __table_args__ = (
        UniqueConstraint(
            "rollout_id", "device_id", name="uq_update_targets_device"
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
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UpdateReport(OwnershipRecord, Base):
    __tablename__ = "update_reports"

    update_target_id: Mapped[UUID] = mapped_column(
        ForeignKey("update_targets.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    report_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    reported_version: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
