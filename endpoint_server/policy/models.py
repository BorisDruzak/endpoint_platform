"""Immutable Endpoint Policy versions and effective assignment state."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    event,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base
from endpoint_server.db.ownership import OwnershipRecord


class PolicyMutationError(RuntimeError):
    """An applied policy version cannot be changed in place."""


class PolicyDefinition(OwnershipRecord, Base):
    __tablename__ = "policy_definitions"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)


class PolicyVersion(OwnershipRecord, Base):
    __tablename__ = "policy_versions"
    __table_args__ = (
        UniqueConstraint("definition_id", "version", name="uq_policy_versions_definition_version"),
        CheckConstraint("version >= 1", name="ck_policy_versions_positive_version"),
    )

    definition_id: Mapped[UUID] = mapped_column(
        ForeignKey("policy_definitions.id", ondelete="RESTRICT"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    document: Mapped[dict[str, object]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False
    )
    created_by: Mapped[UUID] = mapped_column(ForeignKey("admin_users.id"), nullable=False)


@event.listens_for(PolicyVersion, "before_update")
@event.listens_for(PolicyVersion, "before_delete")
def _reject_version_mutation(*_: object) -> None:
    raise PolicyMutationError("policy versions are immutable")


class PolicyAssignment(OwnershipRecord, Base):
    __tablename__ = "policy_assignments"
    __table_args__ = (
        CheckConstraint(
            "(scope = 'default' AND device_id IS NULL) OR "
            "(scope = 'device' AND device_id IS NOT NULL)",
            name="ck_policy_assignments_scope_device",
        ),
        UniqueConstraint("device_id", name="uq_policy_assignments_device"),
        Index(
            "uq_policy_assignments_default",
            "scope",
            unique=True,
            sqlite_where=text("scope = 'default'"),
            postgresql_where=text("scope = 'default'"),
        ),
    )

    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    device_id: Mapped[UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    policy_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("policy_versions.id", ondelete="RESTRICT"), nullable=False
    )
    assigned_by: Mapped[UUID] = mapped_column(ForeignKey("admin_users.id"), nullable=False)
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PolicyDeviceState(OwnershipRecord, Base):
    __tablename__ = "policy_device_states"
    __table_args__ = (
        UniqueConstraint("device_id", name="uq_policy_device_states_device"),
        CheckConstraint(
            "status IN ('PENDING', 'APPLIED', 'STALE', 'UNSUPPORTED', 'ERROR')",
            name="ck_policy_device_states_status",
        ),
    )

    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    policy_version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("policy_versions.id", ondelete="SET NULL")
    )
    policy_digest: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64))
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


__all__ = [
    "PolicyAssignment",
    "PolicyDefinition",
    "PolicyDeviceState",
    "PolicyMutationError",
    "PolicyVersion",
]
