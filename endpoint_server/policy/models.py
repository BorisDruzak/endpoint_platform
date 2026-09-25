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


class PolicyApplication(OwnershipRecord, Base):
    """Immutable proof that one Agent applied a policy at a specific time."""

    __tablename__ = "policy_applications"
    __table_args__ = (
        UniqueConstraint(
            "device_id", "policy_version_id", "applied_at",
            name="uq_policy_applications_device_version_time",
        ),
        Index("ix_policy_applications_device_applied", "device_id", "applied_at"),
    )

    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    policy_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("policy_versions.id", ondelete="RESTRICT"), nullable=False
    )
    policy_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acknowledged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BrowserStatusCurrent(OwnershipRecord, Base):
    """Last per-browser facts reported by one Agent, independent of compliance."""

    __tablename__ = "browser_status_current"
    __table_args__ = (
        UniqueConstraint("device_id", "browser_family", name="uq_browser_status_device_family"),
        CheckConstraint(
            "browser_family IN ('chrome', 'yandex')",
            name="ck_browser_status_family",
        ),
        CheckConstraint(
            "extension_install_type IN ('ADMIN', 'OTHER', 'UNKNOWN')",
            name="ck_browser_status_install_type",
        ),
        Index("ix_browser_status_observed", "device_id", "observed_at"),
    )

    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False,
    )
    browser_family: Mapped[str] = mapped_column(String(16), nullable=False)
    observation_id: Mapped[UUID] = mapped_column(nullable=False)
    policy_id: Mapped[UUID] = mapped_column(nullable=False)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    browser_state: Mapped[str] = mapped_column(String(16), nullable=False)
    running_state: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_owner: Mapped[str] = mapped_column(String(16), nullable=False)
    installation_policy_state: Mapped[str] = mapped_column(String(16), nullable=False)
    native_host_state: Mapped[str] = mapped_column(String(16), nullable=False)
    extension_version: Mapped[str | None] = mapped_column(String(32))
    extension_last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    extension_install_type: Mapped[str] = mapped_column(
        String(16), nullable=False, default="UNKNOWN", server_default="UNKNOWN",
    )
    last_running_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PolicySensorHealthCurrent(OwnershipRecord, Base):
    """Latest bounded local sensor facts for one device and policy version."""

    __tablename__ = "policy_sensor_health_current"
    __table_args__ = (
        UniqueConstraint("device_id", name="uq_policy_sensor_health_device"),
        CheckConstraint(
            "activity_listener_state IN ('READY', 'UNAVAILABLE', 'UNKNOWN') AND "
            "security_spool_state IN ('READY', 'UNAVAILABLE', 'UNKNOWN') AND "
            "usb_source_state IN ('READY', 'UNAVAILABLE', 'UNKNOWN') AND "
            "print_source_state IN ('READY', 'UNAVAILABLE', 'UNKNOWN')",
            name="ck_policy_sensor_health_source_states",
        ),
        Index("ix_policy_sensor_health_observed", "device_id", "observed_at"),
    )

    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False,
    )
    observation_id: Mapped[UUID] = mapped_column(nullable=False)
    policy_id: Mapped[UUID] = mapped_column(nullable=False)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    activity_listener_state: Mapped[str] = mapped_column(String(16), nullable=False)
    user_sensor_last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    security_spool_state: Mapped[str] = mapped_column(String(16), nullable=False)
    usb_source_state: Mapped[str] = mapped_column(String(16), nullable=False)
    print_source_state: Mapped[str] = mapped_column(String(16), nullable=False)


__all__ = [
    "BrowserStatusCurrent",
    "PolicyApplication",
    "PolicyAssignment",
    "PolicyDefinition",
    "PolicyDeviceState",
    "PolicyMutationError",
    "PolicySensorHealthCurrent",
    "PolicyVersion",
]
