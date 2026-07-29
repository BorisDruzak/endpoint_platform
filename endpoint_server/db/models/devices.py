"""Device ownership and connection models."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base

from .common import OwnershipRecord


class Device(OwnershipRecord, Base):
    __tablename__ = "devices"

    device_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    display_name: Mapped[str | None] = mapped_column(String(256))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DeviceCredential(OwnershipRecord, Base):
    __tablename__ = "device_credentials"
    __table_args__ = (
        UniqueConstraint(
            "device_id",
            "credential_identifier",
            name="uq_device_credentials_device_identifier",
        ),
    )

    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    credential_identifier: Mapped[str] = mapped_column(String(128), nullable=False)
    token_digest: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DeviceInstance(OwnershipRecord, Base):
    __tablename__ = "device_instances"
    __table_args__ = (
        UniqueConstraint(
            "device_id",
            "instance_identifier",
            name="uq_device_instances_device_identifier",
        ),
    )

    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    instance_identifier: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(64), nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DeviceSession(OwnershipRecord, Base):
    __tablename__ = "device_sessions"

    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    device_instance_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("device_instances.id", ondelete="SET NULL")
    )
    session_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
