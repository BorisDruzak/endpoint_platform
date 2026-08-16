"""Device ownership and connection models."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    desc,
)
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
    pending_token_digest: Mapped[str | None] = mapped_column(String(256), unique=True)
    rotation_overlap_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
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
        CheckConstraint(
            "last_result_sequence >= 0",
            name="ck_device_instances_last_result_sequence",
        ),
    )

    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    instance_identifier: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(128), nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_result_sequence: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )


class DeviceSession(OwnershipRecord, Base):
    __tablename__ = "device_sessions"
    __table_args__ = (
        Index(
            "ix_device_sessions_device_created_id_desc",
            "device_id",
            desc("created_at"),
            desc("id"),
        ),
        Index(
            "ix_device_sessions_device_handshake_id_desc",
            "device_id",
            desc("last_handshake_at"),
            desc("id"),
        ),
    )

    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    device_instance_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("device_instances.id", ondelete="SET NULL")
    )
    session_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_handshake_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_address: Mapped[str | None] = mapped_column(String(45))
