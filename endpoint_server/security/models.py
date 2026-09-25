"""Independent typed SecurityEvent ledger, separate from Context and Audit."""

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
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base
from endpoint_server.db.ownership import OwnershipRecord


class SecurityEvent(OwnershipRecord, Base):
    """One validated audit fact; raw WSS payload is never stored."""

    __tablename__ = "security_events"
    __table_args__ = (
        UniqueConstraint(
            "device_id", "event_identifier", name="uq_security_events_device_identifier"
        ),
        CheckConstraint(
            "(channel = 'USB' AND event_type IN ('USB_DEVICE_CONNECTED', 'USB_DEVICE_DISCONNECTED')) "
            "OR (channel = 'PRINT' AND event_type = 'PRINT_JOB') "
            "OR (channel = 'BROWSER' AND event_type IN ('BROWSER_UPLOAD', 'BROWSER_PASTE'))",
            name="ck_security_events_type_channel",
        ),
        CheckConstraint("severity = 'INFO'", name="ck_security_events_audit_severity"),
        Index("ix_security_events_device_occurred", "device_id", "occurred_at", "id"),
        Index("ix_security_events_expires", "expires_at", "id"),
        Index("ix_security_events_type_occurred", "event_type", "occurred_at"),
    )

    event_identifier: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), nullable=False
    )
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    user_login: Mapped[str | None] = mapped_column(String(256))
    policy_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), nullable=False
    )
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    safe_metadata: Mapped[dict[str, object]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


__all__ = ["SecurityEvent"]
