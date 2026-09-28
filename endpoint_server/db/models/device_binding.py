"""Endpoint-owned device possession state, containing no requester identity."""
from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, text
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base
from .common import OwnershipRecord


class DeviceBindingChallenge(OwnershipRecord, Base):
    __tablename__ = "device_binding_challenges"
    __table_args__ = (
        CheckConstraint("purpose = 'helpdesk_device_binding'", name="ck_binding_challenge_purpose"),
        CheckConstraint("status IN ('active','redeemed','expired','revoked')", name="ck_binding_challenge_status"),
        Index("uq_binding_active_device", "device_id", "purpose", unique=True,
              postgresql_where=text("status = 'active'"), sqlite_where=text("status = 'active'")),
        Index("uq_binding_active_digest", "code_digest", unique=True,
              postgresql_where=text("status = 'active'"), sqlite_where=text("status = 'active'")),
        Index("ix_binding_challenge_expiry", "status", "expires_at"),
    )
    device_id: Mapped[UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    code_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    redeemed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DeviceBindingThrottle(Base):
    __tablename__ = "device_binding_throttles"
    __table_args__ = (CheckConstraint("attempts >= 0", name="ck_binding_throttle_attempts"),)
    bucket: Mapped[str] = mapped_column(String(128), primary_key=True)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
