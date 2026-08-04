"""Command ownership, delivery, and result models."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base

from .common import OwnershipRecord


class Command(OwnershipRecord, Base):
    __tablename__ = "commands"

    command_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    command_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CommandDelivery(OwnershipRecord, Base):
    __tablename__ = "command_deliveries"

    command_id: Mapped[UUID] = mapped_column(
        ForeignKey("commands.id", ondelete="CASCADE"), nullable=False
    )
    device_session_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("device_sessions.id", ondelete="SET NULL")
    )
    delivery_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CommandResult(OwnershipRecord, Base):
    __tablename__ = "command_results"
    __table_args__ = (
        CheckConstraint(
            "result_sequence IS NULL OR result_sequence >= 0",
            name="ck_command_results_result_sequence",
        ),
    )

    command_id: Mapped[UUID] = mapped_column(
        ForeignKey("commands.id", ondelete="CASCADE"), nullable=False
    )
    delivery_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("command_deliveries.id", ondelete="SET NULL")
    )
    result_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result_sequence: Mapped[int | None] = mapped_column(BigInteger)
    result_payload_digest: Mapped[str | None] = mapped_column(String(64))
