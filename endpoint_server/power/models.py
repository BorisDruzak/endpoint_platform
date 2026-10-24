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
)
from sqlalchemy.orm import Mapped, mapped_column
from endpoint_server.db.base import Base
from endpoint_server.db.ownership import OwnershipRecord


class PowerSourceState(OwnershipRecord, Base):
    __tablename__ = "power_source_states"
    __table_args__ = (
        UniqueConstraint("device_id", name="uq_power_source_device"),
        CheckConstraint(
            "availability IN ('READY','DEGRADED','UNAVAILABLE','UNSUPPORTED')",
            name="ck_power_source_availability",
        ),
        CheckConstraint(
            "loss_count >= 0 AND reset_count >= 0", name="ck_power_source_counters"
        ),
        Index("ix_power_source_reported", "reported_at"),
    )
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    availability: Mapped[str] = mapped_column(String(16), nullable=False)
    reported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    coverage_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    loss_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    reset_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
