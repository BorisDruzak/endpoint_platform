"""Shared mapped ownership columns without importing the model registry."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Uuid, func
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column


class OwnershipRecord:
    """UUID identity and UTC creation time shared by ownership tables."""

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True).with_variant(PostgreSQLUUID(as_uuid=True), "postgresql"),
        primary_key=True,
        default=uuid4,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
