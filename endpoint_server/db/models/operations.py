"""Service-scoped Endpoint Operation ownership records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base

from .common import OwnershipRecord


ENDPOINT_OPERATION_STATUSES = (
    "queued",
    "delivered",
    "acknowledged",
    "running",
    "succeeded",
    "failed",
    "canceled",
    "expired",
)


class EndpointOperation(OwnershipRecord, Base):
    """One public operation identity with private collection/command links."""

    __tablename__ = "endpoint_operations"
    __table_args__ = (
        UniqueConstraint(
            "requested_by_service_client_id",
            "idempotency_key",
            name="uq_endpoint_operations_client_key",
        ),
        UniqueConstraint(
            "context_collection_id",
            name="uq_endpoint_operations_collection",
        ),
        UniqueConstraint("command_id", name="uq_endpoint_operations_command"),
        UniqueConstraint(
            "id",
            "context_collection_id",
            name="uq_endpoint_operations_collection_identity",
        ),
        CheckConstraint(
            "capability = 'context.diagnostic.collect'",
            name="ck_endpoint_operations_capability",
        ),
        CheckConstraint(
            "status IN ('queued', 'delivered', 'acknowledged', 'running', "
            "'succeeded', 'failed', 'canceled', 'expired')",
            name="ck_endpoint_operations_status",
        ),
        CheckConstraint(
            "deadline_at > created_at",
            name="ck_endpoint_operations_deadline",
        ),
        CheckConstraint(
            "((status IN ('succeeded', 'failed', 'canceled', 'expired') "
            "AND completed_at IS NOT NULL) OR "
            "(status IN ('queued', 'delivered', 'acknowledged', 'running') "
            "AND completed_at IS NULL))",
            name="ck_endpoint_operations_terminal",
        ),
        Index("ix_endpoint_operations_status_deadline", "status", "deadline_at"),
        Index(
            "ix_endpoint_operations_client_status",
            "requested_by_service_client_id",
            "status",
        ),
    )

    requested_by_service_client_id: Mapped[UUID] = mapped_column(
        ForeignKey("service_clients.id"), nullable=False
    )
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id"), nullable=False
    )
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    capability: Mapped[str] = mapped_column(String(64), nullable=False)
    parameters: Mapped[dict[str, object]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False
    )
    correlation: Mapped[dict[str, object] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql")
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    deadline_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    context_collection_id: Mapped[UUID | None] = mapped_column(
        ForeignKey(
            "context_collections.id",
            deferrable=True,
            initially="DEFERRED",
        )
    )
    command_id: Mapped[UUID | None] = mapped_column(ForeignKey("commands.id"))


__all__ = ["ENDPOINT_OPERATION_STATUSES", "EndpointOperation"]
