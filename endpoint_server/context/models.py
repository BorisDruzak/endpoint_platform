"""Additive ownership models for immutable Device Context observations."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID

from endpoint_server.db.base import Base
from endpoint_server.db.ownership import OwnershipRecord


CONTEXT_COLLECTION_STATUSES = (
    "requested", "queued", "delivered", "collecting", "result_received",
    "validated", "completed", "failed", "expired",
)

_OPERATION_IDENTITY_FOREIGN_KEY = ForeignKeyConstraint(
    ["operation_id", "id"],
    ["endpoint_operations.id", "endpoint_operations.context_collection_id"],
    name="fk_context_collections_operation_identity",
    deferrable=True,
    initially="DEFERRED",
).ddl_if(dialect="postgresql")
# PostgreSQL owns the cross-table pair invariant. SQLite context tests create
# legacy table subsets without the operation table, so they keep this DDL out.


class ContextCollection(OwnershipRecord, Base):
    """One device/profile collection request and its terminal result correlation."""

    __tablename__ = "context_collections"
    __table_args__ = (
        UniqueConstraint(
            "device_id", "profile", "requested_by", "idempotency_key",
            name="uq_context_collections_request",
        ),
        UniqueConstraint("command_id", name="uq_context_collections_command"),
        UniqueConstraint("command_result_id", name="uq_context_collections_result"),
        UniqueConstraint("operation_id", name="uq_context_collections_operation"),
        UniqueConstraint(
            "operation_id",
            "id",
            name="uq_context_collections_operation_identity",
        ),
        _OPERATION_IDENTITY_FOREIGN_KEY,
        CheckConstraint(
            "status IN ('requested', 'queued', 'delivered', 'collecting', "
            "'result_received', 'validated', 'completed', 'failed', 'expired')",
            name="ck_context_collections_status",
        ),
        Index("ix_context_collections_device_profile_status", "device_id", "profile", "status"),
        Index("ix_context_collections_result", "command_result_id"),
    )

    device_id: Mapped[UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    profile: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    command_id: Mapped[UUID | None] = mapped_column(ForeignKey("commands.id", ondelete="SET NULL"))
    command_result_id: Mapped[UUID | None] = mapped_column(ForeignKey("command_results.id", ondelete="SET NULL"))
    operation_id: Mapped[UUID | None] = mapped_column(PostgreSQLUUID(as_uuid=True))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    result_received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(String(128))
    raw_result_payload: Mapped[dict[str, object] | None] = mapped_column(JSON)


class ContextSnapshot(OwnershipRecord, Base):
    """Immutable validated observation; raw transport and projection are distinct."""

    __tablename__ = "context_snapshots"
    __table_args__ = (
        UniqueConstraint("collection_id", name="uq_context_snapshots_collection"),
        UniqueConstraint(
            "id", "device_id", "profile", name="uq_context_snapshots_identity"
        ),
        Index("ix_context_snapshots_device_profile_collected", "device_id", "profile", "collected_at"),
    )

    collection_id: Mapped[UUID] = mapped_column(ForeignKey("context_collections.id", ondelete="CASCADE"), nullable=False)
    device_id: Mapped[UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    profile: Mapped[str] = mapped_column(String(32), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    pinned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    semantic_hash: Mapped[str | None] = mapped_column(String(64))
    raw_payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    normalized_projection: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)


class ContextDiff(OwnershipRecord, Base):
    __tablename__ = "context_diffs"
    __table_args__ = (
        UniqueConstraint("before_snapshot_id", "after_snapshot_id", name="uq_context_diffs_pair"),
        Index("ix_context_diffs_device_profile", "device_id", "profile"),
    )

    device_id: Mapped[UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    profile: Mapped[str] = mapped_column(String(32), nullable=False)
    before_snapshot_id: Mapped[UUID] = mapped_column(ForeignKey("context_snapshots.id", ondelete="CASCADE"), nullable=False)
    after_snapshot_id: Mapped[UUID] = mapped_column(ForeignKey("context_snapshots.id", ondelete="CASCADE"), nullable=False)
    diff_payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)


class ContextCurrent(OwnershipRecord, Base):
    __tablename__ = "context_current"
    __table_args__ = (
        UniqueConstraint("device_id", "profile", name="uq_context_current_device_profile"),
        ForeignKeyConstraint(
            ["snapshot_id", "device_id", "profile"],
            [
                "context_snapshots.id",
                "context_snapshots.device_id",
                "context_snapshots.profile",
            ],
            name="fk_context_current_snapshot_identity",
            ondelete="CASCADE",
        ),
        Index("ix_context_current_device_profile", "device_id", "profile"),
    )

    device_id: Mapped[UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    profile: Mapped[str] = mapped_column(String(32), nullable=False)
    snapshot_id: Mapped[UUID] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ContextFinding(OwnershipRecord, Base):
    __tablename__ = "context_findings"
    __table_args__ = (Index("ix_context_findings_device_snapshot", "device_id", "snapshot_id"),)

    device_id: Mapped[UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    snapshot_id: Mapped[UUID] = mapped_column(ForeignKey("context_snapshots.id", ondelete="CASCADE"), nullable=False)
    code: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    details: Mapped[str | None] = mapped_column(Text)
