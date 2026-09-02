"""Service-scoped Endpoint Operation ownership records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PostgreSQLUUID
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

ENDPOINT_OPERATION_CAPABILITIES = (
    "context.diagnostic.collect",
    "endpoint.module.recipe",
)

MODULE_OPERATION_STEP_STATUSES = ENDPOINT_OPERATION_STATUSES


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
        ForeignKeyConstraint(
            ["id", "context_collection_id"],
            ["context_collections.operation_id", "context_collections.id"],
            name="fk_endpoint_operations_collection_identity",
            deferrable=True,
            initially="DEFERRED",
        ),
        CheckConstraint(
            "capability IN ('context.diagnostic.collect', 'endpoint.module.recipe')",
            name="ck_endpoint_operations_capability",
        ),
        CheckConstraint(
            "((capability = 'context.diagnostic.collect' "
            "AND module_version_id IS NULL AND module_inputs IS NULL) OR "
            "(capability = 'endpoint.module.recipe' "
            "AND module_version_id IS NOT NULL AND module_inputs IS NOT NULL))",
            name="ck_endpoint_operations_module_shape",
        ),
        CheckConstraint(
            "expected_step_count IS NULL OR expected_step_count BETWEEN 1 AND 8",
            name="ck_endpoint_operations_expected_step_count",
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
        PostgreSQLUUID(as_uuid=True)
    )
    command_id: Mapped[UUID | None] = mapped_column(ForeignKey("commands.id"))
    module_version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("module_versions.id")
    )
    module_inputs: Mapped[dict[str, object] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql")
    )
    expected_step_count: Mapped[int | None] = mapped_column(BigInteger)


class ModuleOperationStep(OwnershipRecord, Base):
    """One ordered Endpoint-owned typed primitive within a parent module operation."""

    __tablename__ = "endpoint_operation_steps"
    __table_args__ = (
        UniqueConstraint("operation_id", "sequence", name="uq_endpoint_operation_steps_sequence"),
        UniqueConstraint(
            "operation_id",
            "recipe_step_key",
            name="uq_endpoint_operation_steps_recipe_key",
        ),
        UniqueConstraint("command_id", name="uq_endpoint_operation_steps_command"),
        CheckConstraint("sequence >= 0", name="ck_endpoint_operation_steps_sequence"),
        CheckConstraint(
            "capability IN ('dns.resolve', 'network.ping', 'tcp.connect')",
            name="ck_endpoint_operation_steps_capability",
        ),
        CheckConstraint(
            "status IN ('queued', 'delivered', 'acknowledged', 'running', "
            "'succeeded', 'failed', 'canceled', 'expired')",
            name="ck_endpoint_operation_steps_status",
        ),
        CheckConstraint(
            "((status IN ('succeeded', 'failed', 'canceled', 'expired') "
            "AND completed_at IS NOT NULL) OR "
            "(status IN ('queued', 'delivered', 'acknowledged', 'running') "
            "AND completed_at IS NULL))",
            name="ck_endpoint_operation_steps_terminal",
        ),
        Index(
            "ix_endpoint_operation_steps_operation_status",
            "operation_id",
            "status",
        ),
    )

    operation_id: Mapped[UUID] = mapped_column(
        ForeignKey("endpoint_operations.id"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    recipe_step_key: Mapped[str] = mapped_column(String(64), nullable=False)
    capability: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    command_id: Mapped[UUID | None] = mapped_column(ForeignKey("commands.id"))
    safe_result_json: Mapped[dict[str, object] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql")
    )
    error_code: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


__all__ = [
    "ENDPOINT_OPERATION_CAPABILITIES",
    "ENDPOINT_OPERATION_STATUSES",
    "MODULE_OPERATION_STEP_STATUSES",
    "EndpointOperation",
    "ModuleOperationStep",
]
