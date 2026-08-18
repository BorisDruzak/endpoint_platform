"""Persist service-scoped Endpoint Operations and private ownership links."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0014_endpoint_operations"
down_revision: str | None = "0013_runtime_session_heartbeat"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "context_collections",
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_unique_constraint(
        "uq_context_collections_operation",
        "context_collections",
        ["operation_id"],
    )
    op.create_unique_constraint(
        "uq_context_collections_operation_identity",
        "context_collections",
        ["operation_id", "id"],
    )
    op.create_table(
        "endpoint_operations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "requested_by_service_client_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("capability", sa.String(length=64), nullable=False),
        sa.Column("parameters", postgresql.JSONB(), nullable=False),
        sa.Column("correlation", postgresql.JSONB(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "context_collection_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
        sa.Column("command_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["requested_by_service_client_id"], ["service_clients.id"]
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.ForeignKeyConstraint(
            ["id", "context_collection_id"],
            ["context_collections.operation_id", "context_collections.id"],
            name="fk_endpoint_operations_collection_identity",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(["command_id"], ["commands.id"]),
        sa.UniqueConstraint(
            "requested_by_service_client_id",
            "idempotency_key",
            name="uq_endpoint_operations_client_key",
        ),
        sa.UniqueConstraint(
            "context_collection_id", name="uq_endpoint_operations_collection"
        ),
        sa.UniqueConstraint("command_id", name="uq_endpoint_operations_command"),
        sa.UniqueConstraint(
            "id",
            "context_collection_id",
            name="uq_endpoint_operations_collection_identity",
        ),
        sa.CheckConstraint(
            "capability = 'context.diagnostic.collect'",
            name="ck_endpoint_operations_capability",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'delivered', 'acknowledged', 'running', "
            "'succeeded', 'failed', 'canceled', 'expired')",
            name="ck_endpoint_operations_status",
        ),
        sa.CheckConstraint(
            "deadline_at > created_at", name="ck_endpoint_operations_deadline"
        ),
        sa.CheckConstraint(
            "((status IN ('succeeded', 'failed', 'canceled', 'expired') "
            "AND completed_at IS NOT NULL) OR "
            "(status IN ('queued', 'delivered', 'acknowledged', 'running') "
            "AND completed_at IS NULL))",
            name="ck_endpoint_operations_terminal",
        ),
    )
    op.create_index(
        "ix_endpoint_operations_status_deadline",
        "endpoint_operations",
        ["status", "deadline_at"],
    )
    op.create_index(
        "ix_endpoint_operations_client_status",
        "endpoint_operations",
        ["requested_by_service_client_id", "status"],
    )
    op.create_foreign_key(
        "fk_context_collections_operation_identity",
        "context_collections",
        "endpoint_operations",
        ["operation_id", "id"],
        ["id", "context_collection_id"],
        deferrable=True,
        initially="DEFERRED",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_context_collections_operation_identity",
        "context_collections",
        type_="foreignkey",
    )
    op.drop_index(
        "ix_endpoint_operations_client_status", table_name="endpoint_operations"
    )
    op.drop_index(
        "ix_endpoint_operations_status_deadline", table_name="endpoint_operations"
    )
    op.drop_table("endpoint_operations")
    op.drop_constraint(
        "uq_context_collections_operation_identity",
        "context_collections",
        type_="unique",
    )
    op.drop_constraint(
        "uq_context_collections_operation",
        "context_collections",
        type_="unique",
    )
    op.drop_column("context_collections", "operation_id")
