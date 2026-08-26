"""Add durable parent module operation references and ordered typed steps."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0017_module_operation_steps"
down_revision: str | None = "0016_module_validation_evidence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "endpoint_operations",
        sa.Column("module_version_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "endpoint_operations",
        sa.Column("module_inputs", postgresql.JSONB(), nullable=True),
    )
    op.create_foreign_key(
        "fk_endpoint_operations_module_version",
        "endpoint_operations",
        "module_versions",
        ["module_version_id"],
        ["id"],
    )
    op.drop_constraint(
        "ck_endpoint_operations_capability",
        "endpoint_operations",
        type_="check",
    )
    op.create_check_constraint(
        "ck_endpoint_operations_capability",
        "endpoint_operations",
        "capability IN ('context.diagnostic.collect', 'endpoint.module.recipe')",
    )
    op.create_check_constraint(
        "ck_endpoint_operations_module_shape",
        "endpoint_operations",
        "((capability = 'context.diagnostic.collect' "
        "AND module_version_id IS NULL AND module_inputs IS NULL) OR "
        "(capability = 'endpoint.module.recipe' "
        "AND module_version_id IS NOT NULL AND module_inputs IS NOT NULL))",
    )
    op.create_table(
        "endpoint_operation_steps",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("recipe_step_key", sa.String(length=64), nullable=False),
        sa.Column("capability", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("command_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("safe_result_json", postgresql.JSONB(), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["operation_id"], ["endpoint_operations.id"]),
        sa.ForeignKeyConstraint(["command_id"], ["commands.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operation_id", "sequence", name="uq_endpoint_operation_steps_sequence"),
        sa.UniqueConstraint(
            "operation_id",
            "recipe_step_key",
            name="uq_endpoint_operation_steps_recipe_key",
        ),
        sa.UniqueConstraint("command_id", name="uq_endpoint_operation_steps_command"),
        sa.CheckConstraint("sequence >= 0", name="ck_endpoint_operation_steps_sequence"),
        sa.CheckConstraint(
            "capability IN ('dns.resolve', 'network.ping', 'tcp.connect')",
            name="ck_endpoint_operation_steps_capability",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'delivered', 'acknowledged', 'running', "
            "'succeeded', 'failed', 'canceled', 'expired')",
            name="ck_endpoint_operation_steps_status",
        ),
        sa.CheckConstraint(
            "((status IN ('succeeded', 'failed', 'canceled', 'expired') "
            "AND completed_at IS NOT NULL) OR "
            "(status IN ('queued', 'delivered', 'acknowledged', 'running') "
            "AND completed_at IS NULL))",
            name="ck_endpoint_operation_steps_terminal",
        ),
    )
    op.create_index(
        "ix_endpoint_operation_steps_operation_status",
        "endpoint_operation_steps",
        ["operation_id", "status"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_endpoint_operation_steps_operation_status",
        table_name="endpoint_operation_steps",
    )
    op.drop_table("endpoint_operation_steps")
    op.drop_constraint(
        "ck_endpoint_operations_module_shape",
        "endpoint_operations",
        type_="check",
    )
    op.drop_constraint(
        "ck_endpoint_operations_capability",
        "endpoint_operations",
        type_="check",
    )
    op.create_check_constraint(
        "ck_endpoint_operations_capability",
        "endpoint_operations",
        "capability = 'context.diagnostic.collect'",
    )
    op.drop_constraint(
        "fk_endpoint_operations_module_version",
        "endpoint_operations",
        type_="foreignkey",
    )
    op.drop_column("endpoint_operations", "module_inputs")
    op.drop_column("endpoint_operations", "module_version_id")
