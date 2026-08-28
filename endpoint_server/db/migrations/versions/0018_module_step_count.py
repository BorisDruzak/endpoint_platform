"""Persist the immutable expected child count for module operations."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0018_module_step_count"
down_revision: str | None = "0017_module_operation_steps"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "endpoint_operations",
        sa.Column("expected_step_count", sa.BigInteger(), nullable=True),
    )
    op.execute(
        """
        UPDATE endpoint_operations AS operation
        SET expected_step_count = jsonb_array_length(version.recipe -> 'steps')
        FROM module_versions AS version
        WHERE operation.capability = 'endpoint.module.recipe'
          AND operation.module_version_id = version.id
          AND operation.expected_step_count IS NULL
          AND version.recipe ->> 'schema_version' = 'endpoint_recipe_module_v1'
          AND jsonb_typeof(version.recipe -> 'steps') = 'array'
          AND jsonb_array_length(version.recipe -> 'steps') BETWEEN 1 AND 8
        """
    )
    op.create_check_constraint(
        "ck_endpoint_operations_expected_step_count",
        "endpoint_operations",
        "expected_step_count IS NULL OR expected_step_count BETWEEN 1 AND 8",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_endpoint_operations_expected_step_count",
        "endpoint_operations",
        type_="check",
    )
    op.drop_column("endpoint_operations", "expected_step_count")
