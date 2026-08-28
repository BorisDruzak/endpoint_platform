"""Backfill historical module-operation child counts from immutable recipes."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op


revision: str = "0019_module_step_count_backfill"
down_revision: str | None = "0018_module_step_count"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
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


def downgrade() -> None:
    """Backfilled immutable counts must remain valid when revisioned down."""
