"""Persist Endpoint-owned immutable module definitions and versions."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0015_module_platform"
down_revision: str | None = "0014_endpoint_operations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "module_definitions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("module_key", sa.String(length=128), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("module_key"),
    )
    op.create_table(
        "module_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("module_definition_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("recipe", postgresql.JSONB(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(["module_definition_id"], ["module_definitions.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("module_definition_id", "version", name="uq_module_versions_definition_version"),
        sa.CheckConstraint("state IN ('draft', 'validation_failed', 'validated', 'lab_accepted', 'published', 'deprecated', 'revoked')", name="ck_module_versions_state"),
    )


def downgrade() -> None:
    op.drop_table("module_versions")
    op.drop_table("module_definitions")
