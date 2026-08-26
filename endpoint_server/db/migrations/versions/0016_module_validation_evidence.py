"""Persist bounded module validation and lab acceptance evidence."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0016_module_validation_evidence"
down_revision: str | None = "0015_module_platform"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "module_validation_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("module_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("validator_version", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error_codes", postgresql.JSONB(), nullable=False),
        sa.Column("warning_codes", postgresql.JSONB(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["module_version_id"], ["module_versions.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('succeeded', 'failed')", name="ck_module_validation_runs_status"
        ),
    )
    op.create_table(
        "module_live_tests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("module_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("platform", sa.String(length=32), nullable=False),
        sa.Column("endpoint_device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("safe_result_snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("tested_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["module_version_id"], ["module_versions.id"]),
        sa.ForeignKeyConstraint(["endpoint_device_id"], ["devices.id"]),
        sa.ForeignKeyConstraint(["operation_id"], ["endpoint_operations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "platform IN ('linux_amd64', 'windows_amd64')",
            name="ck_module_live_tests_platform",
        ),
        sa.CheckConstraint(
            "status IN ('passed', 'failed')", name="ck_module_live_tests_status"
        ),
    )


def downgrade() -> None:
    op.drop_table("module_live_tests")
    op.drop_table("module_validation_runs")
