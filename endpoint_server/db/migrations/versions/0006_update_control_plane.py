"""Persist immutable update manifests and fail-closed rollout state.

Revision ID: 0006_update_control_plane
Revises: 0005_enrollment_campaigns
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0006_update_control_plane"
down_revision: str | None = "0005_enrollment_campaigns"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "update_builds",
        sa.Column("channel", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "update_builds",
        sa.Column("artifact_url", sa.Text(), nullable=True),
    )
    op.add_column(
        "update_builds",
        sa.Column("artifact_name", sa.String(length=256), nullable=True),
    )
    op.add_column(
        "update_builds",
        sa.Column("archive_type", sa.String(length=16), nullable=True),
    )
    op.add_column(
        "update_builds",
        sa.Column("size", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "update_builds",
        sa.Column("release_notes", sa.Text(), nullable=True),
    )
    op.execute(
        "UPDATE update_builds SET "
        "channel = 'legacy-' || replace(id::text, '-', ''), "
        "artifact_url = 'https://invalid.invalid/legacy/' || id::text, "
        "artifact_name = 'legacy-' || replace(id::text, '-', '') || '.zip', "
        "archive_type = 'zip', size = 1, "
        "artifact_identifier = "
        "'legacy-' || replace(id::text, '-', '') || '.zip'"
    )
    for column in ("channel", "artifact_url", "artifact_name", "archive_type", "size"):
        op.alter_column("update_builds", column, nullable=False)
    op.create_unique_constraint(
        "uq_update_builds_platform_channel_version",
        "update_builds",
        ["platform", "channel", "version"],
    )
    op.create_check_constraint(
        "ck_update_builds_size_positive",
        "update_builds",
        "size > 0",
    )

    op.add_column(
        "update_rollouts",
        sa.Column("mode", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "update_rollouts",
        sa.Column("reason", sa.Text(), nullable=True),
    )
    op.add_column(
        "update_rollouts",
        sa.Column("paused_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "update_rollouts",
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute("UPDATE update_rollouts SET mode = 'canary'")
    op.execute(
        "UPDATE update_rollouts SET status = 'cancelled', "
        "cancelled_at = COALESCE(completed_at, started_at, created_at, "
        "CURRENT_TIMESTAMP) "
        "WHERE status NOT IN ('completed', 'cancelled')"
    )
    op.execute(
        "UPDATE update_rollouts SET completed_at = "
        "COALESCE(completed_at, started_at, created_at, CURRENT_TIMESTAMP) "
        "WHERE status = 'completed'"
    )
    op.execute(
        "UPDATE update_rollouts SET cancelled_at = "
        "COALESCE(cancelled_at, completed_at, started_at, created_at, "
        "CURRENT_TIMESTAMP) WHERE status = 'cancelled'"
    )
    op.alter_column("update_rollouts", "mode", nullable=False)
    op.create_check_constraint(
        "ck_update_rollouts_mode",
        "update_rollouts",
        "mode IN ('canary', 'bulk', 'rollback')",
    )
    op.create_check_constraint(
        "ck_update_rollouts_status",
        "update_rollouts",
        "status IN ('draft', 'active', 'paused', 'completed', 'cancelled')",
    )
    op.create_index(
        "ix_update_rollouts_build_id",
        "update_rollouts",
        ["build_id"],
    )

    op.add_column(
        "update_targets",
        sa.Column("operation_id", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "update_targets",
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "update_targets",
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "update_targets",
        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "update_targets",
        sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "update_targets",
        sa.Column("safe_reason", sa.Text(), nullable=True),
    )
    op.execute(
        "UPDATE update_targets SET operation_id = id::text, "
        "assigned_at = created_at"
    )
    op.execute(
        "UPDATE update_targets SET status = 'cancelled', "
        "terminal_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP), "
        "safe_reason = COALESCE(safe_reason, 'migrated_legacy_target') "
        "WHERE status NOT IN "
        "('applied', 'failed', 'rolled_back', 'cancelled')"
    )
    op.execute(
        "UPDATE update_targets SET terminal_at = "
        "COALESCE(terminal_at, updated_at, created_at, CURRENT_TIMESTAMP) "
        "WHERE status IN ('applied', 'failed', 'rolled_back', 'cancelled')"
    )
    op.alter_column("update_targets", "operation_id", nullable=False)
    op.alter_column("update_targets", "assigned_at", nullable=False)
    op.create_unique_constraint(
        "uq_update_targets_operation_id",
        "update_targets",
        ["operation_id"],
    )
    op.create_check_constraint(
        "ck_update_targets_status",
        "update_targets",
        "status IN "
        "('assigned', 'requested', 'scheduled', 'applied', 'failed', "
        "'rolled_back', 'cancelled')",
    )
    op.create_index(
        "uq_update_targets_active_device",
        "update_targets",
        ["device_id"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('assigned', 'requested', 'scheduled')"
        ),
    )

    op.add_column(
        "update_reports",
        sa.Column("report_key", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "update_reports",
        sa.Column("safe_code", sa.String(length=128), nullable=True),
    )
    op.execute("UPDATE update_reports SET report_key = report_identifier")
    op.alter_column("update_reports", "report_key", nullable=False)
    op.create_unique_constraint(
        "uq_update_reports_target_report_key",
        "update_reports",
        ["update_target_id", "report_key"],
    )


def downgrade() -> None:
    op.execute(
        "UPDATE update_rollouts SET status = 'cancelled', completed_at = "
        "COALESCE(completed_at, cancelled_at, paused_at, started_at, "
        "CURRENT_TIMESTAMP) WHERE status IN ('draft', 'active', 'paused')"
    )
    op.execute(
        "UPDATE update_targets SET status = 'cancelled', updated_at = "
        "COALESCE(terminal_at, scheduled_at, requested_at, assigned_at, "
        "updated_at, CURRENT_TIMESTAMP) WHERE status IN "
        "('assigned', 'requested', 'scheduled')"
    )
    op.execute(
        "UPDATE update_rollouts SET completed_at = "
        "COALESCE(completed_at, cancelled_at, paused_at, started_at, "
        "CURRENT_TIMESTAMP) WHERE status = 'cancelled' "
        "AND completed_at IS NULL"
    )
    op.execute(
        "UPDATE update_targets SET updated_at = "
        "COALESCE(updated_at, terminal_at, scheduled_at, requested_at, "
        "assigned_at, CURRENT_TIMESTAMP) WHERE status = 'cancelled' "
        "AND updated_at IS NULL"
    )

    op.drop_constraint(
        "uq_update_reports_target_report_key",
        "update_reports",
        type_="unique",
    )
    op.drop_column("update_reports", "safe_code")
    op.drop_column("update_reports", "report_key")

    op.drop_index(
        "uq_update_targets_active_device",
        table_name="update_targets",
    )
    op.drop_constraint(
        "ck_update_targets_status",
        "update_targets",
        type_="check",
    )
    op.drop_constraint(
        "uq_update_targets_operation_id",
        "update_targets",
        type_="unique",
    )
    for column in (
        "safe_reason",
        "terminal_at",
        "scheduled_at",
        "requested_at",
        "assigned_at",
        "operation_id",
    ):
        op.drop_column("update_targets", column)

    op.drop_index("ix_update_rollouts_build_id", table_name="update_rollouts")
    op.drop_constraint(
        "ck_update_rollouts_status",
        "update_rollouts",
        type_="check",
    )
    op.drop_constraint(
        "ck_update_rollouts_mode",
        "update_rollouts",
        type_="check",
    )
    for column in ("cancelled_at", "paused_at", "reason", "mode"):
        op.drop_column("update_rollouts", column)

    op.drop_constraint(
        "ck_update_builds_size_positive",
        "update_builds",
        type_="check",
    )
    op.drop_constraint(
        "uq_update_builds_platform_channel_version",
        "update_builds",
        type_="unique",
    )
    for column in (
        "release_notes",
        "size",
        "archive_type",
        "artifact_name",
        "artifact_url",
        "channel",
    ):
        op.drop_column("update_builds", column)
