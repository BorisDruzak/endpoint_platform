"""Create additive Device Context collection ownership tables.

Revision ID: 0008_device_context_foundation
Revises: 0007_admin_update_scopes
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0008_device_context_foundation"
down_revision: str | None = "0007_admin_update_scopes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_STATUSES = "'requested', 'queued', 'delivered', 'collecting', 'result_received', 'validated', 'completed', 'failed', 'expired'"


def _identity_columns() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
    )


def upgrade() -> None:
    op.create_table(
        "context_collections", *_identity_columns(),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("profile", sa.String(length=32), nullable=False),
        sa.Column("requested_by", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("command_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("command_result_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result_received_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_code", sa.String(length=128), nullable=True),
        sa.Column("raw_result_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.CheckConstraint(f"status IN ({_STATUSES})", name="ck_context_collections_status"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["command_id"], ["commands.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["command_result_id"], ["command_results.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id", "profile", "idempotency_key", name="uq_context_collections_request"),
        sa.UniqueConstraint("command_id", name="uq_context_collections_command"),
        sa.UniqueConstraint("command_result_id", name="uq_context_collections_result"),
    )
    op.create_index("ix_context_collections_device_profile_status", "context_collections", ["device_id", "profile", "status"])
    op.create_index("ix_context_collections_result", "context_collections", ["command_result_id"])
    op.create_table(
        "context_snapshots", *_identity_columns(),
        sa.Column("collection_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("profile", sa.String(length=32), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("semantic_hash", sa.String(length=64), nullable=True),
        sa.Column("raw_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("normalized_projection", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["collection_id"], ["context_collections.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("collection_id", name="uq_context_snapshots_collection"),
    )
    op.create_index("ix_context_snapshots_device_profile_collected", "context_snapshots", ["device_id", "profile", "collected_at"])
    op.create_table(
        "context_diffs", *_identity_columns(),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("profile", sa.String(length=32), nullable=False),
        sa.Column("before_snapshot_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("after_snapshot_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("diff_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["before_snapshot_id"], ["context_snapshots.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["after_snapshot_id"], ["context_snapshots.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("before_snapshot_id", "after_snapshot_id", name="uq_context_diffs_pair"),
    )
    op.create_index("ix_context_diffs_device_profile", "context_diffs", ["device_id", "profile"])
    op.create_table(
        "context_current", *_identity_columns(),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("profile", sa.String(length=32), nullable=False),
        sa.Column("snapshot_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["context_snapshots.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id", "profile", name="uq_context_current_device_profile"),
    )
    op.create_index("ix_context_current_device_profile", "context_current", ["device_id", "profile"])
    op.create_table(
        "context_findings", *_identity_columns(),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("snapshot_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("code", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("details", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["context_snapshots.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_context_findings_device_snapshot", "context_findings", ["device_id", "snapshot_id"])


def downgrade() -> None:
    op.drop_index("ix_context_findings_device_snapshot", table_name="context_findings")
    op.drop_table("context_findings")
    op.drop_index("ix_context_current_device_profile", table_name="context_current")
    op.drop_table("context_current")
    op.drop_index("ix_context_diffs_device_profile", table_name="context_diffs")
    op.drop_table("context_diffs")
    op.drop_index("ix_context_snapshots_device_profile_collected", table_name="context_snapshots")
    op.drop_table("context_snapshots")
    op.drop_index("ix_context_collections_result", table_name="context_collections")
    op.drop_index("ix_context_collections_device_profile_status", table_name="context_collections")
    op.drop_table("context_collections")
