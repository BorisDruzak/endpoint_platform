"""Add context freshness, durable change events and expiring operation evidence.

Revision ID: 0026_context_evidence_v2
Revises: 0025_console_enrollment_queue
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0026_context_evidence_v2"
down_revision = "0025_console_enrollment_queue"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("context_current", sa.Column("last_observed_at", sa.DateTime(timezone=True)))
    op.add_column("endpoint_operations", sa.Column("error_code", sa.String(64)))
    op.execute("UPDATE context_current SET last_observed_at = updated_at")
    op.alter_column("context_snapshots", "raw_payload", existing_type=postgresql.JSONB(), nullable=True)
    op.create_index("ix_context_collections_raw_retention", "context_collections", ["result_received_at", "id"])
    op.create_index("ix_context_collections_status_requested", "context_collections", ["status", "requested_at", "id"])
    op.create_index("ix_context_snapshots_raw_retention", "context_snapshots", ["collected_at", "id"])
    op.create_index("ix_context_snapshots_profile_retention", "context_snapshots", ["profile", "collected_at", "id"])

    op.create_table(
        "device_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_identifier", sa.String(128), nullable=False),
        sa.Column("event_kind", sa.String(64), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("profile", sa.String(32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_key", sa.String(160), nullable=False),
        sa.Column("summary_code", sa.String(64), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        sa.Column("before_hash", sa.String(64)),
        sa.Column("after_hash", sa.String(64)),
        sa.UniqueConstraint("device_id", "source_key", name="uq_device_events_source"),
        sa.CheckConstraint("length(CAST(details AS TEXT)) <= 2048", name="ck_device_events_details_size"),
    )
    op.create_index("ix_device_events_device_occurred", "device_events", ["device_id", "occurred_at", "id"])
    op.create_index("ix_device_events_kind_occurred", "device_events", ["event_kind", "occurred_at"])

    op.create_table(
        "operation_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("endpoint_operations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("result_kind", sa.String(32), nullable=False),
        sa.Column("safe_payload", postgresql.JSONB()),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("pinned_at", sa.DateTime(timezone=True)),
        sa.Column("pinned_by_actor_kind", sa.String(32)),
        sa.Column("pinned_by_actor_identifier", sa.String(128)),
        sa.Column("pin_reason", sa.String(256)),
        sa.Column("scrubbed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("operation_id", name="uq_operation_evidence_operation"),
        sa.CheckConstraint("pinned_at IS NULL OR expires_at IS NULL", name="ck_operation_evidence_pin_expiry"),
        sa.CheckConstraint("safe_payload IS NULL OR length(CAST(safe_payload AS TEXT)) <= 65536", name="ck_operation_evidence_payload_size"),
    )
    op.create_index("ix_operation_evidence_expiry", "operation_evidence", ["expires_at", "id"])


def downgrade() -> None:
    raise RuntimeError(
        "Context Evidence v2 is forward-only after payload retention begins; "
        "restore the verified database backup with the previous release"
    )
