"""Add independent bounded SecurityEvent audit ledger.

Revision ID: 0032_security_events
Revises: 0031_browser_sensor_release
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0032_security_events"
down_revision = "0031_browser_sensor_release"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policy_applications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("policy_version_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("policy_versions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("policy_digest", sa.String(64), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("device_id", "policy_version_id", "applied_at", name="uq_policy_applications_device_version_time"),
    )
    op.create_index(
        "ix_policy_applications_device_applied", "policy_applications",
        ["device_id", "applied_at"],
    )
    op.create_table(
        "security_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("event_identifier", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "device_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_login", sa.String(256)),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column(
            "safe_metadata",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "device_id", "event_identifier", name="uq_security_events_device_identifier"
        ),
        sa.CheckConstraint(
            "(channel = 'USB' AND event_type IN ('USB_DEVICE_CONNECTED', 'USB_DEVICE_DISCONNECTED')) "
            "OR (channel = 'PRINT' AND event_type = 'PRINT_JOB') "
            "OR (channel = 'BROWSER' AND event_type IN ('BROWSER_UPLOAD', 'BROWSER_PASTE'))",
            name="ck_security_events_type_channel",
        ),
        sa.CheckConstraint(
            "severity = 'INFO'", name="ck_security_events_audit_severity"
        ),
    )
    op.create_index(
        "ix_security_events_device_occurred",
        "security_events",
        ["device_id", "occurred_at", "id"],
    )
    op.create_index(
        "ix_security_events_expires", "security_events", ["expires_at", "id"]
    )
    op.create_index(
        "ix_security_events_type_occurred",
        "security_events",
        ["event_type", "occurred_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_security_events_type_occurred", table_name="security_events")
    op.drop_index("ix_security_events_expires", table_name="security_events")
    op.drop_index("ix_security_events_device_occurred", table_name="security_events")
    op.drop_table("security_events")
    op.drop_index("ix_policy_applications_device_applied", table_name="policy_applications")
    op.drop_table("policy_applications")
