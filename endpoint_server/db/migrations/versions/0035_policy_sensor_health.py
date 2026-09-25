"""Persist one current bounded sensor health report per device.

Revision ID: 0035_policy_sensor_health
Revises: 0034_browser_install_proof
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0035_policy_sensor_health"
down_revision = "0034_browser_install_proof"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policy_sensor_health_current",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("device_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("observation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activity_listener_state", sa.String(16), nullable=False),
        sa.Column("user_sensor_last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("security_spool_state", sa.String(16), nullable=False),
        sa.Column("usb_source_state", sa.String(16), nullable=False),
        sa.Column("print_source_state", sa.String(16), nullable=False),
        sa.UniqueConstraint("device_id", name="uq_policy_sensor_health_device"),
        sa.CheckConstraint(
            "activity_listener_state IN ('READY', 'UNAVAILABLE', 'UNKNOWN') AND "
            "security_spool_state IN ('READY', 'UNAVAILABLE', 'UNKNOWN') AND "
            "usb_source_state IN ('READY', 'UNAVAILABLE', 'UNKNOWN') AND "
            "print_source_state IN ('READY', 'UNAVAILABLE', 'UNKNOWN')",
            name="ck_policy_sensor_health_source_states",
        ),
    )
    op.create_index(
        "ix_policy_sensor_health_observed", "policy_sensor_health_current",
        ["device_id", "observed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_policy_sensor_health_observed",
                  table_name="policy_sensor_health_current")
    op.drop_table("policy_sensor_health_current")
