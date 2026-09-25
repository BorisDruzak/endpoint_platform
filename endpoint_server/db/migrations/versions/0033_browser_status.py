"""Persist separate current Chrome and Yandex Browser Sensor facts.

Revision ID: 0033_browser_status
Revises: 0032_security_events
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0033_browser_status"
down_revision = "0032_security_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "browser_status_current",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "device_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("browser_family", sa.String(16), nullable=False),
        sa.Column("observation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("browser_state", sa.String(16), nullable=False),
        sa.Column("running_state", sa.String(16), nullable=False),
        sa.Column("policy_owner", sa.String(16), nullable=False),
        sa.Column("installation_policy_state", sa.String(16), nullable=False),
        sa.Column("native_host_state", sa.String(16), nullable=False),
        sa.Column("extension_version", sa.String(32)),
        sa.Column("extension_last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("last_running_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "device_id", "browser_family", name="uq_browser_status_device_family",
        ),
        sa.CheckConstraint(
            "browser_family IN ('chrome', 'yandex')", name="ck_browser_status_family",
        ),
    )
    op.create_index(
        "ix_browser_status_observed", "browser_status_current",
        ["device_id", "observed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_browser_status_observed", table_name="browser_status_current")
    op.drop_table("browser_status_current")
