"""Endpoint device possession challenges and persistent attempt budgets.

Revision ID: 0036_device_binding
"""
from alembic import op
import sqlalchemy as sa

revision = "0036_device_binding"
down_revision = "0035_policy_sensor_health"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("device_binding_challenges",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("code_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("redeemed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("purpose = 'helpdesk_device_binding'", name="ck_binding_challenge_purpose"),
        sa.CheckConstraint("status IN ('active','redeemed','expired','revoked')", name="ck_binding_challenge_status"))
    op.create_index("uq_binding_active_device", "device_binding_challenges", ["device_id","purpose"], unique=True,
        postgresql_where=sa.text("status = 'active'"))
    op.create_index("uq_binding_active_digest", "device_binding_challenges", ["code_digest"], unique=True,
        postgresql_where=sa.text("status = 'active'"))
    op.create_index("ix_binding_challenge_expiry", "device_binding_challenges", ["status","expires_at"])
    op.create_table("device_binding_throttles",
        sa.Column("bucket", sa.String(128), primary_key=True),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.CheckConstraint("attempts >= 0", name="ck_binding_throttle_attempts"))


def downgrade():
    op.drop_table("device_binding_throttles")
    op.drop_table("device_binding_challenges")
