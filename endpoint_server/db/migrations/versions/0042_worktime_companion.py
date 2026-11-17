"""Durable, per-request notification delivery independent of telemetry retention."""
from alembic import op
import sqlalchemy as sa

revision = '0042_worktime_companion'
down_revision = '0041_worktime'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('worktime_companion_deliveries',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('request_id', sa.Uuid(), sa.ForeignKey('worktime_explanation_requests.id', ondelete='CASCADE'), nullable=False),
        sa.Column('device_id', sa.Uuid(), sa.ForeignKey('devices.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('user_key', sa.String(300), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('lease_until', sa.DateTime(timezone=True), nullable=False),
        sa.Column('lease_id', sa.Uuid(), nullable=False),
        sa.UniqueConstraint('request_id', name='uq_worktime_companion_request'))


def downgrade():
    op.drop_table('worktime_companion_deliveries')
