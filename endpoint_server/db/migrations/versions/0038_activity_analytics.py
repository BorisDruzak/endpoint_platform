"""Durable measured Activity intervals, cursors and daily aggregates.

Revision ID: 0038_activity_analytics
Revises: 0037_launcher_foundation
"""
from alembic import op
import sqlalchemy as sa

revision = '0038_activity_analytics'
down_revision = '0037_launcher_foundation'
branch_labels = None
depends_on = None


def _ownership():
    return [sa.Column('id', sa.Uuid(), primary_key=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now())]


def upgrade():
    op.create_table('activity_intervals', *_ownership(),
        sa.Column('device_id', sa.Uuid(), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_key', sa.String(300)), sa.Column('user_login', sa.String(256)),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('session_state', sa.String(16), nullable=False),
        sa.Column('process_name', sa.String(128)), sa.Column('application_category', sa.String(32)),
        sa.Column('browser_family', sa.String(32)), sa.Column('policy_version_id', sa.Uuid()),
        sa.CheckConstraint('ended_at >= started_at', name='ck_activity_interval_bounds'),
        sa.CheckConstraint("session_state IN ('ACTIVE','IDLE','LOCKED','DISCONNECTED','UNKNOWN')", name='ck_activity_interval_state'),
    )
    op.create_index('ix_activity_intervals_user_time', 'activity_intervals', ['user_key', 'started_at', 'ended_at'])
    op.create_index('ix_activity_intervals_device_time', 'activity_intervals', ['device_id', 'started_at'])
    op.create_index('ix_activity_intervals_retention', 'activity_intervals', ['ended_at', 'id'])
    op.create_table('activity_cursors', *_ownership(),
        sa.Column('device_id', sa.Uuid(), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_key', sa.String(300)), sa.Column('user_login', sa.String(256)),
        sa.Column('interval_id', sa.Uuid(), sa.ForeignKey('activity_intervals.id', ondelete='SET NULL')),
        sa.Column('observation_id', sa.Uuid(), nullable=False),
        sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('session_state', sa.String(16), nullable=False),
        sa.UniqueConstraint('device_id', name='uq_activity_cursor_device'),
    )
    op.create_index('ix_activity_cursor_user', 'activity_cursors', ['user_key'])
    op.create_table('activity_daily', *_ownership(),
        sa.Column('user_key', sa.String(300), nullable=False),
        sa.Column('timezone', sa.String(64), nullable=False), sa.Column('day', sa.Date(), nullable=False),
        sa.Column('dirty', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.UniqueConstraint('user_key', 'timezone', 'day', name='uq_activity_daily_user_zone_day'),
    )
    op.create_index('ix_activity_daily_report', 'activity_daily', ['timezone', 'day', 'user_key'])
    op.create_index('ix_activity_daily_dirty', 'activity_daily', ['dirty', 'updated_at'])


def downgrade():
    op.drop_table('activity_daily')
    op.drop_table('activity_cursors')
    op.drop_table('activity_intervals')
