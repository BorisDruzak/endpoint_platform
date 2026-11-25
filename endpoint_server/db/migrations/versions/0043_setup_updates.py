"""Separate immutable full Setup releases, client presence and device assignments."""
from alembic import op
import sqlalchemy as sa

revision = '0043_setup_updates'
down_revision = '0042_worktime_companion'
branch_labels = None
depends_on = None


def identity():
    return (sa.Column('id', sa.Uuid(), primary_key=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))


def upgrade():
    op.create_table('setup_update_releases', *identity(),
        sa.Column('release_identifier', sa.String(128), nullable=False, unique=True),
        sa.Column('version', sa.String(64), nullable=False),
        sa.Column('artifact_name', sa.String(256), nullable=False, unique=True),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('size', sa.BigInteger(), nullable=False),
        sa.Column('source_revision', sa.String(40), nullable=False),
        sa.Column('msi_sha256', sa.String(64), nullable=False),
        sa.Column('tray_sha256', sa.String(64), nullable=False),
        sa.Column('sensor_sha256', sa.String(64), nullable=False))
    op.create_table('setup_update_clients', *identity(),
        sa.Column('device_id', sa.Uuid(), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('client_version', sa.String(32), nullable=False),
        sa.Column('foundation_version', sa.String(64)), sa.Column('core_version', sa.String(64)),
        sa.Column('ready', sa.Boolean(), nullable=False), sa.Column('safe_code', sa.String(128)),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False))
    op.create_table('setup_update_assignments', *identity(),
        sa.Column('device_id', sa.Uuid(), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.Column('release_id', sa.Uuid(), sa.ForeignKey('setup_update_releases.id'), nullable=False),
        sa.Column('status', sa.String(32), nullable=False), sa.Column('reason', sa.String(256), nullable=False),
        sa.Column('assigned_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True)), sa.Column('finished_at', sa.DateTime(timezone=True)),
        sa.Column('attempt_id', sa.Uuid()), sa.Column('safe_code', sa.String(128)),
        sa.Column('last_report', sa.JSON()))
    op.create_index('ix_setup_update_assignments_device_id', 'setup_update_assignments', ['device_id'])
    op.create_index('uq_setup_update_active_device', 'setup_update_assignments', ['device_id'], unique=True,
        postgresql_where=sa.text("status IN ('assigned','downloading','verified','installing','verifying')"),
        sqlite_where=sa.text("status IN ('assigned','downloading','verified','installing','verifying')"))
    op.create_table('setup_update_preparations', *identity(),
        sa.Column('device_id', sa.Uuid(), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.Column('release_id', sa.Uuid(), sa.ForeignKey('setup_update_releases.id'), nullable=False),
        sa.Column('bridge_rollout_id', sa.Uuid(), sa.ForeignKey('update_rollouts.id'), nullable=False),
        sa.Column('return_build_id', sa.Uuid(), sa.ForeignKey('update_builds.id')),
        sa.Column('return_rollout_id', sa.Uuid(), sa.ForeignKey('update_rollouts.id')),
        sa.Column('assignment_id', sa.Uuid(), sa.ForeignKey('setup_update_assignments.id')),
        sa.Column('status', sa.String(32), nullable=False),
        sa.Column('reason', sa.String(256), nullable=False),
        sa.Column('requested_by', sa.String(128), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('safe_code', sa.String(128)))
    op.create_index('ix_setup_update_preparations_device_id', 'setup_update_preparations', ['device_id'])
    op.create_index('uq_setup_preparation_active_device', 'setup_update_preparations', ['device_id'], unique=True,
        postgresql_where=sa.text("status IN ('preparing_client','restoring_core')"),
        sqlite_where=sa.text("status IN ('preparing_client','restoring_core')"))


def downgrade():
    op.drop_table('setup_update_preparations')
    op.drop_table('setup_update_assignments')
    op.drop_table('setup_update_clients')
    op.drop_table('setup_update_releases')
