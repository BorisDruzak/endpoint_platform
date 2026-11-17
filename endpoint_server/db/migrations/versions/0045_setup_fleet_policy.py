"""Add disabled-by-default full Setup fleet control and authenticated platform."""
from alembic import op
import sqlalchemy as sa

revision = '0045_setup_fleet_policy'
down_revision = '0044_setup_recovery_hold'
branch_labels = None
depends_on = None


def identity():
    return (sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))


def upgrade():
    op.add_column('device_instances', sa.Column('platform', sa.String(64)))
    op.add_column('setup_update_assignments', sa.Column('source_foundation_version', sa.String(64)))
    op.add_column('setup_update_assignments', sa.Column('source_core_version', sa.String(64)))
    op.add_column('setup_update_assignments', sa.Column('source_client_version', sa.String(32)))
    op.create_table('setup_fleet_qualifications', *identity(),
        sa.Column('release_id', sa.Uuid(), sa.ForeignKey('setup_update_releases.id'), nullable=False),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('source_foundation', sa.String(64), nullable=False),
        sa.Column('evidence_assignment_id', sa.Uuid(), sa.ForeignKey('setup_update_assignments.id'), nullable=False),
        sa.Column('qualified_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('qualified_by', sa.String(128), nullable=False),
        sa.Column('evidence_code', sa.String(128), nullable=False),
        sa.UniqueConstraint('release_id', 'sha256', 'source_foundation', name='uq_setup_fleet_qualification'))
    op.create_table('setup_fleet_policy', *identity(),
        sa.Column('policy_key', sa.String(32), nullable=False, unique=True),
        sa.Column('revision', sa.Integer(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('release_id', sa.Uuid(), sa.ForeignKey('setup_update_releases.id')),
        sa.Column('scope', sa.String(32), nullable=False),
        sa.Column('device_ids', sa.JSON(), nullable=False),
        sa.Column('max_parallel', sa.Integer(), nullable=False),
        sa.Column('reason', sa.String(256), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_by', sa.String(128), nullable=False),
        sa.Column('safe_code', sa.String(128)),
        sa.CheckConstraint("policy_key = 'windows-full-setup'", name='ck_setup_fleet_singleton'),
        sa.CheckConstraint('revision > 0', name='ck_setup_fleet_revision'),
        sa.CheckConstraint('max_parallel BETWEEN 1 AND 2', name='ck_setup_fleet_parallel'),
        sa.CheckConstraint("scope IN ('all_active','selected')", name='ck_setup_fleet_scope'))
    op.create_table('setup_fleet_decisions', *identity(),
        sa.Column('policy_id', sa.Uuid(), sa.ForeignKey('setup_fleet_policy.id'), nullable=False),
        sa.Column('policy_revision', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Uuid(), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.Column('release_id', sa.Uuid(), sa.ForeignKey('setup_update_releases.id'), nullable=False),
        sa.Column('target_sha256', sa.String(64), nullable=False),
        sa.Column('status', sa.String(32), nullable=False),
        sa.Column('safe_code', sa.String(128), nullable=False),
        sa.Column('job_id', sa.Uuid()),
        sa.Column('evaluated_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('policy_id', 'policy_revision', 'device_id', 'target_sha256', name='uq_setup_fleet_decision'))
    op.create_index('ix_setup_fleet_decision_scan', 'setup_fleet_decisions', ['policy_id', 'policy_revision', 'evaluated_at'])
    # No target, qualification, policy or assignments are seeded.


def downgrade():
    op.drop_table('setup_fleet_decisions')
    op.drop_table('setup_fleet_policy')
    op.drop_table('setup_fleet_qualifications')
    op.drop_column('setup_update_assignments', 'source_client_version')
    op.drop_column('setup_update_assignments', 'source_core_version')
    op.drop_column('setup_update_assignments', 'source_foundation_version')
    op.drop_column('device_instances', 'platform')
