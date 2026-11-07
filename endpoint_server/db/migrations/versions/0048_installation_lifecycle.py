"""Causal installation facts; no inferred state or release metadata backfill."""
from alembic import op
import sqlalchemy as sa
revision='0048_installation_lifecycle'
down_revision='0047_support_install_access'
branch_labels=None
depends_on=None

def identity():
    return [sa.Column('id',sa.Uuid(),primary_key=True),sa.Column('created_at',sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now())]

def upgrade():
    op.add_column('windows_setup_releases',sa.Column('product_code',sa.String(38),nullable=True))
    op.add_column('windows_setup_releases',sa.Column('download_published',sa.Boolean(),nullable=False,server_default=sa.true()))
    op.create_table('installation_events',*identity(),
        sa.Column('device_id',sa.Uuid(),sa.ForeignKey('devices.id'),nullable=False),
        sa.Column('source_credential_id',sa.Uuid(),sa.ForeignKey('device_credentials.id'),nullable=False),
        sa.Column('generation_id',sa.Uuid(),nullable=False),sa.Column('sequence',sa.Integer(),nullable=False),
        sa.Column('previous_event_id',sa.Uuid(),sa.ForeignKey('installation_events.id')),
        sa.Column('action',sa.String(16),nullable=False),sa.Column('occurred_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('received_at',sa.DateTime(timezone=True),nullable=False),sa.Column('payload',sa.JSON(),nullable=False),
        sa.Column('acknowledgement',sa.JSON(),nullable=False),
        sa.UniqueConstraint('device_id','generation_id','sequence',name='uq_installation_event_sequence'),
        sa.CheckConstraint('sequence BETWEEN 1 AND 2147483647',name='ck_installation_event_sequence'))
    op.create_index('ix_installation_events_device_id','installation_events',['device_id'])
    op.create_table('installation_states',*identity(),
        sa.Column('device_id',sa.Uuid(),sa.ForeignKey('devices.id'),unique=True,nullable=False),
        sa.Column('generation_id',sa.Uuid(),nullable=False),sa.Column('sequence',sa.Integer(),nullable=False),
        sa.Column('event_id',sa.Uuid(),sa.ForeignKey('installation_events.id'),nullable=False),
        sa.Column('state',sa.String(16),nullable=False),sa.Column('received_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('support_revision',sa.Integer()),sa.Column('support_generation',sa.Integer()),
        sa.Column('support_credential_id',sa.Uuid(),sa.ForeignKey('device_credentials.id')),
        sa.Column('support_auto_eligible',sa.Boolean(),nullable=False,server_default=sa.false()),
        sa.Column('support_rebind_until',sa.DateTime(timezone=True)))
    op.create_table('installation_parents',*identity(),
        sa.Column('enrollment_request_id',sa.Uuid(),sa.ForeignKey('enrollment_requests.id'),unique=True,nullable=False),
        sa.Column('previous_device_id',sa.Uuid(),sa.ForeignKey('devices.id'),nullable=False),
        sa.Column('removed_event_id',sa.Uuid(),sa.ForeignKey('installation_events.id'),nullable=False),
        sa.Column('approved_by',sa.Uuid(),sa.ForeignKey('admin_users.id'),nullable=False))


def downgrade():
    op.drop_table('installation_parents');op.drop_table('installation_states');op.drop_table('installation_events')
    op.drop_column('windows_setup_releases','product_code')
    op.drop_column('windows_setup_releases','download_published')
