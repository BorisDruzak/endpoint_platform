"""Independent support key authority, disabled by default; no seeded leases."""
from alembic import op
import sqlalchemy as sa

revision='0046_support_access'
down_revision='0045_setup_fleet_policy'
branch_labels=None
depends_on=None


def upgrade():
    op.create_table('support_access',
        sa.Column('id',sa.Uuid(),primary_key=True),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.Column('device_id',sa.Uuid(),sa.ForeignKey('devices.id'),nullable=False,unique=True),
        sa.Column('source_credential_id',sa.Uuid(),sa.ForeignKey('device_credentials.id'),nullable=False),
        sa.Column('tunnel_public_key',sa.String(128),nullable=False,unique=True),
        sa.Column('host_public_key',sa.String(128),nullable=False,unique=True),
        sa.Column('remote_port',sa.Integer(),nullable=False,unique=True),
        sa.Column('component_version',sa.String(20),nullable=False),
        sa.Column('revision',sa.Integer(),nullable=False),
        sa.Column('generation',sa.Integer(),nullable=False),
        sa.Column('enabled',sa.Boolean(),nullable=False,server_default=sa.false()),
        sa.Column('reset_registration_allowed',sa.Boolean(),nullable=False,server_default=sa.false()),
        sa.Column('expires_at',sa.DateTime(timezone=True)),
        sa.Column('revoked_at',sa.DateTime(timezone=True)),
        sa.Column('operator_public_keys',sa.JSON(),nullable=False),
        sa.Column('windows_admin_username',sa.String(64)),
        sa.Column('installed',sa.Boolean(),nullable=False),
        sa.Column('tunnel_connected',sa.Boolean(),nullable=False),
        sa.Column('reported_at',sa.DateTime(timezone=True)),
        sa.Column('last_error_code',sa.String(64)),
        sa.Column('access_verified_at',sa.DateTime(timezone=True)),
        sa.Column('access_verified_by',sa.String(128)),
        sa.CheckConstraint('remote_port BETWEEN 32000 AND 41999',name='ck_support_port'))


def downgrade():
    op.drop_table('support_access')
