"""Add Linux support bindings and exact signed native source registry."""
from alembic import op
import sqlalchemy as sa

revision='0049_linux_support_lifecycle'
down_revision='0048_installation_lifecycle'
branch_labels=None
depends_on=None


def upgrade():
    op.add_column('support_access',sa.Column('platform',sa.String(32),nullable=False,server_default='windows_amd64'))
    op.add_column('support_access',sa.Column('linux_admin_username',sa.String(32)))
    op.add_column('support_access',sa.Column('linux_admin_uid',sa.Integer()))
    op.create_check_constraint('ck_support_platform_principal','support_access',
        "(platform = 'windows_amd64' AND linux_admin_username IS NULL AND linux_admin_uid IS NULL) OR "
        "(platform = 'linux_amd64' AND windows_admin_username IS NULL AND "
        "((linux_admin_username IS NULL AND linux_admin_uid IS NULL) OR "
        "(linux_admin_username IS NOT NULL AND linux_admin_uid IS NOT NULL AND linux_admin_uid BETWEEN 0 AND 2147483647)))")
    op.create_table('linux_native_releases',
        sa.Column('id',sa.Uuid(),primary_key=True),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.Column('version',sa.String(17),nullable=False,unique=True),
        sa.Column('source_revision',sa.String(40),nullable=False),
        sa.Column('core_nevra',sa.String(200),nullable=False,unique=True),
        sa.Column('core_rpm_sha256',sa.String(64),nullable=False,unique=True),
        sa.Column('user_sensor_nevra',sa.String(200)),sa.Column('user_sensor_rpm_sha256',sa.String(64)),
        sa.Column('signer_fingerprint',sa.String(64),nullable=False),
        sa.Column('frozen_manifest_sha256',sa.String(64),nullable=False),
        sa.Column('reviewed_by',sa.String(128),nullable=False),
        sa.Column('retired_at',sa.DateTime(timezone=True)),
        sa.CheckConstraint('(user_sensor_nevra IS NULL) = (user_sensor_rpm_sha256 IS NULL)',name='ck_linux_native_sensor_pair'))


def downgrade():
    # Never silently discard Linux policy authority or accepted native history.
    connection=op.get_bind()
    if not connection.dialect.name=='postgresql':
        raise RuntimeError('Linux authority downgrade requires PostgreSQL')
    if connection.execute(sa.text("SELECT EXISTS (SELECT 1 FROM support_access WHERE platform = 'linux_amd64') OR EXISTS (SELECT 1 FROM linux_native_releases)")).scalar():
        raise RuntimeError('Linux support/source authority must be preserved before downgrade')
    op.drop_table('linux_native_releases')
    op.drop_constraint('ck_support_platform_principal','support_access',type_='check')
    op.drop_column('support_access','linux_admin_uid')
    op.drop_column('support_access','linux_admin_username')
    op.drop_column('support_access','platform')
