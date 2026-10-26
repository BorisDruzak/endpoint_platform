"""Separate confirmed identity, OIDC flow and employee browser authority."""
from alembic import op
import sqlalchemy as sa

revision = '0040_identity_sso'
down_revision = '0039_power_source_state'
branch_labels = None
depends_on = None


def ownership():
    return [sa.Column('id',sa.Uuid(),primary_key=True),sa.Column('created_at',sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now())]


def upgrade():
    op.add_column('admin_users',sa.Column('sso_migrated_at',sa.DateTime(timezone=True)))
    op.add_column('admin_sessions',sa.Column('auth_method',sa.String(16),nullable=False,server_default='local'))
    op.create_check_constraint('ck_admin_session_auth_method','admin_sessions',"auth_method IN ('local','oidc','breakglass')")
    op.create_table('confirmed_identities',*ownership(),
        sa.Column('person_id',sa.Uuid(),nullable=False,unique=True),sa.Column('department_id',sa.Uuid()),
        sa.Column('issuer',sa.String(512),nullable=False),sa.Column('subject',sa.String(255),nullable=False),
        sa.Column('ad_object_guid',sa.Uuid(),nullable=False,unique=True),sa.Column('state',sa.String(16),nullable=False),
        sa.Column('admin_user_id',sa.Uuid(),sa.ForeignKey('admin_users.id'),unique=True),
        sa.Column('confirmed_at',sa.DateTime(timezone=True),nullable=False),sa.Column('revoked_at',sa.DateTime(timezone=True)),
        sa.UniqueConstraint('issuer','subject',name='uq_confirmed_identity_subject'),
        sa.CheckConstraint("state IN ('active','revoked')",name='ck_confirmed_identity_state'))
    op.create_table('oidc_flows',*ownership(),sa.Column('state_digest',sa.String(64),nullable=False,unique=True),
        sa.Column('browser_digest',sa.String(64),nullable=False),sa.Column('realm',sa.String(16),nullable=False),
        sa.Column('encrypted_material',sa.Text(),nullable=False),sa.Column('expires_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('consumed_at',sa.DateTime(timezone=True)),sa.CheckConstraint("realm IN ('admin','employee')",name='ck_oidc_flow_realm'))
    op.create_table('oidc_upstream_sessions',*ownership(),
        sa.Column('identity_id',sa.Uuid(),sa.ForeignKey('confirmed_identities.id'),nullable=False),sa.Column('realm',sa.String(16),nullable=False),
        sa.Column('sid',sa.String(255),nullable=False),sa.Column('encrypted_tokens',sa.Text(),nullable=False),
        sa.Column('expires_at',sa.DateTime(timezone=True),nullable=False),sa.Column('checked_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('achieved_acr',sa.String(255),nullable=False,server_default=''),sa.Column('absolute_expires_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('revoked_at',sa.DateTime(timezone=True)),sa.Column('admin_session_id',sa.Uuid(),sa.ForeignKey('admin_sessions.id',ondelete='CASCADE'),unique=True),
        sa.CheckConstraint("realm IN ('admin','employee')",name='ck_upstream_realm'))
    op.create_table('employee_sessions',*ownership(),sa.Column('identity_id',sa.Uuid(),sa.ForeignKey('confirmed_identities.id'),nullable=False),
        sa.Column('upstream_session_id',sa.Uuid(),sa.ForeignKey('oidc_upstream_sessions.id'),nullable=False),
        sa.Column('session_digest',sa.String(64),nullable=False,unique=True),sa.Column('expires_at',sa.DateTime(timezone=True),nullable=False),sa.Column('revoked_at',sa.DateTime(timezone=True)))
    op.create_table('scoped_role_grants',*ownership(),sa.Column('identity_id',sa.Uuid(),sa.ForeignKey('confirmed_identities.id'),nullable=False),
        sa.Column('role',sa.String(32),nullable=False),sa.Column('department_id',sa.Uuid()),
        sa.Column('granted_by',sa.Uuid(),sa.ForeignKey('admin_users.id'),nullable=False),sa.Column('revoked_at',sa.DateTime(timezone=True)),
        sa.CheckConstraint("role IN ('employee','manager','hr','worktime_admin','endpoint_admin','dlp_officer')",name='ck_scoped_role'),
        sa.CheckConstraint("role != 'manager' OR department_id IS NOT NULL",name='ck_manager_department'))
    op.create_index('ix_scoped_role_grants_identity_id','scoped_role_grants',['identity_id'])


def downgrade():
    for table in ['scoped_role_grants','employee_sessions','oidc_upstream_sessions','oidc_flows','confirmed_identities']:
        op.drop_table(table)
    op.drop_constraint('ck_admin_session_auth_method','admin_sessions',type_='check')
    op.drop_column('admin_sessions','auth_method')
    op.drop_column('admin_users','sso_migrated_at')
