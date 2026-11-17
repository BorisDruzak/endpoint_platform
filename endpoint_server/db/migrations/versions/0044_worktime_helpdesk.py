"""Explicit local Helpdesk identities and isolated WorkTime authority."""
from alembic import op
import sqlalchemy as sa

revision='0044_worktime_helpdesk'
down_revision='0043_worktime_recorded'
branch_labels=None
depends_on=None


def upgrade():
    op.add_column('confirmed_identities',sa.Column('authority_kind',sa.String(16),nullable=False,server_default='oidc'))
    op.alter_column('confirmed_identities','ad_object_guid',nullable=True)
    op.create_check_constraint('ck_confirmed_identity_authority','confirmed_identities',"(authority_kind = 'oidc' AND ad_object_guid IS NOT NULL) OR (authority_kind = 'helpdesk' AND ad_object_guid IS NULL AND admin_user_id IS NULL)")
    common=lambda:[sa.Column('id',sa.Uuid(),primary_key=True),sa.Column('created_at',sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now())]
    op.create_table('worktime_login_flows',*common(),sa.Column('state_digest',sa.String(64),nullable=False,unique=True),
        sa.Column('browser_digest',sa.String(64),nullable=False),sa.Column('verifier_encrypted',sa.Text(),nullable=False),
        sa.Column('expires_at',sa.DateTime(timezone=True),nullable=False),sa.Column('consumed_at',sa.DateTime(timezone=True)))
    op.create_table('helpdesk_worktime_sessions',*common(),sa.Column('identity_id',sa.Uuid(),sa.ForeignKey('confirmed_identities.id'),nullable=False),
        sa.Column('session_digest',sa.String(64),nullable=False,unique=True),sa.Column('lease_encrypted',sa.Text(),nullable=False),
        sa.Column('expires_at',sa.DateTime(timezone=True),nullable=False),sa.Column('revoked_at',sa.DateTime(timezone=True)))


def downgrade():
    # Refuse to erase adopted identities/history or recreate a fake AD identity.
    op.execute("DO $$ BEGIN IF EXISTS (SELECT 1 FROM confirmed_identities WHERE authority_kind='helpdesk') THEN RAISE EXCEPTION 'Helpdesk persons require explicit rollback reconciliation'; END IF; END $$")
    op.drop_table('helpdesk_worktime_sessions');op.drop_table('worktime_login_flows')
    op.drop_constraint('ck_confirmed_identity_authority','confirmed_identities',type_='check')
    op.alter_column('confirmed_identities','ad_object_guid',nullable=False)
    op.drop_column('confirmed_identities','authority_kind')
