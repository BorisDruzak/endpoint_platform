"""Bind Linux source requests to canonical consumed enrollment identities."""
from alembic import op
import sqlalchemy as sa

revision = '0050_linux_enrollment_binding'
down_revision = '0049_linux_support_lifecycle'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('linux_enrollment_bindings',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('enrollment_request_id', sa.Uuid(), sa.ForeignKey('enrollment_requests.id', ondelete='RESTRICT'), nullable=False, unique=True),
        sa.Column('native_release_id', sa.Uuid(), sa.ForeignKey('linux_native_releases.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('claim_fingerprint_digest', sa.String(64), nullable=False),
        sa.Column('claim_id', sa.Uuid(), sa.ForeignKey('enrollment_claims.id', ondelete='RESTRICT'), unique=True),
        sa.Column('credential_id', sa.Uuid(), sa.ForeignKey('device_credentials.id', ondelete='RESTRICT'), unique=True),
        sa.CheckConstraint('(claim_id IS NULL) = (credential_id IS NULL)', name='ck_linux_enrollment_consumed_pair'))


def downgrade():
    if op.get_bind().execute(sa.text('SELECT EXISTS (SELECT 1 FROM linux_enrollment_bindings)')).scalar():
        raise RuntimeError('Linux enrollment authority must be preserved before downgrade')
    op.drop_table('linux_enrollment_bindings')
