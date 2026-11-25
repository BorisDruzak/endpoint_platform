"""One-time bounded installation intent; existing registrations remain untouched."""
from alembic import op
import sqlalchemy as sa

revision = '0047_support_install_access'
down_revision = '0046_support_access'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('support_access', sa.Column('installation_access_pending_until', sa.DateTime(timezone=True), nullable=True))


def downgrade():
    op.drop_column('support_access', 'installation_access_pending_until')
