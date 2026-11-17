"""Keep the latest negotiated periodic Device Context profiles."""

from alembic import op
import sqlalchemy as sa

revision = "0054_periodic_context_profiles"
down_revision = "0053_activity_dirty_since"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("devices", sa.Column("scheduled_context_profiles", sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table("devices") as batch:
        batch.drop_column("scheduled_context_profiles")
