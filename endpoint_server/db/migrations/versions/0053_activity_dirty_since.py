"""Track when a daily rollup first becomes dirty."""

from alembic import op
import sqlalchemy as sa

revision = "0053_activity_dirty_since"
down_revision = "0052_inventory_installation"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("activity_daily", sa.Column("dirty_since", sa.DateTime(timezone=True)))


def downgrade():
    with op.batch_alter_table("activity_daily") as batch:
        batch.drop_column("dirty_since")
