"""Index Gateway delivery lookups by command ID."""

from alembic import op

revision = "0055_command_delivery_lookup"
down_revision = "0054_periodic_context_profiles"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index("ix_command_deliveries_command_id", "command_deliveries", ["command_id"])


def downgrade():
    op.drop_index("ix_command_deliveries_command_id", table_name="command_deliveries")
