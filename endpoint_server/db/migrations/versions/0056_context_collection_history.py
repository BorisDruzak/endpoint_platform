"""Index per-device Context collection history in scheduler order."""

import sqlalchemy as sa
from alembic import op

revision = "0056_context_collection_history"
down_revision = "0055_command_delivery_lookup"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        "ix_context_collections_device_profile_requested",
        "context_collections",
        ["device_id", "profile", sa.text("requested_at DESC"), sa.text("id DESC")],
    )


def downgrade():
    op.drop_index(
        "ix_context_collections_device_profile_requested",
        table_name="context_collections",
    )
