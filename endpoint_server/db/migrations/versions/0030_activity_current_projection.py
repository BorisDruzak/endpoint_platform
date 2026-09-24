"""Keep the latest bounded Activity observation beside immutable state snapshots.

Revision ID: 0030_activity_current_projection
Revises: 0029_endpoint_policy_dlp_v1
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0030_activity_current_projection"
down_revision = "0029_endpoint_policy_dlp_v1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("context_current", sa.Column("last_projection", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("context_current", "last_projection")
