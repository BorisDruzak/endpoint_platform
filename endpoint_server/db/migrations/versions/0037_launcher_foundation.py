"""Persist reported launcher foundation and immutable build requirements.

Revision ID: 0037_launcher_foundation
Revises: 0036_device_binding
"""

from alembic import op
import sqlalchemy as sa


revision = "0037_launcher_foundation"
down_revision = "0036_device_binding"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Legacy foundation stays unknown: a core version cannot establish it.
    op.add_column(
        "device_instances",
        sa.Column("launcher_version", sa.String(128), nullable=True),
    )
    op.add_column(
        "update_builds",
        sa.Column("minimum_launcher_version", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("update_builds", "minimum_launcher_version")
    op.drop_column("device_instances", "launcher_version")
