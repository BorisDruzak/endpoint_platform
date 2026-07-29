"""Persist explicit update administration grants.

Revision ID: 0007_admin_update_scopes
Revises: 0006_update_control_plane
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0007_admin_update_scopes"
down_revision: str | None = "0006_update_control_plane"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "admin_users",
        sa.Column(
            "scopes",
            postgresql.ARRAY(sa.String(length=128)),
            nullable=True,
        ),
    )
    op.execute("UPDATE admin_users SET scopes = ARRAY['updates:write']::varchar[]")
    op.alter_column("admin_users", "scopes", nullable=False)


def downgrade() -> None:
    op.drop_column("admin_users", "scopes")
