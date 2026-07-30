"""Persist explicit Device Context snapshot retention pins.

Revision ID: 0009_context_snapshot_pins
Revises: 0008_device_context_foundation
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0009_context_snapshot_pins"
down_revision: str | None = "0008_device_context_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "context_snapshots",
        sa.Column("pinned_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("context_snapshots", "pinned_at")
