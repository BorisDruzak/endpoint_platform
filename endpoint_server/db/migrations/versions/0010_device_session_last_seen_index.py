"""Index deterministic device-session last-seen lookups.

Revision ID: 0010_session_last_seen_index
Revises: 0009_context_snapshot_pins
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0010_session_last_seen_index"
down_revision: str | None = "0009_context_snapshot_pins"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_device_sessions_device_created_id_desc",
        "device_sessions",
        ["device_id", sa.text("created_at DESC"), sa.text("id DESC")],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_device_sessions_device_created_id_desc",
        table_name="device_sessions",
    )
