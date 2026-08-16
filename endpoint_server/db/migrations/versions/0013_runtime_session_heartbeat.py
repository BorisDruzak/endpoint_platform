"""Persist server-observed runtime heartbeat time on durable sessions."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0013_runtime_session_heartbeat"
down_revision: str | None = "0012_gateway_campaign_merge"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "device_sessions",
        sa.Column("last_handshake_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_device_sessions_device_handshake_id_desc",
        "device_sessions",
        ["device_id", sa.text("last_handshake_at DESC"), sa.text("id DESC")],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_device_sessions_device_handshake_id_desc",
        table_name="device_sessions",
    )
    op.drop_column("device_sessions", "last_handshake_at")
