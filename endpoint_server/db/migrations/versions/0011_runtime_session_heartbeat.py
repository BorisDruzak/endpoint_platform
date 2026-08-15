"""Persist server-observed runtime heartbeat time on durable sessions.

Revision ID: 0011_runtime_session_heartbeat
Revises: 0010_session_last_seen_index
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0011_runtime_session_heartbeat"
down_revision: str | None = "0010_session_last_seen_index"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "device_instances",
        "agent_version",
        type_=sa.String(length=128),
        existing_type=sa.String(length=64),
        existing_nullable=False,
    )
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
        "ix_device_sessions_device_handshake_id_desc", table_name="device_sessions"
    )
    op.drop_column("device_sessions", "last_handshake_at")
    op.alter_column(
        "device_instances",
        "agent_version",
        type_=sa.String(length=64),
        existing_type=sa.String(length=128),
        existing_nullable=False,
    )
