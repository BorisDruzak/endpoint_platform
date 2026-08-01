"""Add durable Gateway WSS presence and result sequence metadata.

Revision ID: 0011_gateway_wss
Revises: 0010_session_last_seen_index
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0011_gateway_wss"
down_revision: str | None = "0010_session_last_seen_index"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "device_instances",
        "agent_version",
        existing_type=sa.String(length=64),
        type_=sa.String(length=128),
        existing_nullable=False,
    )
    op.add_column(
        "device_instances",
        sa.Column(
            "last_result_sequence",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )
    op.create_check_constraint(
        "ck_device_instances_last_result_sequence",
        "device_instances",
        "last_result_sequence >= 0",
    )
    op.add_column(
        "device_sessions",
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "device_sessions",
        sa.Column("source_address", sa.String(length=45), nullable=True),
    )
    op.add_column(
        "command_results",
        sa.Column("result_sequence", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "command_results",
        sa.Column("result_payload_digest", sa.String(length=64), nullable=True),
    )
    op.create_check_constraint(
        "ck_command_results_result_sequence",
        "command_results",
        "result_sequence IS NULL OR result_sequence >= 0",
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM device_instances WHERE length(agent_version) > 64) THEN
                RAISE EXCEPTION 'cannot downgrade: agent_version exceeds 64 characters';
            END IF;
        END
        $$;
        """
    )
    op.drop_constraint(
        "ck_command_results_result_sequence",
        "command_results",
        type_="check",
    )
    op.drop_column("command_results", "result_payload_digest")
    op.drop_column("command_results", "result_sequence")
    op.drop_column("device_sessions", "source_address")
    op.drop_column("device_sessions", "last_seen_at")
    op.drop_constraint(
        "ck_device_instances_last_result_sequence",
        "device_instances",
        type_="check",
    )
    op.drop_column("device_instances", "last_result_sequence")
    op.alter_column(
        "device_instances",
        "agent_version",
        existing_type=sa.String(length=128),
        type_=sa.String(length=64),
        existing_nullable=False,
    )
