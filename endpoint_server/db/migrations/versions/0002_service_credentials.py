"""Add exact scopes and public lookup prefixes to service credentials.

Revision ID: 0002_service_credentials
Revises: 0001_initial
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0002_service_credentials"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "service_credentials",
        sa.Column("token_prefix", sa.String(length=160), nullable=True),
    )
    op.execute(
        "UPDATE service_credentials "
        "SET token_prefix = 'svc_migrated_' || replace(id::text, '-', '')"
    )
    op.alter_column(
        "service_credentials",
        "token_prefix",
        existing_type=sa.String(length=160),
        nullable=False,
    )
    op.create_unique_constraint(
        "uq_service_credentials_token_prefix",
        "service_credentials",
        ["token_prefix"],
    )
    op.add_column(
        "service_credentials",
        sa.Column(
            "scopes",
            postgresql.ARRAY(sa.String(length=128)),
            server_default=sa.text("'{}'::varchar[]"),
            nullable=False,
        ),
    )
    op.alter_column(
        "service_credentials",
        "scopes",
        existing_type=postgresql.ARRAY(sa.String(length=128)),
        server_default=None,
    )


def downgrade() -> None:
    op.drop_column("service_credentials", "scopes")
    op.drop_constraint(
        "uq_service_credentials_token_prefix",
        "service_credentials",
        type_="unique",
    )
    op.drop_column("service_credentials", "token_prefix")
