"""Add device credential rotation and encrypted retry-envelope state.

Revision ID: 0004_device_credentials
Revises: 0003_immutable_audit
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0004_device_credentials"
down_revision: str | None = "0003_immutable_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "device_credentials",
        sa.Column("pending_token_digest", sa.String(length=256), nullable=True),
    )
    op.add_column(
        "device_credentials",
        sa.Column(
            "rotation_overlap_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.create_unique_constraint(
        "uq_device_credentials_pending_token_digest",
        "device_credentials",
        ["pending_token_digest"],
    )
    op.create_table(
        "enrollment_retry_envelopes",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "device_credential_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("receipt_digest", sa.String(length=256), nullable=False),
        sa.Column("fingerprint_digest", sa.String(length=256), nullable=False),
        sa.Column("encrypted_token", sa.LargeBinary(), nullable=False),
        sa.Column("encryption_nonce", sa.LargeBinary(), nullable=False),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["device_credential_id"],
            ["device_credentials.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "device_credential_id",
            name="uq_enrollment_retry_envelopes_device_credential",
        ),
        sa.UniqueConstraint(
            "receipt_digest",
            name="uq_enrollment_retry_envelopes_receipt_digest",
        ),
    )
    op.create_index(
        "ix_enrollment_retry_envelopes_expires_at",
        "enrollment_retry_envelopes",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_enrollment_retry_envelopes_expires_at",
        table_name="enrollment_retry_envelopes",
    )
    op.drop_table("enrollment_retry_envelopes")
    op.drop_constraint(
        "uq_device_credentials_pending_token_digest",
        "device_credentials",
        type_="unique",
    )
    op.drop_column("device_credentials", "rotation_overlap_expires_at")
    op.drop_column("device_credentials", "pending_token_digest")
