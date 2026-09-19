"""Persist encrypted recovery envelopes for universal request claims."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0021_request_claim_envelopes"
down_revision: str | None = "0020_enrollment_requests"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "enrollment_request_claim_envelopes",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("enrollment_request_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("claim_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("receipt_digest", sa.String(length=256), nullable=False),
        sa.Column("fingerprint_digest", sa.String(length=256), nullable=False),
        sa.Column("encrypted_token", sa.LargeBinary(), nullable=False),
        sa.Column("encryption_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["enrollment_request_id"], ["enrollment_requests.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["claim_id"], ["enrollment_claims.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("enrollment_request_id", name="uq_request_claim_envelopes_request"),
        sa.UniqueConstraint("claim_id", name="uq_request_claim_envelopes_claim"),
        sa.UniqueConstraint("receipt_digest", name="uq_request_claim_envelopes_receipt"),
    )


def downgrade() -> None:
    op.drop_table("enrollment_request_claim_envelopes")
