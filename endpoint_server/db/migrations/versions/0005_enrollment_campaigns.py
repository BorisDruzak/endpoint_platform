"""Add bounded campaign and install-claim state.

Revision ID: 0005_enrollment_campaigns
Revises: 0004_device_credentials
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0005_enrollment_campaigns"
down_revision: str | None = "0004_device_credentials"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "enrollment_campaigns",
        sa.Column("max_uses", sa.Integer(), nullable=True),
    )
    op.add_column(
        "enrollment_campaigns",
        sa.Column("use_count", sa.Integer(), nullable=True),
    )
    op.add_column(
        "enrollment_campaigns",
        sa.Column(
            "allowed_cidrs",
            postgresql.ARRAY(sa.String(length=64)),
            nullable=True,
        ),
    )
    op.add_column(
        "enrollment_campaigns",
        sa.Column("target_platform", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "enrollment_campaigns",
        sa.Column("policy", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "enrollment_campaigns",
        sa.Column("label", sa.String(length=256), nullable=True),
    )
    op.add_column(
        "enrollment_campaigns",
        sa.Column("site", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "enrollment_campaigns",
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        "UPDATE enrollment_campaigns SET "
        "max_uses = 1, use_count = 0, "
        "allowed_cidrs = ARRAY['0.0.0.0/0', '::/0']::varchar(64)[], "
        "target_platform = 'legacy', policy = '{}'::jsonb"
    )
    for column in (
        "max_uses",
        "use_count",
        "allowed_cidrs",
        "target_platform",
        "policy",
    ):
        op.alter_column("enrollment_campaigns", column, nullable=False)
    op.create_check_constraint(
        "ck_enrollment_campaigns_max_uses_positive",
        "enrollment_campaigns",
        "max_uses > 0",
    )
    op.create_check_constraint(
        "ck_enrollment_campaigns_use_count_bounded",
        "enrollment_campaigns",
        "use_count >= 0 AND use_count <= max_uses",
    )

    op.add_column(
        "enrollment_claims",
        sa.Column("claim_digest", sa.String(length=256), nullable=True),
    )
    op.add_column(
        "enrollment_claims",
        sa.Column(
            "installation_session_digest",
            sa.String(length=256),
            nullable=True,
        ),
    )
    op.add_column(
        "enrollment_claims",
        sa.Column("fingerprint_digest", sa.String(length=256), nullable=True),
    )
    op.add_column(
        "enrollment_claims",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        "UPDATE enrollment_claims SET "
        "claim_digest = 'migrated-claim-' || replace(id::text, '-', ''), "
        "installation_session_digest = "
        "'migrated-session-' || replace(id::text, '-', ''), "
        "fingerprint_digest = "
        "'migrated-fingerprint-' || replace(id::text, '-', ''), "
        "expires_at = created_at"
    )
    for column in (
        "claim_digest",
        "installation_session_digest",
        "fingerprint_digest",
        "expires_at",
    ):
        op.alter_column("enrollment_claims", column, nullable=False)
    op.create_unique_constraint(
        "uq_enrollment_claims_claim_digest",
        "enrollment_claims",
        ["claim_digest"],
    )
    op.create_index(
        "ix_enrollment_claims_expires_at",
        "enrollment_claims",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_enrollment_claims_expires_at",
        table_name="enrollment_claims",
    )
    op.drop_constraint(
        "uq_enrollment_claims_claim_digest",
        "enrollment_claims",
        type_="unique",
    )
    for column in (
        "expires_at",
        "fingerprint_digest",
        "installation_session_digest",
        "claim_digest",
    ):
        op.drop_column("enrollment_claims", column)
    op.drop_constraint(
        "ck_enrollment_campaigns_use_count_bounded",
        "enrollment_campaigns",
        type_="check",
    )
    op.drop_constraint(
        "ck_enrollment_campaigns_max_uses_positive",
        "enrollment_campaigns",
        type_="check",
    )
    for column in (
        "revoked_at",
        "site",
        "label",
        "policy",
        "target_platform",
        "allowed_cidrs",
        "use_count",
        "max_uses",
    ):
        op.drop_column("enrollment_campaigns", column)
