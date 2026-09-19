"""Persist universal Windows pre-enrollment requests."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0020_enrollment_requests"
down_revision: str | None = "0019_module_step_count_backfill"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_ACTIVE_STATUSES = (
    "'created', 'validating', 'auto_approved', 'waiting_approval', "
    "'review_required', 'claim_issued', 'enrolling', 'device_registered', "
    "'waiting_wss'"
)


def upgrade() -> None:
    op.create_table(
        "enrollment_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("installation_id_digest", sa.String(length=256), nullable=False),
        sa.Column("fingerprint_digest", sa.String(length=256), nullable=False),
        sa.Column("request_capability_digest", sa.String(length=256), nullable=False),
        sa.Column("platform", sa.String(length=64), nullable=False),
        sa.Column("hostname", sa.String(length=256), nullable=False),
        sa.Column("manufacturer", sa.String(length=256)),
        sa.Column("model", sa.String(length=256)),
        sa.Column("serial", sa.String(length=256)),
        sa.Column("product_uuid", sa.String(length=64)),
        sa.Column("macs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("source_address", sa.String(length=64), nullable=False),
        sa.Column("installer_version", sa.String(length=128), nullable=False),
        sa.Column("installer_release_id", sa.String(length=128), nullable=False),
        sa.Column("selected_campaign_id", postgresql.UUID(as_uuid=True)),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("decision_reason", sa.String(length=128)),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("decided_by", postgresql.UUID(as_uuid=True)),
        sa.Column("device_id", postgresql.UUID(as_uuid=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["selected_campaign_id"], ["enrollment_campaigns.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["decided_by"], ["admin_users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_enrollment_requests_expires_at", "enrollment_requests", ["expires_at"])
    op.create_index(
        "uq_enrollment_requests_active_installation",
        "enrollment_requests",
        ["installation_id_digest"],
        unique=True,
        postgresql_where=sa.text(f"status IN ({_ACTIVE_STATUSES})"),
    )
    op.add_column(
        "enrollment_claims",
        sa.Column("enrollment_request_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_enrollment_claims_enrollment_request",
        "enrollment_claims",
        "enrollment_requests",
        ["enrollment_request_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_unique_constraint(
        "uq_enrollment_claims_enrollment_request",
        "enrollment_claims",
        ["enrollment_request_id"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_enrollment_claims_enrollment_request", "enrollment_claims", type_="unique")
    op.drop_constraint("fk_enrollment_claims_enrollment_request", "enrollment_claims", type_="foreignkey")
    op.drop_column("enrollment_claims", "enrollment_request_id")
    op.drop_index("uq_enrollment_requests_active_installation", table_name="enrollment_requests")
    op.drop_index("ix_enrollment_requests_expires_at", table_name="enrollment_requests")
    op.drop_table("enrollment_requests")
