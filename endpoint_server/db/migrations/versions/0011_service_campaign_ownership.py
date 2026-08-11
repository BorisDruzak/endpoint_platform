"""Track the service client that created an enrollment campaign.

Revision ID: 0011_service_campaign_ownership
Revises: 0010_session_last_seen_index
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0011_service_campaign_ownership"
down_revision: str | None = "0010_session_last_seen_index"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "enrollment_campaigns",
        sa.Column(
            "owner_service_client_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_enrollment_campaigns_owner_service_client_id",
        "enrollment_campaigns",
        "service_clients",
        ["owner_service_client_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_enrollment_campaigns_owner_service_client_id",
        "enrollment_campaigns",
        ["owner_service_client_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_enrollment_campaigns_owner_service_client_id",
        table_name="enrollment_campaigns",
    )
    op.drop_constraint(
        "fk_enrollment_campaigns_owner_service_client_id",
        "enrollment_campaigns",
        type_="foreignkey",
    )
    op.drop_column("enrollment_campaigns", "owner_service_client_id")
