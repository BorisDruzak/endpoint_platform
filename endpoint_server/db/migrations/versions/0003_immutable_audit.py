"""Add attributed details and database immutability to audit events.

Revision ID: 0003_immutable_audit
Revises: 0002_service_credentials
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0003_immutable_audit"
down_revision: str | None = "0002_service_credentials"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "audit_events",
        sa.Column("request_id", sa.String(length=128), nullable=True),
    )
    op.execute(
        "UPDATE audit_events SET request_id = 'legacy-' || replace(id::text, '-', '')"
    )
    op.alter_column(
        "audit_events",
        "request_id",
        existing_type=sa.String(length=128),
        nullable=False,
    )
    op.add_column(
        "audit_events",
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.alter_column(
        "audit_events",
        "details",
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        server_default=None,
    )
    op.execute(
        """
        CREATE FUNCTION reject_audit_event_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'audit_events is append-only'
                USING ERRCODE = '55000';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_append_only
        BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER audit_events_append_only ON audit_events")
    op.execute("DROP FUNCTION reject_audit_event_mutation()")
    op.drop_column("audit_events", "details")
    op.drop_column("audit_events", "request_id")
