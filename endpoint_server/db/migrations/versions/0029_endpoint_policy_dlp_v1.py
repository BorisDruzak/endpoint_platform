"""Persist immutable Endpoint Policy versions and effective assignments.

Revision ID: 0029_endpoint_policy_dlp_v1
Revises: 0028_capability_platform_v2
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0029_endpoint_policy_dlp_v1"
down_revision = "0028_capability_platform_v2"
branch_labels = None
depends_on = None


def _id_column() -> sa.Column:
    return sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True)


def _created_at_column() -> sa.Column:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), nullable=False,
        server_default=sa.text("now()"),
    )


def upgrade() -> None:
    op.create_table(
        "policy_definitions",
        _id_column(),
        _created_at_column(),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
    )
    op.create_table(
        "policy_versions",
        _id_column(),
        _created_at_column(),
        sa.Column("definition_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["definition_id"], ["policy_definitions.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["created_by"], ["admin_users.id"]),
        sa.UniqueConstraint(
            "definition_id", "version", name="uq_policy_versions_definition_version"
        ),
        sa.CheckConstraint("version >= 1", name="ck_policy_versions_positive_version"),
    )
    op.execute(
        """
        CREATE FUNCTION reject_policy_version_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'policy_versions is append-only'
                USING ERRCODE = '55000';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER policy_versions_append_only
        BEFORE UPDATE OR DELETE ON policy_versions
        FOR EACH ROW EXECUTE FUNCTION reject_policy_version_mutation()
        """
    )
    op.create_table(
        "policy_assignments",
        _id_column(),
        _created_at_column(),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True)),
        sa.Column("policy_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assigned_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["policy_version_id"], ["policy_versions.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["assigned_by"], ["admin_users.id"]),
        sa.UniqueConstraint("device_id", name="uq_policy_assignments_device"),
        sa.CheckConstraint(
            "(scope = 'default' AND device_id IS NULL) OR "
            "(scope = 'device' AND device_id IS NOT NULL)",
            name="ck_policy_assignments_scope_device",
        ),
    )
    op.create_index(
        "uq_policy_assignments_default", "policy_assignments", ["scope"],
        unique=True, postgresql_where=sa.text("scope = 'default'"),
    )
    op.create_table(
        "policy_device_states",
        _id_column(),
        _created_at_column(),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_version_id", postgresql.UUID(as_uuid=True)),
        sa.Column("policy_digest", sa.String(64)),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("received_at", sa.DateTime(timezone=True)),
        sa.Column("applied_at", sa.DateTime(timezone=True)),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["policy_version_id"], ["policy_versions.id"], ondelete="SET NULL"
        ),
        sa.UniqueConstraint("device_id", name="uq_policy_device_states_device"),
        sa.CheckConstraint(
            "status IN ('PENDING', 'APPLIED', 'STALE', 'UNSUPPORTED', 'ERROR')",
            name="ck_policy_device_states_status",
        ),
    )


def downgrade() -> None:
    raise RuntimeError("Endpoint Policy v1 migration is forward-only")
