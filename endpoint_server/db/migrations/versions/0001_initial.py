"""Create the initial Endpoint Platform ownership schema.

Revision ID: 0001_initial
Revises:
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _identity_columns() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )


def upgrade() -> None:
    op.create_table(
        "admin_users",
        *_identity_columns(),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("password_digest", sa.String(length=256), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )
    op.create_table(
        "admin_sessions",
        *_identity_columns(),
        sa.Column("admin_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("session_digest", sa.String(length=256), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["admin_user_id"], ["admin_users.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_digest"),
    )
    op.create_table(
        "service_clients",
        *_identity_columns(),
        sa.Column("client_identifier", sa.String(length=128), nullable=False),
        sa.Column("display_name", sa.String(length=256), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("client_identifier"),
    )
    op.create_table(
        "service_credentials",
        *_identity_columns(),
        sa.Column("service_client_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("credential_identifier", sa.String(length=128), nullable=False),
        sa.Column("secret_digest", sa.String(length=256), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["service_client_id"], ["service_clients.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "service_client_id",
            "credential_identifier",
            name="uq_service_credentials_client_identifier",
        ),
    )
    op.create_table(
        "audit_events",
        *_identity_columns(),
        sa.Column("actor_kind", sa.String(length=32), nullable=False),
        sa.Column("actor_identifier", sa.String(length=128), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("object_kind", sa.String(length=64), nullable=False),
        sa.Column("object_identifier", sa.String(length=128), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "devices",
        *_identity_columns(),
        sa.Column("device_identifier", sa.String(length=128), nullable=False),
        sa.Column("display_name", sa.String(length=256), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_identifier"),
    )
    op.create_table(
        "device_credentials",
        *_identity_columns(),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("credential_identifier", sa.String(length=128), nullable=False),
        sa.Column("token_digest", sa.String(length=256), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "device_id",
            "credential_identifier",
            name="uq_device_credentials_device_identifier",
        ),
        sa.UniqueConstraint("token_digest"),
    )
    op.create_table(
        "device_instances",
        *_identity_columns(),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("instance_identifier", sa.String(length=128), nullable=False),
        sa.Column("agent_version", sa.String(length=64), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "device_id",
            "instance_identifier",
            name="uq_device_instances_device_identifier",
        ),
    )
    op.create_table(
        "device_sessions",
        *_identity_columns(),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "device_instance_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
        sa.Column("session_identifier", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["device_instance_id"], ["device_instances.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_identifier"),
    )
    op.create_table(
        "enrollment_campaigns",
        *_identity_columns(),
        sa.Column("campaign_identifier", sa.String(length=128), nullable=False),
        sa.Column("token_digest", sa.String(length=256), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("campaign_identifier"),
        sa.UniqueConstraint("token_digest"),
    )
    op.create_table(
        "enrollment_claims",
        *_identity_columns(),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("claim_identifier", sa.String(length=128), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["campaign_id"], ["enrollment_campaigns.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("claim_identifier"),
    )
    op.create_table(
        "enrollment_events",
        *_identity_columns(),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("claim_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_kind", sa.String(length=64), nullable=False),
        sa.Column("remote_identifier", sa.String(length=128), nullable=True),
        sa.ForeignKeyConstraint(
            ["campaign_id"], ["enrollment_campaigns.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["claim_id"], ["enrollment_claims.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "commands",
        *_identity_columns(),
        sa.Column("command_identifier", sa.String(length=128), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("command_kind", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("command_identifier"),
    )
    op.create_table(
        "command_deliveries",
        *_identity_columns(),
        sa.Column("command_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("device_session_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("delivery_identifier", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["command_id"], ["commands.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["device_session_id"], ["device_sessions.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("delivery_identifier"),
    )
    op.create_table(
        "command_results",
        *_identity_columns(),
        sa.Column("command_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("delivery_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("result_identifier", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["command_id"], ["commands.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["delivery_id"], ["command_deliveries.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("result_identifier"),
    )
    op.create_table(
        "update_builds",
        *_identity_columns(),
        sa.Column("build_identifier", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("platform", sa.String(length=64), nullable=False),
        sa.Column("artifact_identifier", sa.String(length=256), nullable=False),
        sa.Column("sha256_digest", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("build_identifier"),
    )
    op.create_table(
        "update_rollouts",
        *_identity_columns(),
        sa.Column("rollout_identifier", sa.String(length=128), nullable=False),
        sa.Column("build_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["build_id"], ["update_builds.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("rollout_identifier"),
    )
    op.create_table(
        "update_targets",
        *_identity_columns(),
        sa.Column("rollout_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_identifier", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["rollout_id"], ["update_rollouts.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("target_identifier"),
        sa.UniqueConstraint(
            "rollout_id",
            "device_id",
            name="uq_update_targets_device",
        ),
    )
    op.create_table(
        "update_reports",
        *_identity_columns(),
        sa.Column("update_target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("report_identifier", sa.String(length=128), nullable=False),
        sa.Column("reported_version", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["update_target_id"],
            ["update_targets.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("report_identifier"),
    )


def downgrade() -> None:
    op.drop_table("update_reports")
    op.drop_table("update_targets")
    op.drop_table("update_rollouts")
    op.drop_table("update_builds")
    op.drop_table("command_results")
    op.drop_table("command_deliveries")
    op.drop_table("commands")
    op.drop_table("enrollment_events")
    op.drop_table("enrollment_claims")
    op.drop_table("enrollment_campaigns")
    op.drop_table("device_sessions")
    op.drop_table("device_instances")
    op.drop_table("device_credentials")
    op.drop_table("devices")
    op.drop_table("audit_events")
    op.drop_table("service_credentials")
    op.drop_table("service_clients")
    op.drop_table("admin_sessions")
    op.drop_table("admin_users")
