"""Register immutable Browser Sensor metadata beside artifact storage.

Revision ID: 0031_browser_sensor_release
Revises: 0030_activity_current_projection
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0031_browser_sensor_release"
down_revision = "0030_activity_current_projection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "browser_sensor_releases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("extension_version", sa.String(32), nullable=False),
        sa.Column("extension_id", sa.String(32), nullable=False),
        sa.Column("protocol_version", sa.Integer(), nullable=False),
        sa.Column("source_revision", sa.String(40), nullable=False),
        sa.Column("minimum_agent_version", sa.String(32), nullable=False),
        sa.Column("artifact_identifier", sa.String(256), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("update_manifest_identifier", sa.String(256), nullable=False),
        sa.Column("update_manifest_sha256", sa.String(64), nullable=False),
        sa.Column("metadata_identifier", sa.String(256), nullable=False),
        sa.Column("metadata_sha256", sa.String(64), nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("built_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("extension_version", name="uq_browser_sensor_releases_version"),
        sa.UniqueConstraint("artifact_identifier", name="uq_browser_sensor_releases_artifact"),
        sa.CheckConstraint("protocol_version >= 1", name="ck_browser_sensor_protocol_positive"),
    )
    op.execute("""
        CREATE FUNCTION reject_browser_sensor_release_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'browser_sensor_releases is append-only' USING ERRCODE = '55000';
            END IF;
            IF (to_jsonb(NEW) - 'retired_at') IS DISTINCT FROM
               (to_jsonb(OLD) - 'retired_at') THEN
                RAISE EXCEPTION 'browser_sensor_releases metadata is immutable' USING ERRCODE = '55000';
            END IF;
            IF OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
                RAISE EXCEPTION 'browser_sensor_releases retirement is final' USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER browser_sensor_releases_immutable
        BEFORE UPDATE OR DELETE ON browser_sensor_releases
        FOR EACH ROW EXECUTE FUNCTION reject_browser_sensor_release_mutation()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER browser_sensor_releases_immutable ON browser_sensor_releases")
    op.execute("DROP FUNCTION reject_browser_sensor_release_mutation()")
    op.drop_table("browser_sensor_releases")
