"""Persist immutable metadata for signed Windows Setup artifacts."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0023_windows_setup_releases"
down_revision: str | None = "0022_module_step_capabilities"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "windows_setup_releases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("version", sa.String(128), nullable=False),
        sa.Column("agent_version", sa.String(128), nullable=False),
        sa.Column("artifact_identifier", sa.String(256), nullable=False),
        sa.Column("filename", sa.String(256), nullable=False),
        sa.Column("setup_sha256", sa.String(64), nullable=False),
        sa.Column("msi_sha256", sa.String(64), nullable=False),
        sa.Column("source_commit", sa.String(40), nullable=False),
        sa.Column("msi_source_commit", sa.String(40), nullable=False),
        sa.Column("authenticode_status", sa.String(16), nullable=False),
        sa.Column("authenticode_publisher", sa.String(512)),
        sa.Column("msi_authenticode_status", sa.String(16), nullable=False),
        sa.Column("msi_authenticode_publisher", sa.String(512)),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("authenticode_status IN ('valid', 'unsigned', 'invalid')", name="ck_windows_setup_releases_signature"),
        sa.CheckConstraint("msi_authenticode_status IN ('valid', 'unsigned', 'invalid')", name="ck_windows_setup_releases_msi_signature"),
        sa.UniqueConstraint("version", name="uq_windows_setup_releases_version"),
        sa.UniqueConstraint("artifact_identifier", name="uq_windows_setup_releases_artifact"),
    )


def downgrade() -> None:
    op.drop_table("windows_setup_releases")
