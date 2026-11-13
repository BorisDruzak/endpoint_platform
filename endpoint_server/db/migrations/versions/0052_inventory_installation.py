"""Persist one-use inventory installation authority."""

from alembic import op
import sqlalchemy as sa

revision = "0052_inventory_installation"
down_revision = "0051_staging_linux_worktime"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "inventory_installation_assignments",
        sa.Column("installation_digest", sa.String(64), primary_key=True),
        sa.Column("service_client_id", sa.Uuid(), sa.ForeignKey("service_clients.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("fingerprint_digest", sa.String(64), nullable=False),
        sa.Column("platform", sa.String(16), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enrollment_request_id", sa.Uuid(), sa.ForeignKey("enrollment_requests.id", ondelete="RESTRICT"), unique=True),
        sa.CheckConstraint("platform IN ('linux', 'windows')", name="ck_inventory_installation_platform"),
        sa.CheckConstraint("expires_at > issued_at", name="ck_inventory_installation_window"),
    )


def downgrade():
    op.execute("LOCK TABLE inventory_installation_assignments IN ACCESS EXCLUSIVE MODE")
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM inventory_installation_assignments) THEN "
        "RAISE EXCEPTION 'Inventory installation authority must be preserved before downgrade'; "
        "END IF; END $$"
    )
    op.drop_table("inventory_installation_assignments")
