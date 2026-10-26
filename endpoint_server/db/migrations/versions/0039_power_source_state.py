"""Track current native power-source coverage independently of historical facts."""

from alembic import op
import sqlalchemy as sa

revision = "0039_power_source_state"
down_revision = "0038_activity_analytics"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "power_source_states",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "device_id",
            sa.Uuid(),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("availability", sa.String(16), nullable=False),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("coverage_started_at", sa.DateTime(timezone=True)),
        sa.Column("loss_count", sa.BigInteger(), nullable=False),
        sa.Column("reset_count", sa.BigInteger(), nullable=False),
        sa.UniqueConstraint("device_id", name="uq_power_source_device"),
        sa.CheckConstraint(
            "availability IN ('READY','DEGRADED','UNAVAILABLE','UNSUPPORTED')",
            name="ck_power_source_availability",
        ),
        sa.CheckConstraint(
            "loss_count >= 0 AND reset_count >= 0", name="ck_power_source_counters"
        ),
    )
    op.create_index("ix_power_source_reported", "power_source_states", ["reported_at"])


def downgrade():
    op.drop_table("power_source_states")
