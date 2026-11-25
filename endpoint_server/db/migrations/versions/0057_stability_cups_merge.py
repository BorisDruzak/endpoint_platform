"""Join the deployed stability and CUPS schema histories."""

revision = "0057_stability_cups_merge"
down_revision = ("0056_context_collection_history", "0040_cups_operations")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
