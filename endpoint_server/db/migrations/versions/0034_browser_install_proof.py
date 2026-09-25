"""Record browser-reported extension installation provenance.

Revision ID: 0034_browser_install_proof
Revises: 0033_browser_status
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0034_browser_install_proof"
down_revision = "0033_browser_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "browser_status_current",
        sa.Column(
            "extension_install_type", sa.String(16), nullable=False,
            server_default="UNKNOWN",
        ),
    )
    op.create_check_constraint(
        "ck_browser_status_install_type", "browser_status_current",
        "extension_install_type IN ('ADMIN', 'OTHER', 'UNKNOWN')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_browser_status_install_type", "browser_status_current", type_="check",
    )
    op.drop_column("browser_status_current", "extension_install_type")
