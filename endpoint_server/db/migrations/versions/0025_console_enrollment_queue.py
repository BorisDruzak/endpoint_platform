"""Index Console enrollment queues by status and stable page order.

Revision ID: 0025_console_enrollment_queue
Revises: 0024_console_module_owner
"""

from __future__ import annotations

from alembic import op


revision: str = "0025_console_enrollment_queue"
down_revision: str | None = "0024_console_module_owner"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_index(
        "ix_enrollment_requests_status_created",
        "enrollment_requests",
        ["status", "created_at", "id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_enrollment_requests_status_created",
        table_name="enrollment_requests",
    )
