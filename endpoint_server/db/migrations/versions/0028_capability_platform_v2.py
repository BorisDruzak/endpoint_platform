"""Expand persisted Module steps for Capability Platform v2.

Revision ID: 0028_capability_platform_v2
Revises: 0027_context_observed_backfill
"""

from __future__ import annotations

from alembic import op


revision = "0028_capability_platform_v2"
down_revision = "0027_context_observed_backfill"
branch_labels = None
depends_on = None


# Immutable migration snapshot. A registry drift test compares this with the
# executable registry; migrations must never import mutable application state.
CAPABILITY_NAMES = (
    "dns.resolve",
    "network.ping",
    "tcp.connect",
    "route.get",
    "adapter.list",
    "system.service_status",
    "system.resource_snapshot",
    "process.list",
    "process.find",
    "service.list",
    "service.status",
    "printer.list",
    "printer.status",
    "printer.queue.summary",
    "software.list",
    "software.find",
    "filesystem.free_space",
    "filesystem.path_exists",
    "filesystem.file_metadata",
    "eventlog.query",
    "eventlog.recent_errors",
)


def upgrade() -> None:
    op.drop_constraint(
        "ck_endpoint_operation_steps_capability",
        "endpoint_operation_steps",
        type_="check",
    )
    op.create_check_constraint(
        "ck_endpoint_operation_steps_capability",
        "endpoint_operation_steps",
        "capability IN (" + ", ".join(f"'{name}'" for name in CAPABILITY_NAMES) + ")",
    )


def downgrade() -> None:
    raise RuntimeError("Capability Platform v2 step migration is forward-only")
