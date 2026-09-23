"""Align module operation step persistence with the six canonical primitives."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op


revision: str = "0022_module_step_capabilities"
down_revision: str | None = "0021_request_claim_envelopes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(
        "ck_endpoint_operation_steps_capability",
        "endpoint_operation_steps",
        type_="check",
    )
    op.create_check_constraint(
        "ck_endpoint_operation_steps_capability",
        "endpoint_operation_steps",
        "capability IN ('dns.resolve', 'network.ping', 'tcp.connect', "
        "'route.get', 'adapter.list', 'system.service_status')",
    )


def downgrade() -> None:
    raise RuntimeError(
        "module step capability repair is forward-only: existing operations "
        "may use the added canonical primitives"
    )
