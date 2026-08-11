"""Merge Gateway WSS and service campaign ownership migration branches.

Revision ID: 0012_gateway_campaign_merge
Revises: 0011_gateway_wss, 0011_service_campaign_ownership
"""

from __future__ import annotations

from collections.abc import Sequence


revision: str = "0012_gateway_campaign_merge"
down_revision: tuple[str, str] = (
    "0011_gateway_wss",
    "0011_service_campaign_ownership",
)
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Record that both additive 0011 branches are present."""


def downgrade() -> None:
    """Restore the two independent 0011 heads without changing schema."""
