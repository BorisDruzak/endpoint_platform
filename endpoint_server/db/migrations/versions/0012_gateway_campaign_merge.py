"""Merge durable Gateway and campaign ownership migration branches."""
from __future__ import annotations
from collections.abc import Sequence
revision: str = "0012_gateway_campaign_merge"
down_revision: tuple[str, str] = ("0011_gateway_wss", "0011_service_campaign_ownership")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
def upgrade() -> None:
    pass
def downgrade() -> None:
    pass
