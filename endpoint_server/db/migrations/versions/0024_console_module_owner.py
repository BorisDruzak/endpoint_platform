"""Reserve a credential-free internal owner for Console module operations."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op


revision: str = "0024_console_module_owner"
down_revision: str | None = "0023_windows_setup_releases"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "INSERT INTO service_clients (id, client_identifier, display_name, created_at) "
        "VALUES ('f8cb2618-6707-460a-9727-141d57c30f4d'::uuid, "
        "'endpoint-console-internal', 'Endpoint Console', now()) "
        "ON CONFLICT (client_identifier) DO NOTHING"
    )


def downgrade() -> None:
    raise RuntimeError("Console operation ownership is forward-only")
