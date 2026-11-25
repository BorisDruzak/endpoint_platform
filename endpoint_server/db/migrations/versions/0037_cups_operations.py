"""Persist typed CUPS operations and their results alongside the audit log."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0037_cups_operations"
down_revision = "0036_device_binding"
branch_labels = None
depends_on = None


def _constraints(*, allow_cups: bool) -> None:
    table = "endpoint_operations"
    op.drop_constraint("ck_endpoint_operations_capability", table, type_="check")
    op.drop_constraint("ck_endpoint_operations_module_shape", table, type_="check")
    capabilities = "'context.diagnostic.collect', 'endpoint.module.recipe'"
    if allow_cups:
        capabilities += ", 'printer.cups.queue.configure', 'printer.cups.testpage.submit'"
    op.create_check_constraint("ck_endpoint_operations_capability", table, f"capability IN ({capabilities})")
    direct = "capability <> 'endpoint.module.recipe'" if allow_cups else "capability = 'context.diagnostic.collect'"
    op.create_check_constraint(
        "ck_endpoint_operations_module_shape", table,
        f"(({direct} AND module_version_id IS NULL AND module_inputs IS NULL) OR "
        "(capability = 'endpoint.module.recipe' AND module_version_id IS NOT NULL AND module_inputs IS NOT NULL))",
    )


def upgrade() -> None:
    op.add_column("endpoint_operations", sa.Column("action_result", JSONB(), nullable=True))
    op.add_column("endpoint_operations", sa.Column("action_device_instance_id", sa.Uuid(), nullable=True))
    _constraints(allow_cups=True)


def downgrade() -> None:
    if op.get_bind().scalar(sa.text(
        "SELECT EXISTS(SELECT 1 FROM endpoint_operations WHERE capability LIKE 'printer.cups.%')"
    )):
        raise RuntimeError("cannot downgrade while auditable CUPS operations exist")
    _constraints(allow_cups=False)
    op.drop_column("endpoint_operations", "action_result")
    op.drop_column("endpoint_operations", "action_device_instance_id")
