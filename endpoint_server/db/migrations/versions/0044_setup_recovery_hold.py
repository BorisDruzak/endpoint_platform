"""Retain exclusive device ownership while a native outcome is unresolved."""
from alembic import op
import sqlalchemy as sa

revision = '0044_setup_recovery_hold'
down_revision = '0043_setup_updates'
branch_labels = None
depends_on = None


def predicate(include_hold):
    phases = "'assigned','downloading','verified','installing','verifying'"
    if include_hold:
        phases += ",'recovery_required'"
    return sa.text('status IN (' + phases + ')')


def replace_index(include_hold):
    op.drop_index('uq_setup_update_active_device', table_name='setup_update_assignments')
    op.create_index('uq_setup_update_active_device', 'setup_update_assignments', ['device_id'], unique=True,
        postgresql_where=predicate(include_hold), sqlite_where=predicate(include_hold))


def upgrade():
    replace_index(True)


def downgrade():
    replace_index(False)
