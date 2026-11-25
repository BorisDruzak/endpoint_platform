"""Retire independent-finalizer gate; preserve every existing ledger row."""
from alembic import op

revision = '0043_worktime_recorded'
down_revision = '0042_worktime_companion'
branch_labels = None
depends_on = None


def _postgresql_only():
    if op.get_bind().dialect.name != 'postgresql':
        raise RuntimeError('Recorded WorkTime policy migration requires PostgreSQL')


def upgrade():
    _postgresql_only()
    op.drop_constraint('ck_worktime_timesheet_independent', 'worktime_timesheets', type_='check')


def downgrade():
    _postgresql_only()
    # Prevent a concurrent self-finalization between the safety check and ADD.
    op.execute('LOCK TABLE worktime_timesheets IN ACCESS EXCLUSIVE MODE')
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM worktime_timesheets WHERE finalized_by = person_id) THEN
            RAISE EXCEPTION 'Cannot restore independent finalization: self-finalized history exists';
        END IF;
    END $$""")
    op.create_check_constraint('ck_worktime_timesheet_independent', 'worktime_timesheets', 'finalized_by != person_id')
