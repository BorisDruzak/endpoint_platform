"""Only the independent-finalizer check is retired; immutable rows stay intact."""
import io
from alembic import command
from alembic.config import Config


def test_recorded_policy_upgrade_and_refusing_downgrade_ddl(preserve_migration_loggers):
    output=io.StringIO();config=Config('alembic.ini',output_buffer=output)
    command.upgrade(config,'0042_worktime_companion:0043_worktime_recorded',sql=True)
    ddl=output.getvalue()
    assert 'DROP CONSTRAINT ck_worktime_timesheet_independent' in ddl
    assert all(sql not in ddl for sql in ('UPDATE worktime_', 'DELETE FROM worktime_', 'DROP TABLE', 'DROP TRIGGER'))
    output.seek(0);output.truncate(0)
    command.downgrade(config,'0043_worktime_recorded:0042_worktime_companion',sql=True)
    ddl=output.getvalue()
    assert 'LOCK TABLE worktime_timesheets IN ACCESS EXCLUSIVE MODE' in ddl
    assert 'finalized_by = person_id' in ddl and 'RAISE EXCEPTION' in ddl
    assert ddl.index('RAISE EXCEPTION')<ddl.index('ADD CONSTRAINT ck_worktime_timesheet_independent')
    assert all(sql not in ddl for sql in ('UPDATE worktime_', 'DELETE FROM worktime_', 'DROP TABLE', 'DROP TRIGGER'))
