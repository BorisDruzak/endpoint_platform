import io
from importlib import import_module

from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect


def test_postgres_ddl_and_executed_sqlite_upgrade_downgrade(preserve_migration_loggers):
    output = io.StringIO()
    config = Config('alembic.ini',output_buffer=output)
    command.upgrade(config,'0040_identity_sso:0041_worktime',sql=True)
    ddl = output.getvalue()
    assert 'CREATE TABLE worktime_state' in ddl
    assert 'TIMESTAMP WITH TIME ZONE' in ddl
    assert 'uq_worktime_request_interval' in ddl
    assert 'DROP TABLE activity_intervals' not in ddl
    migration = import_module('endpoint_server.db.migrations.versions.0041_worktime')
    engine = create_engine('sqlite:///:memory:')
    with engine.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
        assert set(inspect(connection).get_table_names()) == {
            'worktime_activity_bindings','worktime_approvals','worktime_audit','worktime_categories',
            'worktime_corrections','worktime_events','worktime_explanation_requests',
            'worktime_explanations','worktime_retention_policies','worktime_schedules','worktime_state',
            'worktime_timesheets','worktime_timesheet_days'}
        with Operations.context(MigrationContext.configure(connection)):
            migration.downgrade()
        assert inspect(connection).get_table_names() == []
    engine.dispose()
