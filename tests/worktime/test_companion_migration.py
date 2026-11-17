import io
from importlib import import_module

from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect


def test_companion_postgres_ddl_and_sqlite_upgrade_downgrade(preserve_migration_loggers):
    output=io.StringIO()
    config=Config('alembic.ini',output_buffer=output)
    command.upgrade(config,'0041_worktime:0042_worktime_companion',sql=True)
    ddl=output.getvalue()
    assert 'CREATE TABLE worktime_companion_deliveries' in ddl
    assert 'TIMESTAMP WITH TIME ZONE' in ddl and 'uq_worktime_companion_request' in ddl
    migration=import_module('endpoint_server.db.migrations.versions.0042_worktime_companion')
    engine=create_engine('sqlite:///:memory:')
    with engine.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
        assert inspect(connection).get_table_names()==['worktime_companion_deliveries']
        with Operations.context(MigrationContext.configure(connection)):
            migration.downgrade()
        assert inspect(connection).get_table_names()==[]
    engine.dispose()
