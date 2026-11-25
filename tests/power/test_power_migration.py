import io
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

pytestmark = pytest.mark.usefixtures("preserve_migration_loggers")


def test_power_source_postgresql_sql():
    output = io.StringIO()
    config = Config(Path("alembic.ini"), output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url", "postgresql+asyncpg://unused@127.0.0.1/unused"
    )
    command.upgrade(config, "0038_activity_analytics:0039_power_source_state", sql=True)
    sql = output.getvalue()
    assert "CREATE TABLE power_source_states" in sql
    assert "CREATE INDEX ix_power_source_reported" in sql
    assert "UNIQUE (device_id)" in sql
    assert "ALTER TABLE device_events" not in sql
    assert "REFERENCES devices (id) ON DELETE CASCADE" in sql
