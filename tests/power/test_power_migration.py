import io
from pathlib import Path
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory


def test_power_source_postgresql_sql_and_single_head():
    output = io.StringIO()
    config = Config(Path("alembic.ini"), output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url", "postgresql+asyncpg://unused@127.0.0.1/unused"
    )
    assert ScriptDirectory.from_config(config).get_heads() == [
        "0039_power_source_state"
    ]
    command.upgrade(config, "0038_activity_analytics:0039_power_source_state", sql=True)
    sql = output.getvalue()
    assert "CREATE TABLE power_source_states" in sql
    assert "CREATE INDEX ix_power_source_reported" in sql
    assert "UNIQUE (device_id)" in sql
    assert "ALTER TABLE device_events" not in sql
    assert "REFERENCES devices (id) ON DELETE CASCADE" in sql
