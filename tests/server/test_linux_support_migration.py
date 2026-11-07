import io
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory


def test_linux_migration_is_additive_and_preserves_windows_default_offline():
    output=io.StringIO()
    config=Config(Path('alembic.ini'),output_buffer=output)
    config.set_main_option('sqlalchemy.url','postgresql+asyncpg://unused@127.0.0.1/unused')
    assert ScriptDirectory.from_config(config).get_heads()==['0050_linux_enrollment_binding']
    command.upgrade(config,'0048_installation_lifecycle:head',sql=True)
    sql=output.getvalue()
    assert "DEFAULT 'windows_amd64' NOT NULL" in sql
    assert 'CREATE TABLE linux_native_releases' in sql
    assert 'CREATE TABLE linux_enrollment_bindings' in sql
    assert 'ck_support_platform_principal' in sql
    assert 'UPDATE windows_setup_releases' not in sql and 'DROP TABLE' not in sql
