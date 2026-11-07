"""The whole-fix seams on migrated PostgreSQL, including worker-thread sessions."""
import pytest
from alembic import command
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

from tests.server import test_linux_support_whole_seams as seams
from tests.server.test_linux_support_lifecycle_postgresql import seed
from tests.server.test_update_postgresql import update_migration_database_urls, _alembic_config

pytestmark = pytest.mark.usefixtures('preserve_migration_loggers')


@pytest.fixture
def isolated_database():
    # Delegate UUID create/drop and loopback validation to the existing fixture;
    # function scope keeps committed status/rebind cases independent.
    owner = update_migration_database_urls.__wrapped__()
    url, _ = next(owner)
    try:
        command.upgrade(_alembic_config(url), 'head')
        yield url
    finally:
        try:
            next(owner)
        except StopIteration:
            pass


@pytest.fixture
async def pg_sessions(isolated_database, monkeypatch):
    engine = create_async_engine(isolated_database, poolclass=NullPool)
    monkeypatch.setattr(seams, 'identity', seed)
    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


@pytest.mark.parametrize('offline', [False,True])
async def test_journal_reinstall(pg_sessions, tmp_path, offline):
    await seams.test_real_journal_provider_reinstall(pg_sessions, tmp_path, offline)


@pytest.mark.parametrize('persistent,restart,failure', [(False,False,'account'),(True,False,'account'),
    (True,True,'account'),(False,True,'account'),(False,False,'https'),(False,False,'native')])
async def test_service_recovery(pg_sessions, tmp_path, monkeypatch, persistent, restart, failure):
    await seams.test_actual_provider_masked_policy_service_recovery(
        pg_sessions, tmp_path, monkeypatch, persistent, restart, failure)


@pytest.mark.parametrize('configuration,allowed', [('canonical',True),('staging',True),
    ('staging_opt_out',False),('mixed',False),('missing_pin',False),('invalid_pin',False),
    ('unavailable',False),('wrong_port',False)])
async def test_export_authority(pg_sessions, tmp_path, configuration, allowed):
    await seams.test_populated_linux_export_matches_effective_policy(
        pg_sessions, tmp_path, configuration, allowed)


async def test_initial_availability(pg_sessions, tmp_path):
    await seams.test_initial_provider_availability_binds_first_enabled_authority(pg_sessions, tmp_path)
