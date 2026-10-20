"""Migration execution, PostgreSQL DDL and bounded retention safety."""
import io
from datetime import timedelta
from importlib import import_module

import pytest
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import func, inspect, select

from endpoint_server.activity.analytics_models import ActivityDaily, ActivityInterval
from endpoint_server.activity.analytics_policy import AnalyticsPolicy
from endpoint_server.activity.analytics_store import rebuild_daily, retain_analytics
from endpoint_server.db.models import Device
from tests.activity.test_analytics import db, observation, record, NOW


def test_postgresql_ddl_is_additive_and_reversible(preserve_migration_loggers):
    output = io.StringIO()
    config = Config('alembic.ini', output_buffer=output)
    command.upgrade(config, '0037_launcher_foundation:0038_activity_analytics', sql=True)
    ddl = output.getvalue()
    assert 'CREATE TABLE activity_intervals' in ddl
    assert 'TIMESTAMP WITH TIME ZONE' in ddl
    assert 'uq_activity_daily_user_zone_day' in ddl
    assert 'ON DELETE SET NULL' in ddl
    assert 'security_events' not in ddl and 'context_snapshots' not in ddl
    output.seek(0); output.truncate()
    command.downgrade(config, '0038_activity_analytics:0037_launcher_foundation', sql=True)
    assert 'DROP TABLE activity_intervals' in output.getvalue()
    assert 'DROP TABLE devices' not in output.getvalue()


@pytest.mark.asyncio
async def test_executed_migration_downgrades_without_dropping_devices(db):
    session, _, _ = db
    await session.commit()
    async with session.bind.begin() as connection:
        def downgrade(c):
            with Operations.context(MigrationContext.configure(c)):
                import_module('endpoint_server.db.migrations.versions.0038_activity_analytics').downgrade()
            assert inspect(c).get_table_names() == ['devices']
        await connection.run_sync(downgrade)
    assert await session.scalar(select(func.count()).select_from(Device)) == 1


@pytest.mark.asyncio
async def test_retention_does_not_destroy_pending_rollup_evidence(db):
    session, device, _ = db
    await record(session, device, observation())
    await record(session, device, observation(15, process=None))
    await record(session, device, observation(30, process=None))
    future = NOW + timedelta(days=17)
    assert await retain_analytics(session, policy=AnalyticsPolicy(), now=future) == 0
    await rebuild_daily(session, policy=AnalyticsPolicy(), now=future)
    payload = (await session.scalars(select(ActivityDaily))).first().payload
    assert sum(app['seconds'] for app in payload['applications']) == payload['seconds']['ACTIVE']
    assert 'Приложение неизвестно' in [app['label'] for app in payload['applications']]
    assert await retain_analytics(session, policy=AnalyticsPolicy(), now=future) > 0
    assert await session.scalar(select(func.count()).select_from(ActivityInterval)) == 0


def test_environment_retention_settings_are_bounded():
    policy = AnalyticsPolicy.from_environment({'ACTIVITY_ANALYTICS_DETAIL_DAYS': '21',
        'ACTIVITY_ANALYTICS_AGGREGATE_DAYS': '120', 'ACTIVITY_ANALYTICS_TIMEZONE': 'Europe/Berlin'})
    assert policy.timezones == ('Europe/Berlin', 'UTC')
    with pytest.raises(ValueError):
        AnalyticsPolicy.from_environment({'ACTIVITY_ANALYTICS_MAX_GAP_SECONDS': '3600'})
