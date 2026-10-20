"""Optional real PostgreSQL locks/upsert test in an isolated migrated database."""
import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_contracts.activity import ActivityObservationV1
from endpoint_server.activity.analytics_models import ActivityDaily
from endpoint_server.activity.analytics_policy import AnalyticsPolicy
from endpoint_server.activity.analytics_store import rebuild_daily, record_observation
from endpoint_server.db.models import Device
from tests.server.test_migrations import empty_database_url, _alembic_config

pytestmark = pytest.mark.usefixtures('preserve_migration_loggers')


def test_migrated_postgresql_serializes_accounts_and_rollup_dirty_marks(empty_database_url):
    command.upgrade(_alembic_config(empty_database_url), 'head')

    async def exercise():
        engine = create_async_engine(empty_database_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        start = datetime(2026, 10, 20, 12, tzinfo=UTC)
        policy = AnalyticsPolicy()
        try:
            async with factory() as session:
                devices = [Device(id=uuid4(), device_identifier=f'analytics-pg-{i}') for i in range(2)]
                session.add_all(devices)
                await session.commit()

            async def write(index, second):
                async with factory() as session:
                    observation = ActivityObservationV1(
                        schema_version='activity_observation_v1', observation_id=uuid4(),
                        observed_at=start + timedelta(seconds=second), user_login='DOMAIN\\Concurrent',
                        session_state='ACTIVE', idle_seconds=0,
                        foreground={'process_name': 'WINWORD.EXE' if index == 0 else 'EXCEL.EXE',
                                    'application_category': 'office'})
                    await record_observation(session, devices[index].id, observation, state='ACTIVE',
                                             policy_version_id=None, policy=policy)
                    await session.commit()

            async def rollup():
                async with factory() as session:
                    await rebuild_daily(session, policy=policy, now=start + timedelta(minutes=1))
                    await session.commit()

            await asyncio.gather(write(0, 0), write(1, 0))
            await asyncio.gather(write(0, 30), write(1, 30))
            await rollup()
            await asyncio.gather(write(0, 45), rollup())
            await rollup()
            async with factory() as session:
                rows = list((await session.scalars(select(ActivityDaily))).all())
                assert len(rows) == 2
                for row in rows:
                    assert not row.dirty
                    assert row.payload['seconds']['ACTIVE'] == 45
                    assert row.payload['overlap_seconds'] == 30
                    assert sum(app['seconds'] for app in row.payload['applications']) == 45
        finally:
            await engine.dispose()

    asyncio.run(exercise())
