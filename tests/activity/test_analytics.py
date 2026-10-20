"""Measured time is bounded by observations, durable and unioned across devices."""
from datetime import UTC, datetime, timedelta, date
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, func, text
from importlib import import_module
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_contracts.activity import ActivityObservationV1
from endpoint_server.activity.analytics_models import ActivityInterval, ActivityCursor, ActivityDaily
from endpoint_server.activity.analytics_policy import AnalyticsPolicy
from endpoint_server.activity.analytics_store import record_observation, rebuild_daily, retain_analytics
from endpoint_server.activity.analytics_math import summarize, normalize_login, day_bounds, utc
from endpoint_server.db.models import Device

NOW = datetime(2026, 10, 19, 18, 59, 30, tzinfo=UTC)


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    async with engine.begin() as connection:
        await connection.execute(text('PRAGMA foreign_keys=ON'))
        def migrate(c):
            Device.__table__.create(c)
            with Operations.context(MigrationContext.configure(c)):
                import_module('endpoint_server.db.migrations.versions.0038_activity_analytics').upgrade()
        await connection.run_sync(migrate)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        device = Device(device_identifier='analytics-test')
        session.add(device)
        await session.flush()
        yield session, device.id, factory
    await engine.dispose()


def observation(second=0, state='ACTIVE', process='WINWORD.EXE', user='DOMAIN\\Alice'):
    return ActivityObservationV1(
        schema_version='activity_observation_v1', observation_id=uuid4(),
        observed_at=NOW + timedelta(seconds=second), user_login=user, session_state=state,
        idle_seconds=(900 if state == 'IDLE' else 0) if state in {'ACTIVE', 'IDLE'} else None,
        foreground={'process_name': process, 'application_category': 'other'}
        if process and state in {'ACTIVE', 'IDLE'} else None,
    )


async def record(session, device, obs, **kwargs):
    await record_observation(session, device, obs, state=obs.session_state,
                             policy_version_id=None, policy=AnalyticsPolicy(), **kwargs)


async def rows(session):
    return list((await session.scalars(select(ActivityInterval).order_by(ActivityInterval.started_at))).all())


@pytest.mark.asyncio
async def test_transitions_apps_gaps_replay_and_restart(db):
    session, device, factory = db
    samples = [observation(0), observation(15), observation(30, process='EXCEL.EXE'),
               observation(45, 'IDLE'), observation(60), observation(75, 'LOCKED'),
               observation(90), observation(300, process='chrome.exe'), observation(315, process='chrome.exe')]
    for obs in samples:
        await record(session, device, obs)
    await record(session, device, samples[-1])
    await record(session, device, observation(100, 'LOCKED'))
    result = summarize(await rows(session), NOW, NOW + timedelta(seconds=315))
    assert result['seconds'] == {'ACTIVE': 75, 'IDLE': 15, 'LOCKED': 15, 'DISCONNECTED': 0, 'UNKNOWN': 210}
    apps = {a['label']: a['seconds'] for a in result['applications']}
    assert apps == {'Microsoft Word': 45, 'Microsoft Excel': 15, 'Google Chrome': 15}
    assert result['coverage'] == pytest.approx(105 / 315)
    await session.commit()
    async with factory() as reopened:
        assert await reopened.scalar(select(func.count()).select_from(ActivityCursor)) == 1
        assert summarize(await rows(reopened), NOW, NOW + timedelta(seconds=315)) == result


@pytest.mark.asyncio
async def test_unchanged_heartbeats_compact_and_gap_boundary(db):
    session, device, _ = db
    for second in (0, 15, 30):
        await record(session, device, observation(second))
    # Organization midnight is a deliberate split, not one row per heartbeat.
    for second in (45, 60, 75):
        await record(session, device, observation(second))
    assert len(await rows(session)) == 2
    await record(session, device, observation(120))  # exactly 45 seconds is supported
    await record(session, device, observation(166))  # 46 seconds is wholly unknown
    result = summarize(await rows(session), NOW, NOW + timedelta(seconds=166))
    assert result['seconds']['ACTIVE'] == 120
    assert result['seconds']['UNKNOWN'] == 46


@pytest.mark.asyncio
async def test_identity_switch_and_no_unqualified_cross_device_merge(db):
    session, device, _ = db
    await record(session, device, observation())
    await record(session, device, observation(15, user='OTHER\\Alice'))
    await record(session, device, observation(30, user='OTHER\\Alice'))
    result = await rows(session)
    assert result[0].user_key == 'domain\\alice'
    assert utc(result[0].last_observed_at) == NOW
    assert result[-1].user_key == 'other\\alice'
    assert normalize_login('DOMAIN\\ALICE', device) == 'domain\\alice'
    assert normalize_login('alice', device) != normalize_login('alice', uuid4())
    assert normalize_login(None, device) is None


@pytest.mark.asyncio
async def test_daily_union_timezone_overlap_and_retention(db):
    session, device, _ = db
    other = Device(device_identifier='analytics-other')
    session.add(other)
    await session.flush()
    for second in (0, 15, 30, 45, 60):
        await record(session, device, observation(second))
        await record(session, other.id, observation(second, process='EXCEL.EXE'))
    await rebuild_daily(session, policy=AnalyticsPolicy(), now=NOW + timedelta(seconds=60))
    daily = list((await session.scalars(select(ActivityDaily).where(ActivityDaily.timezone == 'Asia/Yekaterinburg').order_by(ActivityDaily.day))).all())
    assert [d.day for d in daily] == [date(2026, 10, 19), date(2026, 10, 20)]
    assert [d.payload['seconds']['ACTIVE'] for d in daily] == [30, 30]
    assert all(d.payload['overlap_seconds'] == 30 for d in daily)
    assert all(sum(a['seconds'] for a in d.payload['applications']) == 30 for d in daily)
    await retain_analytics(session, policy=AnalyticsPolicy(), now=NOW + timedelta(days=16))
    assert await session.scalar(select(func.count()).select_from(ActivityInterval)) == 0
    assert await session.scalar(select(func.count()).select_from(ActivityDaily)) > 0
    await retain_analytics(session, policy=AnalyticsPolicy(), now=NOW + timedelta(days=92))
    assert await session.scalar(select(func.count()).select_from(ActivityDaily)) == 0


def test_calendar_days_include_dst_and_validate_policy():
    start, end = day_bounds(date(2026, 10, 25), 'Europe/Berlin')
    assert (end - start).total_seconds() == 25 * 3600
    with pytest.raises(ValueError):
        AnalyticsPolicy(detail_days=0)
    with pytest.raises(ValueError):
        AnalyticsPolicy(detail_days=30, aggregate_days=14)
    with pytest.raises(ValueError):
        AnalyticsPolicy(organization_timezone='../invalid')


@pytest.mark.asyncio
async def test_gap_with_different_user_is_not_attributed_to_previous_employee(db):
    session, device, _ = db
    await record(session, device, observation())
    await record(session, device, observation(300, user='OTHER\\Alice'))
    history = await rows(session)
    assert all(r.user_key is None for r in history if r.session_state == 'UNKNOWN')
    old_user = [r for r in history if r.user_key == 'domain\\alice']
    assert summarize(old_user, NOW, NOW + timedelta(seconds=300))['observed_span_seconds'] == 0
