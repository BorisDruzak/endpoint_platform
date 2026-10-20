"""Real administrative API projections over synthetic measured telemetry."""
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, func, select

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.db.models import AdminUser, AdminSession, AuditEvent, Device, DeviceInstance, DeviceSession
from endpoint_server.main import create_app
from endpoint_server.console import activity_analytics as routes
from tests.activity.test_analytics import db, observation, record, NOW
from endpoint_server.activity.analytics_models import ActivityDaily
from endpoint_server.activity.analytics_store import rebuild_daily
from endpoint_server.activity.analytics_policy import AnalyticsPolicy
from endpoint_server.activity.analytics_reports import employees, report_rows


@pytest.mark.asyncio
async def test_admin_only_bounded_reports_and_audited_timeline(db, monkeypatch):
    session, device, factory = db
    async with session.bind.begin() as connection:
        await connection.run_sync(lambda c: [t.create(c) for t in [DeviceInstance.__table__, DeviceSession.__table__, AuditEvent.__table__]])
    missing = Device(device_identifier='linux-no-sensor', display_name='ALT without Activity')
    session.add(missing)
    await session.flush()
    for second in (0, 15, 30, 45, 60):
        await record(session, device, observation(second))
    session.add(DeviceSession(device_id=device, session_identifier='gateway-test',
        created_at=NOW, last_seen_at=NOW + timedelta(seconds=60),
        expires_at=NOW + timedelta(seconds=150), closed_at=NOW + timedelta(seconds=65)))
    session.add(DeviceSession(device_id=missing.id, session_identifier='gateway-online-no-activity',
        created_at=NOW, last_seen_at=NOW + timedelta(seconds=300),
        expires_at=NOW + timedelta(seconds=390)))
    await rebuild_daily(session, policy=AnalyticsPolicy(), now=NOW + timedelta(seconds=60))
    await session.commit()
    monkeypatch.setattr(routes, 'now_utc', lambda: NOW + timedelta(seconds=300))
    settings = Settings(database_url='unused', public_base_url='https://endpoint.sosnadmin.local',
        device_token_pepper=b'x', service_token_pepper=b'x', session_secret=b'x',
        allowed_agent_cidrs=(), allowed_admin_cidrs=(), artifact_root=Path('.'))
    app = create_app(settings, session_provider=factory)
    async with AsyncClient(transport=ASGITransport(app=app), base_url=settings.public_base_url) as client:
        prefix = '/api/admin/console/activity-analytics'
        assert (await client.get(prefix + '/overview')).status_code == 401
        app.dependency_overrides[require_admin] = lambda: AdminPrincipal(
            user=AdminUser(id=uuid4(), username='analytics-admin', password_digest='unused', scopes=[]),
            session=AdminSession(id=uuid4(), admin_user_id=uuid4(), session_digest='unused', expires_at=NOW + timedelta(days=1)),
        )
        query = '?period=custom&since=2026-10-19&until=2026-10-20&timezone=Asia%2FYekaterinburg'
        overview = await client.get(prefix + '/overview' + query)
        assert overview.status_code == 200, overview.text
        data = overview.json()
        assert data['total'] == 2
        employee = next(r for r in data['data'] if r['user_key'])
        assert employee['state'] == 'UNKNOWN' and not employee['fresh']
        assert employee['metrics']['seconds']['ACTIVE'] == 60
        assert employee['devices'][0]['online'] is False
        unsupported = next(r for r in data['data'] if r['user_key'] is None)
        assert unsupported['metrics'] is None and unsupported['state'] == 'UNKNOWN'
        assert unsupported['devices'][0]['online'] is True  # ONLINE never establishes ACTIVE
        assert data['summary']['unknown_devices'] == 1
        filtered = await client.get(prefix + '/overview' + query + '&search=analytics-test&limit=1')
        assert filtered.json()['total'] == 1
        report = await client.get(prefix + '/user' + query + '&user_key=domain%5Calice')
        assert report.status_code == 200, report.text
        assert report.json()['data']['metrics']['applications'][0]['label'] == 'Microsoft Word'
        assert [d['metrics']['seconds']['ACTIVE'] for d in report.json()['daily']] == [30, 30]
        timeline = await client.get(prefix + '/timeline?user_key=domain%5Calice&day=2026-10-20&timezone=Asia%2FYekaterinburg')
        assert timeline.status_code == 200, timeline.text
        assert any(s['state'] == 'ACTIVE' for s in timeline.json()['data'])
        assert any(s['state'] == 'UNKNOWN' and not s['attributed'] for s in timeline.json()['data'])
        assert timeline.json()['connection_gaps']
        assert (await client.get(prefix + '/overview?timezone=../x')).status_code == 422
        assert (await client.get(prefix + '/overview?period=custom&since=2020-01-01&until=2026-10-20')).status_code == 422
        assert (await client.get(prefix + '/timeline?user_key=domain%5Calice&day=2026-09-01')).status_code == 410
        assert (await client.get(prefix + '/overview?limit=1001')).status_code == 422
        assert (await client.get(prefix + '/overview?search=%00')).status_code == 422
    async with factory() as check:
        assert await check.scalar(select(func.count()).select_from(AuditEvent).where(
            AuditEvent.action == 'activity.analytics.read')) == 2
        assert await check.scalar(select(func.count()).select_from(ActivityDaily)) == 3


@pytest.mark.asyncio
async def test_overview_queries_are_constant_for_120_device_fleet(db):
    session, _, _ = db
    async with session.bind.begin() as connection:
        await connection.run_sync(lambda c: [t.create(c) for t in [DeviceInstance.__table__, DeviceSession.__table__]])
    session.add_all(Device(device_identifier=f'fleet-{index:03}') for index in range(120))
    await session.flush()
    statements = []
    def count(_conn, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().upper().startswith('SELECT'):
            statements.append(statement)
    event.listen(session.bind.sync_engine, 'before_cursor_execute', count)
    try:
        daily = await report_rows(session, SimpleNamespace(timezone='UTC', since=NOW.date(), until=NOW.date()))
        result = await employees(session, daily, NOW, 45)
        assert len(result) == 121
        assert len(statements) == 4  # one daily query + three batched fleet queries
        assert all(row['state'] == 'UNKNOWN' and row['metrics'] is None for row in result)
    finally:
        event.remove(session.bind.sync_engine, 'before_cursor_execute', count)
