"""Preserve the deployed DAG and both populated paths during explicit promotion."""
import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import asyncpg
import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import select

from endpoint_server.db.models import AdminUser, ConfirmedIdentity, ScopedRoleGrant
from endpoint_server.db.models.worktime_sessions import HelpdeskWorktimeSession, WorktimeLoginFlow
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.support_access.platforms import verified_platform
from endpoint_server.worktime.service import transition, request_correction, finalize_timesheet
from tests.server.test_linux_support_lifecycle_postgresql import seed
from tests.server.test_update_postgresql import update_migration_database_urls, _alembic_config, _fetch

HEAD = '0051_staging_linux_worktime'
PARENTS = ('0050_linux_enrollment_binding', '0044_worktime_helpdesk')
ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.usefixtures('preserve_migration_loggers')


def test_staging_merge_preserves_both_original_branches():
    script = ScriptDirectory.from_config(_alembic_config('postgresql+asyncpg://unused@127.0.0.1/unused'))
    assert script.get_heads() == [HEAD]
    merge = script.get_revision(HEAD)
    assert merge.down_revision == PARENTS and merge.is_merge_point
    assert script.get_revision('0044_worktime_helpdesk').down_revision == '0043_worktime_recorded'
    assert script.get_revision('0043_worktime_recorded').down_revision == '0042_worktime_companion'
    assert script.get_revision('0043_setup_updates').down_revision == '0042_worktime_companion'
    # Exact original DDL is part of the preserved staging provenance.
    expected = {'0043_worktime_recorded.py': 'bee0067cdd618ac9e3ea6ee60b5cf78d74c910fc5d2b1e8451d3d754af6adf70', '0044_worktime_helpdesk.py': '4eefc85b3a6a68a809168f705394c19a98f58db21e899ef7cc2156a439b172f9'}
    for name, digest in expected.items():
        assert hashlib.sha256((ROOT / 'endpoint_server/db/migrations/versions' / name).read_bytes().replace(b'\r\n', b'\n')).hexdigest() == digest


def test_populated_production0050_upgrade_preserves_native_identity(update_migration_database_urls):
    url, plain = update_migration_database_urls
    config = _alembic_config(url)
    command.upgrade(config, '0050_linux_enrollment_binding')

    async def populate():
        provider = AsyncSessionProvider(url)
        try:
            async with provider() as session:
                principal = await seed(session)
                await session.commit()
                return principal.device.id
        finally:
            await provider.close()

    device = asyncio.run(populate())
    columns, before = asyncio.run(fingerprint(plain))
    command.upgrade(config, HEAD)
    assert asyncio.run(_fetch(plain, 'SELECT version_num FROM alembic_version'))[0]['version_num'] == HEAD
    assert asyncio.run(fingerprint(plain, columns))[1] == before

    async def verify():
        provider = AsyncSessionProvider(url)
        try:
            async with provider() as session:
                assert await verified_platform(session, device) == 'linux_amd64'
        finally:
            await provider.close()

    asyncio.run(verify())
    command.upgrade(config, HEAD)
    assert asyncio.run(fingerprint(plain, columns))[1] == before


async def fingerprint(url, columns=None):
    connection = await asyncpg.connect(url)
    try:
        if columns is None:
            rows = await connection.fetch("SELECT table_name, column_name FROM information_schema.columns WHERE table_schema='public' AND table_name<>'alembic_version' ORDER BY table_name, ordinal_position")
            columns = {}
            for row in rows:
                columns.setdefault(row['table_name'], []).append(row['column_name'])
        values = {}
        for table, names in columns.items():
            # All identifiers originate in PostgreSQL metadata, not user input.
            quote = lambda name: '"' + name.replace('"', '""') + '"'
            projection = ','.join(map(quote, names))
            values[table] = await connection.fetchval("SELECT md5(COALESCE(string_agg(row::text, chr(10) ORDER BY row::text), '')) FROM (SELECT to_jsonb(t) AS row FROM (SELECT " + projection + ' FROM ' + quote(table) + ') t) s')
        return columns, values
    finally:
        await connection.close()


def test_populated_worktime0044_upgrade_preserves_history_and_linux_identity(update_migration_database_urls):
    url, plain = update_migration_database_urls
    config = _alembic_config(url)
    command.upgrade(config, '0044_worktime_helpdesk')

    async def populate():
        provider = AsyncSessionProvider(url)
        now = datetime(2026, 10, 1, tzinfo=UTC)
        start = datetime(2026, 9, 5, 4, tzinfo=UTC)
        person = uuid4()
        try:
            async with provider() as session:
                principal = await seed(session)
                admin = AdminUser(username='staging-preservation-fixture', password_digest='fixture-only', scopes=[])
                identity = ConfirmedIdentity(person_id=person, issuer='https://helpdesk-staging.sosnadmin.local', subject=str(person), authority_kind='helpdesk', ad_object_guid=None, state='active', confirmed_at=now)
                session.add_all([admin, identity]); await session.flush()
                session.add(ScopedRoleGrant(identity_id=identity.id, role='employee', granted_by=admin.id))
                session.add(HelpdeskWorktimeSession(identity_id=identity.id, session_digest='a'*64, lease_encrypted='opaque-fixture', expires_at=now+timedelta(hours=1)))
                session.add(WorktimeLoginFlow(state_digest='b'*64, browser_digest='c'*64, verifier_encrypted='opaque-fixture', expires_at=now+timedelta(hours=1)))
                await transition(session, person, person, 'start', uuid4(), start)
                await transition(session, person, person, 'end', uuid4(), start+timedelta(hours=8))
                await request_correction(session, person, person, start, start+timedelta(hours=1), 'BREAK', 'Recorded fixture', uuid4(), now)
                sheet = await finalize_timesheet(session, person, person, '2026-09', 'Self finalized fixture', uuid4(), now)
                assert sheet.finalized_by == person
                await session.commit()
                return principal.device.id
        finally:
            await provider.close()

    device = asyncio.run(populate())
    columns, before = asyncio.run(fingerprint(plain))
    command.upgrade(config, 'head')
    assert asyncio.run(_fetch(plain, 'SELECT version_num FROM alembic_version'))[0]['version_num'] == HEAD
    assert asyncio.run(fingerprint(plain, columns))[1] == before
    assert asyncio.run(_fetch(plain, "SELECT count(*) AS n FROM pg_constraint WHERE conname='ck_worktime_timesheet_independent'"))[0]['n'] == 0
    assert asyncio.run(_fetch(plain, 'SELECT count(*) AS n FROM enrollment_requests'))[0]['n'] == 0
    async def verify():
        provider = AsyncSessionProvider(url)
        try:
            async with provider() as session:
                assert await verified_platform(session, device) == 'linux_amd64'
                identity = await session.scalar(select(ConfirmedIdentity))
                assert identity.authority_kind == 'helpdesk' and identity.ad_object_guid is None
        finally:
            await provider.close()
    asyncio.run(verify())
    # Reapplying head is inert, including original sessions and complete ledger rows.
    command.upgrade(config, 'head')
    assert asyncio.run(fingerprint(plain, columns))[1] == before
