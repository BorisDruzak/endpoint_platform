"""Real isolated PostgreSQL: migration, last-slot races, cookie/CSRF and revisions."""
import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from alembic import command
from sqlalchemy import select, text

from endpoint_server.auth.admin_sessions import ADMIN_SESSION_COOKIE, issue_admin_session
from endpoint_server.db.models import Device, DeviceInstance, DeviceSession, AdminUser
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.main import create_app
from endpoint_server.setup_updates.models import SetupRelease, SetupAssignment, SetupFleetQualification, SetupFleetPolicy, SetupFleetDecision
from endpoint_server.setup_updates.policy import FleetPolicyUpdate, update_policy
from endpoint_server.setup_updates.scheduler import schedule_one
from endpoint_server.setup_updates.preparation import request_setup
from endpoint_server.setup_updates.service import record_presence, SetupConflict
from tests.server.test_update_agent_api import _settings
from tests.server.test_update_postgresql import update_migration_database_urls, _alembic_config, _fetch

pytestmark = pytest.mark.usefixtures('preserve_migration_loggers')


@pytest.fixture(scope='module')
def fleet_database(update_migration_database_urls):
    url, plain = update_migration_database_urls
    command.upgrade(_alembic_config(url), 'head')
    return url, plain


async def seed(session, *, count=2):
    now = datetime.now(UTC)
    release = SetupRelease(id=uuid4(), release_identifier='fleet-'+uuid4().hex, version='3.2.158',
        artifact_name=uuid4().hex+'.exe', sha256='a'*64, size=10, source_revision='b'*40,
        msi_sha256='c'*64, tray_sha256='d'*64, sensor_sha256='e'*64)
    witness = Device(id=uuid4(), device_identifier='witness-'+uuid4().hex, retired_at=now)
    session.add_all([release, witness]); await session.flush()
    evidence = SetupAssignment(id=uuid4(), device_id=witness.id, release_id=release.id, status='applied',
        reason='Isolated test fixture only', assigned_at=now, updated_at=now)
    session.add(evidence); await session.flush()
    session.add(SetupFleetQualification(id=uuid4(), release_id=release.id, sha256=release.sha256,
        source_foundation='3.2.156', evidence_assignment_id=evidence.id, qualified_at=now,
        expires_at=now+timedelta(days=1), qualified_by='isolated-test', evidence_code='isolated_fixture'))
    devices = []
    for _ in range(count):
        device = Device(id=uuid4(), device_identifier='fleet-'+uuid4().hex)
        session.add(device); await session.flush()
        instance = DeviceInstance(id=uuid4(), device_id=device.id, instance_identifier=uuid4().hex,
            platform='windows_amd64', agent_version='3.2.156', launcher_version='3.2.156', last_seen_at=now)
        session.add(instance); await session.flush()
        session.add(DeviceSession(id=uuid4(), device_id=device.id, device_instance_id=instance.id,
            session_identifier='gateway-'+uuid4().hex, expires_at=now+timedelta(minutes=5), last_seen_at=now))
        await record_presence(session, device.id, dict(client_version='1.0.5', ready=True,
            core_version='3.2.156', foundation_version='3.2.156'), now=now)
        devices.append(device)
    await session.flush()
    existing = await session.scalar(select(SetupFleetPolicy))
    policy = await update_policy(session, FleetPolicyUpdate(expected_revision=existing.revision if existing else 0,
        enabled=True, release_id=release.id, scope='selected', device_ids=[d.id for d in devices],
        max_parallel=1, reason='Isolated fleet race'), actor='test-admin', request_id=uuid4().hex, now=now)
    await session.commit()
    return release, devices, policy, now


def test_fleet_migration_is_additive_disabled_and_reversible(update_migration_database_urls):
    url, plain = update_migration_database_urls
    config = _alembic_config(url)
    command.downgrade(config, '0044_setup_recovery_hold') if asyncio.run(_fetch(plain, "SELECT to_regclass('alembic_version') AS t"))[0]['t'] else None
    command.upgrade(config, '0044_setup_recovery_hold')
    async def preserve():
        provider = AsyncSessionProvider(url)
        async with provider() as session:
            device_id = uuid4()
            session.add(Device(id=device_id, device_identifier='preserve-before-fleet'))
            await session.flush()
            # Use the actual previous schema: the new ORM has fields that must
            # not exist before0045. Keep this active instance unchanged.
            await session.execute(text('INSERT INTO device_instances '
                '(id,device_id,instance_identifier,agent_version,launcher_version,last_result_sequence) '
                'VALUES (:id,:device_id,:name,:version,:version,0)'),
                dict(id=uuid4(), device_id=device_id, name='preserved-source156', version='3.2.156'))
            await session.commit()
        await provider.close()
    asyncio.run(preserve())
    command.upgrade(config, 'head')
    assert asyncio.run(_fetch(plain, 'SELECT count(*) AS n FROM setup_fleet_policy'))[0]['n'] == 0
    assert asyncio.run(_fetch(plain, 'SELECT count(*) AS n FROM setup_fleet_qualifications'))[0]['n'] == 0
    preserved = asyncio.run(_fetch(plain, "SELECT agent_version,launcher_version,platform FROM device_instances WHERE instance_identifier='preserved-source156'"))[0]
    assert dict(preserved) == dict(agent_version='3.2.156', launcher_version='3.2.156', platform=None)
    command.downgrade(config, '0044_setup_recovery_hold')
    assert asyncio.run(_fetch(plain, "SELECT count(*) AS n FROM devices WHERE device_identifier='preserve-before-fleet'"))[0]['n'] == 1
    command.upgrade(config, 'head')


def test_competing_workers_cannot_claim_the_last_slot_or_replay_on_restart(fleet_database):
    async def scenario():
        provider = AsyncSessionProvider(fleet_database[0])
        try:
            async with provider() as session:
                release, devices, policy, now = await seed(session)
            async with provider() as first:
                assert await schedule_one(first, now=now)
                # The first request remains uncommitted: a second worker skips
                # admission rather than reading the same apparently free slot.
                async with provider() as second:
                    assert await asyncio.wait_for(schedule_one(second, now=now), 2) is False
                    await second.commit()
                await first.commit()
            async with provider() as restarted:
                for tick in range(4):
                    await schedule_one(restarted, now=now+timedelta(seconds=tick+1)); await restarted.commit()
                jobs = (await restarted.scalars(select(SetupAssignment).where(
                    SetupAssignment.device_id.in_([d.id for d in devices])))).all()
                assert len(jobs) == 1 and jobs[0].status == 'assigned'
                decisions = (await restarted.scalars(select(SetupFleetDecision).where(
                    SetupFleetDecision.release_id == release.id))).all()
                assert len(decisions) == 2
                assert sum(d.job_id is not None for d in decisions) == 1
                assert any(d.safe_code == 'capacity_full' for d in decisions)
        finally:
            await provider.close()
    asyncio.run(scenario())


def test_manual_request_waits_for_worker_commit_then_obeys_same_native_limit(fleet_database):
    async def scenario():
        provider = AsyncSessionProvider(fleet_database[0])
        try:
            # Previous isolated scenarios may leave active chains intentionally;
            # retire neither those records nor devices. They must still reserve
            # capacity, so use the whole policy's existing active count below.
            async with provider() as session:
                release, devices, policy, now = await seed(session, count=2)
                from endpoint_server.setup_updates.policy import active_chain_devices
                active = await active_chain_devices(session)
                # This test needs one free slot. Earlier test attempts remain
                # immutable, and a fresh policy limit2 includes their one slot.
                policy.max_parallel = min(2, len(active)+1)
                await session.commit()
            async with provider() as worker:
                assert await schedule_one(worker, now=now)
                admitted = await worker.scalar(select(SetupFleetDecision.device_id).where(
                    SetupFleetDecision.release_id == release.id, SetupFleetDecision.job_id.is_not(None)))
                manual_device = next(device for device in devices if device.id != admitted)
                started = asyncio.Event()
                async def manual():
                    async with provider() as session:
                        started.set()
                        try:
                            await request_setup(session, manual_device.id, release.id, 'Competing manual request',
                                actor='test-admin', request_id=uuid4().hex, now=now)
                        except SetupConflict:
                            await session.rollback(); return 'capacity-conflict'
                        await session.rollback(); return 'unexpected-admission'
                task = asyncio.create_task(manual())
                await started.wait(); await asyncio.sleep(.1)
                assert not task.done()
                await worker.commit()
                assert await asyncio.wait_for(task, 5) == 'capacity-conflict'
        finally:
            await provider.close()
    asyncio.run(scenario())


def test_two_administrators_cannot_lose_an_update(fleet_database):
    async def scenario():
        provider = AsyncSessionProvider(fleet_database[0])
        try:
            async with provider() as session:
                release, devices, policy, now = await seed(session, count=1)
                revision = policy.revision
            body = FleetPolicyUpdate(expected_revision=revision, enabled=False, release_id=release.id,
                scope='selected', device_ids=[devices[0].id], max_parallel=1, reason='Pause isolated fleet')
            async def change():
                async with provider() as session:
                    try:
                        result = await update_policy(session, body, actor='admin', request_id=uuid4().hex, now=now)
                        await session.commit(); return result.revision
                    except SetupConflict:
                        await session.rollback(); return 'conflict'
            results = await asyncio.gather(change(), change())
            assert sorted(map(str, results)) == sorted([str(revision+1), 'conflict'])
        finally:
            await provider.close()
    asyncio.run(scenario())


def test_real_cookie_csrf_scope_preview_and_optimistic_conflict(fleet_database, tmp_path):
    async def scenario():
        provider = AsyncSessionProvider(fleet_database[0])
        settings = replace(_settings(tmp_path), database_url=fleet_database[0])
        try:
            async with provider() as session:
                release, devices, policy, _ = await seed(session, count=1)
                admin = AdminUser(id=uuid4(), username='fleet-'+uuid4().hex, password_digest='test-only', scopes=['updates:write'])
                session.add(admin); await session.flush()
                issued = issue_admin_session(admin.id, settings.session_secret); session.add(issued.record)
                await session.commit()
            app = create_app(settings, provider)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('127.0.0.1', 12345)),
                base_url=settings.public_base_url, cookies={ADMIN_SESSION_COOKIE: issued.token}) as client:
                base = '/api/admin/setup-updates/fleet'
                body = dict(expected_revision=policy.revision, enabled=False, release_id=str(release.id),
                    scope='selected', device_ids=[str(devices[0].id)], max_parallel=2, reason='HTTP isolated pause')
                assert (await client.put(base, json=body)).status_code == 403
                headers = {'X-CSRF-Token': issued.csrf_token}
                async with provider() as session:
                    before = len((await session.scalars(select(SetupFleetDecision))).all())
                preview = await client.post(base+'/preview', headers=headers, json=dict(release_id=str(release.id),
                    scope='selected', device_ids=[str(devices[0].id)], max_parallel=2))
                assert preview.status_code == 200 and preview.json()['read_only'] is True
                async with provider() as session:
                    assert len((await session.scalars(select(SetupFleetDecision))).all()) == before
                saved = await client.put(base, json=body, headers=headers)
                assert saved.status_code == 200, saved.text
                assert saved.json()['data']['enabled'] is False
                assert (await client.put(base, json=body, headers=headers)).status_code == 409
                async with provider() as session:
                    user = await session.get(AdminUser, admin.id); user.scopes=[]; await session.commit()
                body['expected_revision'] += 1
                assert (await client.put(base, json=body, headers={**headers, 'X-Scope':'updates:write'})).status_code == 403
                assert (await client.get(base)).status_code == 200
        finally:
            await provider.close()
    asyncio.run(scenario())
