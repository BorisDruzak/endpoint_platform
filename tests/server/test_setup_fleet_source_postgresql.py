"""Separate WSS/observer arrivals never authorize a different native source."""
import asyncio
from datetime import timedelta
from sqlalchemy import select, delete
from endpoint_server.db.models import DeviceInstance, DeviceSession, UpdateRollout, UpdateTarget
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.setup_updates.models import SetupClientPresence, SetupAssignment, SetupFleetDecision, SetupFleetQualification, SetupPreparation
from endpoint_server.setup_updates.scheduler import schedule_one
from endpoint_server.setup_updates.service import record_presence
from tests.server.test_setup_fleet_postgresql import fleet_database, seed
from tests.server.test_update_postgresql import update_migration_database_urls
from tests.server.test_setup_preparation import build
from endpoint_server.setup_updates.preparation import advance_preparations


def test_modern_reconnect_requires_fresh_matching_observer_before_first_native_assignment(fleet_database):
    async def scenario():
        provider = AsyncSessionProvider(fleet_database[0])
        try:
            async with provider() as session:
                release, devices, policy, now = await seed(session, count=1)
                device = devices[0]
                release.version = '3.2.165'
                instance = await session.scalar(select(DeviceInstance).where(DeviceInstance.device_id == device.id))
                instance.agent_version, instance.launcher_version = '3.2.164', '3.2.158'
                q = await session.scalar(select(SetupFleetQualification).where(SetupFleetQualification.release_id == release.id))
                q.source_foundation = '3.2.158'
                client = await session.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == device.id))
                client.core_version, client.foundation_version = '3.2.164', '3.2.158'
                client.last_seen_at = now-timedelta(minutes=12)
                policy.max_parallel = 2
                await session.commit()
                for tick, expected, foundation, core in [
                    (0, 'waiting_setup_client', None, None),
                    (1, 'waiting_source_confirmation', '3.2.156', '3.2.156'),
                    (2, 'chain_requested', '3.2.158', '3.2.164'),
                ]:
                    at = now+timedelta(seconds=tick)
                    if foundation:
                        await record_presence(session, device.id, dict(client_version='1.0.5', ready=True,
                            foundation_version=foundation, core_version=core), now=at)
                    await schedule_one(session, now=at)
                    await session.commit()
                    decision = await session.scalar(select(SetupFleetDecision).where(SetupFleetDecision.device_id == device.id))
                    assert decision.safe_code == expected
                    assert policy.enabled and policy.safe_code is None
                    jobs = (await session.scalars(select(SetupAssignment).where(SetupAssignment.device_id == device.id))).all()
                    assert len(jobs) == (1 if tick == 2 else 0)
                assert jobs[0].source_foundation_version == '3.2.158'
                assert jobs[0].source_core_version == '3.2.164'
        finally:
            await provider.close()
    asyncio.run(scenario())


def test_missing_modern_observer_uses_one_persisted_upward_child_and_fresh_wss(fleet_database):
    async def scenario():
        provider = AsyncSessionProvider(fleet_database[0])
        try:
            async with provider() as session:
                release, devices, policy, now = await seed(session, count=1)
                device = devices[0]
                release.version = '3.2.167'
                # The preceding scenario retains its assigned chain. It still
                # reserves one global slot across a new policy revision.
                policy.max_parallel = 2
                instance = await session.scalar(select(DeviceInstance).where(DeviceInstance.device_id == device.id))
                instance.agent_version = instance.launcher_version = '3.2.165'
                connection = await session.scalar(select(DeviceSession).where(DeviceSession.device_id == device.id))
                connection.created_at = now-timedelta(minutes=4)
                qualification = await session.scalar(select(SetupFleetQualification).where(SetupFleetQualification.release_id == release.id))
                qualification.source_foundation = '3.2.165'
                await session.execute(delete(SetupClientPresence).where(SetupClientPresence.device_id == device.id))
                bootstrap = build('3.2.166', 'endpoint-windows-core-3.2.166-observer-bootstrap')
                bootstrap.minimum_launcher_version = '3.2.158'
                session.add(bootstrap)
                await session.commit()
                assert await schedule_one(session, now=now)
                await session.commit()
                decision = await session.scalar(select(SetupFleetDecision).where(SetupFleetDecision.device_id == device.id))
                assert decision.safe_code == 'chain_requested', decision.safe_code
                prep_id = decision.job_id
                prep = await session.get(SetupPreparation, prep_id)
                assert prep.status == 'preparing_client' and prep.return_build_id is None
                assert await session.get(SetupAssignment, prep_id) is None

            # A fresh session must find the same preparation after worker restart.
            async with provider() as session:
                prep = await session.get(SetupPreparation, prep_id)
                child = await session.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == prep.bridge_rollout_id))
                assert (await session.get(UpdateRollout, child.rollout_id)).build_id == bootstrap.id
                child.status = 'applied'
                instance = await session.scalar(select(DeviceInstance).where(DeviceInstance.device_id == device.id))
                instance.agent_version = '3.2.166'
                await record_presence(session, device.id, dict(client_version='1.0.6', ready=True,
                    foundation_version='3.2.165', core_version='3.2.166'), now=now)
                await advance_preparations(session, now=now)
                await session.commit()

            async with provider() as session:
                prep = await session.get(SetupPreparation, prep_id)
                job = await session.get(SetupAssignment, prep_id)
                assert prep.status == 'completed' and prep.return_rollout_id is None
                assert job.status == 'assigned' and job.source_core_version == '3.2.166'
                assert job.source_foundation_version == '3.2.165' and job.source_client_version == '1.0.6'
                children = (await session.scalars(select(UpdateTarget).where(UpdateTarget.device_id == device.id))).all()
                assert len(children) == 1
        finally:
            await provider.close()
    asyncio.run(scenario())
