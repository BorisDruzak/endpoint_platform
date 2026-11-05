"""Separate WSS/observer arrivals never authorize a different native source."""
import asyncio
from datetime import timedelta
from sqlalchemy import select
from endpoint_server.db.models import DeviceInstance
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.setup_updates.models import SetupClientPresence, SetupAssignment, SetupFleetDecision, SetupFleetQualification
from endpoint_server.setup_updates.scheduler import schedule_one
from endpoint_server.setup_updates.service import record_presence
from tests.server.test_setup_fleet_postgresql import fleet_database, seed
from tests.server.test_update_postgresql import update_migration_database_urls


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
