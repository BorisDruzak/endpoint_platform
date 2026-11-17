"""Fleet platform evidence comes from authenticated hello, never inventory text."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4
from endpoint_contracts import AgentHeartbeatV1, AgentHelloV1
from endpoint_server.db.models import DeviceInstance, DeviceSession
from endpoint_server.gateway.presence_service import PresenceService
from .conftest import agent_hello, seed_device


async def test_authenticated_hello_persists_exact_platform_and_reconnect_refreshes_it(session_provider):
    device = await seed_device(session_provider)
    instance_id = uuid4()
    payload = agent_hello(device.id, instance_id=instance_id)
    payload['platform'] = 'windows_amd64'
    service = PresenceService(session_provider)
    presence = await service.open_session(device_id=device.id, hello=AgentHelloV1.model_validate(payload),
        source_address='192.168.101.20')
    async with session_provider() as session:
        assert (await session.get(DeviceInstance, presence.device_instance_id)).platform == 'windows_amd64'
    payload['platform'] = 'linux_amd64'
    await service.open_session(device_id=device.id, hello=AgentHelloV1.model_validate(payload),
        source_address='192.168.101.20')
    async with session_provider() as session:
        assert (await session.get(DeviceInstance, presence.device_instance_id)).platform == 'linux_amd64'


async def test_session_open_and_first_heartbeat_have_distinct_observation_times(session_provider):
    device = await seed_device(session_provider)
    opened_at = datetime.now(UTC) - timedelta(minutes=1)
    service = PresenceService(session_provider)
    presence = await service.open_session(
        device_id=device.id, hello=AgentHelloV1.model_validate(agent_hello(device.id)),
        source_address="192.168.101.20", observed_at=opened_at,
    )
    async with session_provider() as session:
        row = await session.get(DeviceSession, presence.session_id)
        assert row.created_at == row.last_seen_at

    heartbeat_at = opened_at + timedelta(seconds=30)
    await service.record_heartbeat(
        device_id=device.id, session_id=presence.session_id,
        heartbeat=AgentHeartbeatV1(
            schema_version="agent_heartbeat_v1", device_id=device.id, platform="linux",
            agent_version="3.2.0", reported_at=heartbeat_at,
        ), observed_at=heartbeat_at,
    )
    async with session_provider() as session:
        row = await session.get(DeviceSession, presence.session_id)
        assert row.last_seen_at > row.created_at
