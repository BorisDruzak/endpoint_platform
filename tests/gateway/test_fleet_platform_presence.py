"""Fleet platform evidence comes from authenticated hello, never inventory text."""
from uuid import uuid4
from endpoint_contracts import AgentHelloV1
from endpoint_server.db.models import DeviceInstance
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
