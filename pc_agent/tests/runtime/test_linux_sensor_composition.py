"""Linux composes existing Policy cache, Activity dispatch and Sensor Health."""
import os

import pytest

from endpoint_contracts.endpoint_policy import policy_digest
from endpoint_contracts.gateway_ws import EndpointPolicyDeliveryV1
from pc_agent.runtime import application
from pc_agent.tests.policy.test_runtime import _delivery


@pytest.mark.skipif(os.name != 'posix', reason='real Linux local listener')
@pytest.mark.asyncio
async def test_listener_failure_rejects_policy_without_terminating_core(tmp_path, monkeypatch):
    from pc_agent.platform.linux import sensor_listener
    from pc_agent.policy.cache import AppliedPolicyCache

    monkeypatch.setattr(application, 'AGENT_VERSION', '3.2.122')
    real_factory = sensor_listener.create_activity_listener
    monkeypatch.setattr(sensor_listener, 'create_activity_listener', lambda **kwargs: real_factory(socket_path=tmp_path / 'sensor.sock', **kwargs))
    settings = application.RuntimeSettings(data_root=tmp_path / 'data', install_root=tmp_path / 'install',
        ca_file=tmp_path / 'ca.crt', endpoint_origin='https://endpoint.example', transport_mode='gateway_wss')
    settings.data_root.mkdir(mode=0o700)
    dependencies = application._default_dependencies(settings)
    listener = dependencies.start_local_sensor(settings)
    assert listener is not None and listener.available
    try:
        await dependencies.restore_policy(settings)
        inactive = _delivery(active=False)
        policy = inactive.policy.model_copy(update={'activity': inactive.policy.activity.model_copy(update={'enabled': True})})
        delivery = EndpointPolicyDeliveryV1(**(inactive.model_dump() | {'policy': policy, 'policy_digest': policy_digest(policy)}))
        ack = await dependencies.policy_handler(delivery)
        assert ack.status == 'APPLIED', ack.error_code
        assert AppliedPolicyCache(settings.data_root).load().policy == policy
        listener.stop()
        ack = await dependencies.policy_handler(delivery)
        assert ack.status == 'ERROR' and ack.error_code == 'SENSOR_NOT_READY'
    finally:
        listener.stop()
