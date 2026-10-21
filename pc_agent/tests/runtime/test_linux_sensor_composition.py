"""Linux composes existing Policy cache, Activity dispatch and Sensor Health."""
import os
import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from endpoint_contracts.endpoint_policy import policy_digest
from endpoint_contracts.gateway_ws import EndpointPolicyDeliveryV1
from pc_agent.runtime import application
from pc_agent.tests.policy.test_runtime import _delivery


def test_linux_dlp_features_are_separate_from_the_activity_candidate():
    old = application._policy_protocol_features('3.2.122','linux_amd64','gateway_wss',False)
    new = application._policy_protocol_features('3.2.123','linux_amd64','gateway_wss',False)
    assert 'endpoint.security-events.v1' not in old
    assert {'endpoint.security-events.v1','endpoint.browser-status.v1'} <= set(new)


@pytest.mark.asyncio
async def test_initial_spool_failure_does_not_abort_core_startup(tmp_path, monkeypatch):
    async def unavailable(_self): raise OSError('spool unavailable')
    monkeypatch.setattr(application,'os',SimpleNamespace(name='posix'))
    monkeypatch.setattr(application,'AGENT_VERSION','3.2.123')
    monkeypatch.setattr(application.SecurityEventRuntime,'open',unavailable)
    settings=application.RuntimeSettings(data_root=tmp_path/'data',install_root=tmp_path/'install',
        ca_file=tmp_path/'ca.crt',endpoint_origin='https://endpoint.example',transport_mode='gateway_wss')
    settings.data_root.mkdir(mode=0o700)
    dependencies=application._default_dependencies(settings)
    await dependencies.restore_policy(settings)
    acknowledgement=await dependencies.policy_handler(_delivery(active=False))
    assert acknowledgement.status == 'APPLIED'


@pytest.mark.asyncio
async def test_linux_print_reaches_the_shared_spool_when_optional_usb_fails(tmp_path, monkeypatch):
    from pc_agent import browser_identity, browser_status as shared_browser_status
    from pc_agent.platform.linux import sensor_listener, usb_sensor, print_sensor, browser_status
    from pc_agent.security.spool import SecurityEventSpool

    captured = {}
    browser_gates=[]
    class BrowserRuntime:
        def __init__(self, **_kwargs): pass
        def begin_connection(self): browser_gates.append('pause')
        def policy_ack_sent(self): browser_gates.append('resume')
    monkeypatch.setattr(shared_browser_status,'BrowserStatusRuntime',BrowserRuntime)
    class Listener:
        available=True
        def start(self): pass
        def stop(self): self.available=False
    def create_listener(**kwargs):
        captured.update(kwargs)
        return Listener()
    class Usb:
        available=False
        def __init__(self, _callback): pass
        def start(self): raise OSError('optional source unavailable')
        def stop(self): pass
    class Print:
        available=True
        def __init__(self, callback): captured['print_callback']=callback
        def start(self): pass
        def stop(self): self.available=False
    class Probe:
        def __init__(self, **_kwargs): pass
        def bridge_available(self): return True
    monkeypatch.setattr(application,'os',SimpleNamespace(name='posix'))
    monkeypatch.setattr(application,'AGENT_VERSION','3.2.123')
    monkeypatch.setattr(sensor_listener,'create_activity_listener',create_listener)
    monkeypatch.setattr(browser_identity,'load_packaged_extension_id',lambda:'a'*32)
    monkeypatch.setattr(browser_status,'LinuxBrowserProbe',Probe)
    monkeypatch.setattr(usb_sensor,'UsbNotifications',Usb)
    monkeypatch.setattr(print_sensor,'PrintNotifications',Print)
    monkeypatch.setattr('pc_agent.policy.linux_sensors.send_policy_request',lambda *_args:'EXTERNALLY_MANAGED')
    settings=application.RuntimeSettings(data_root=tmp_path/'data',install_root=tmp_path/'install',
        ca_file=tmp_path/'ca.crt',endpoint_origin='https://endpoint.example',transport_mode='gateway_wss')
    settings.data_root.mkdir(mode=0o700)
    dependencies=application._default_dependencies(settings)
    sensors=dependencies.start_local_sensor(settings)
    assert sensors is not None
    try:
        await dependencies.restore_policy(settings)
        disabled=_delivery(active=False)
        policy=disabled.policy.model_copy(update={'dlp':disabled.policy.dlp.model_copy(update={'print_events':'audit'})})
        delivery=EndpointPolicyDeliveryV1(**(disabled.model_dump()|{'policy':policy,'policy_digest':policy_digest(policy)}))
        ack=await dependencies.policy_handler(delivery)
        assert ack.status == 'APPLIED',ack.error_code
        dependencies.security_policy_ack_sent()
        assert browser_gates == ['pause','resume']
        assert captured['ingress']._extension_id == 'a'*32
        facts=print_sensor.PrintFacts(987,uuid4(),datetime.now(UTC),'acceptance-printer',None,1)
        await asyncio.to_thread(captured['print_callback'],facts)
        spool=SecurityEventSpool(settings.data_root)
        await spool.open()
        batch=await spool.next_batch(now=datetime.now(UTC))
        assert batch is not None and len(batch.events) == 1
        assert batch.events[0].event_type == 'PRINT_JOB'
        assert batch.events[0].policy_id == policy.policy_id
        failed=policy.model_copy(update={'dlp':policy.dlp.model_copy(update={'usb_device_events':'audit'})})
        rejected=await dependencies.policy_handler(EndpointPolicyDeliveryV1(**(delivery.model_dump()|{
            'policy':failed,'policy_digest':policy_digest(failed)})))
        assert rejected.status == 'ERROR' and rejected.error_code == 'SENSOR_NOT_READY'
        dependencies.security_policy_ack_sent()
        assert browser_gates == ['pause','resume','pause']
    finally:
        sensors.stop()


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
