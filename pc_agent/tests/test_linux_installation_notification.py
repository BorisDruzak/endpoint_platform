import asyncio
from uuid import uuid4
from contextlib import contextmanager
from types import SimpleNamespace
import pytest
from pc_agent.tests.test_linux_installation_lifecycle import MemoryStore, source
from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending


def test_failed_or_mismatched_ack_never_overtakes_removed_event():
    from pc_agent.platform.linux.installation_notification import drain_events
    journal = LifecycleJournal(MemoryStore())
    device = str(uuid4())
    for action in ('remove', 'install'):
        journal.begin(action, source())
        journal.native_result(0)
        journal.settle(exact_native_state=True, device_id=device)
    calls = []
    class Transport:
        async def post(self, path, event, bearer):
            calls.append(event['action'])
            return {**event, 'event_id': str(uuid4())}
    with pytest.raises((InstallationPending, ValueError)):
        asyncio.run(drain_events(journal, Transport(), 'x'*43))
    assert calls == ['removed']
    assert [e['sequence'] for e in journal.pending_events()] == [1, 2]


def test_events_ack_exact_order_and_keep_credential_out_of_payload():
    from pc_agent.platform.linux.installation_notification import drain_events
    journal = LifecycleJournal(MemoryStore())
    device = str(uuid4())
    for action in ('remove', 'install'):
        journal.begin(action, source())
        journal.native_result(0)
        journal.settle(exact_native_state=True, device_id=device)
    calls = []
    class Transport:
        async def post(self, path, event, bearer):
            assert bearer == 'x'*43 and 'x'*43 not in str(event)
            calls.append(event['action'])
            return {k: event[k] for k in ('device_id','event_id','generation_id','sequence')} | {
                'schema_version':'endpoint_installation_event_ack_v1','state': event['action'],'received_at':event['occurred_at']}
    asyncio.run(drain_events(journal, Transport(), 'x'*43))
    assert calls == ['removed', 'installed']
    assert journal.pending_events() == []


def test_acknowledged_delivery_never_replaces_rotated_retained_credential(monkeypatch, tmp_path):
    from pc_agent.platform.linux import installation_notification as n
    device = str(uuid4())
    class Private:
        def __init__(self, directory): pass
        @contextmanager
        def locked(self): yield self
        def read(self):
            return {'delivery': {'schema_version':'agent_enrollment_delivery_v1','device_id':device,
                'device_token':'o'*43,'enrollment_receipt':'e'*43,'policy_id':'fixture','policy':{},
                'issued_at':'2026-11-07T00:00:00Z'}, 'canonical_acknowledged':True}
    monkeypatch.setattr(n,'LinuxPrivateEnrollmentStore',Private)
    monkeypatch.setattr(n,'canonical_identity',lambda: (device,'r'*43))
    result = asyncio.run(n.ensure_identity(SimpleNamespace(paths=SimpleNamespace(private=tmp_path)),
        {'action':'upgrade'},None,{}))
    assert result == (device,'r'*43)


def test_absent_graphical_environment_completes_machine_bootstrap_once(monkeypatch):
    from pc_agent.platform.linux import installation_notification as n, installation_coordinator as c
    from pc_agent.platform.linux import installation_user_sessions as sensors, support_access_service as support
    from pc_agent.tests.test_linux_installation_coordinator import Backend
    store, device = MemoryStore(), str(uuid4())
    @contextmanager
    def locked(): yield store
    store.locked = locked
    journal = LifecycleJournal(store)
    native = source() | {'user_sensor_nevra':'endpoint-agent-user-sensor-3.2.178-alt6.x86_64','user_sensor_rpm_sha256':'c'*64}
    journal.begin('install',native)
    journal.native_result(0)
    journal.settle(exact_native_state=True,device_id=device)
    backend = Backend()
    units = []
    backend._systemctl = lambda *args: units.append(args)
    monkeypatch.setattr(c,'RPMBackend',lambda _:backend)
    import json
    monkeypatch.setattr(n,'read_secret',lambda path: json.dumps({'gateway':{
        'endpoint':'https://example.invalid','ca_file':str(n.CA)}}).encode())
    monkeypatch.setattr(n,'configured_endpoint_origin',lambda: 'https://example.invalid')
    monkeypatch.setattr(n,'NotificationTransport',lambda *_:object())
    async def identity(*_): return device,'x'*43
    async def drain(*_): pass
    monkeypatch.setattr(n,'ensure_identity',identity)
    monkeypatch.setattr(n,'drain_events',drain)
    registrations = []
    monkeypatch.setattr(support,'install_from_enrollment',lambda **kw: registrations.append(kw['device_id']))
    monkeypatch.setattr(sensors,'session_ids',lambda: ['6'])
    monkeypatch.setattr(sensors,'session_context',lambda _:None)
    asyncio.run(n.notify(store))
    assert journal.state()['operation']['bootstrap'] == 'complete'
    assert store.data['sensor-handoff-result.json'] == [{'session':'6','status':'session_prerequisite_absent'}]
    assert store.data['runtime-ready']['operation_id'] == journal.state()['operation']['id']
    count = len(units)
    asyncio.run(n.notify(store))
    assert registrations == [device] and len(units) == count
