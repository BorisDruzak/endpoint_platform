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
    assert result == (device,'r'*43, True)


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
    async def identity(*_, **_kwargs): return device,'x'*43, False
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

@pytest.mark.parametrize('case', ['retained', 'fresh', 'wrong_ack', 'wrong_device',
    'wrong_generation', 'unknown_native', 'wrong_source', 'wrong_event', 'core_only',
    'recovered_identity', 'other_https_failure'])
def test_support_conflict_starts_only_confirmed_reinstalled_core(monkeypatch, case):
    import json
    from pc_agent.platform.linux import installation_notification as n, installation_coordinator as c
    from pc_agent.platform.linux import installation_user_sessions as sensors, support_access_service as support
    from pc_agent.platform.linux.support_access import SupportError
    from pc_agent.tests.test_linux_installation_coordinator import Backend

    store = MemoryStore()
    @contextmanager
    def locked():
        yield store
    store.locked = locked
    device = str(uuid4())
    journal = LifecycleJournal(store)
    target = source() | {'user_sensor_nevra':'endpoint-agent-user-sensor-3.2.178-alt6.x86_64',
        'user_sensor_rpm_sha256':'c'*64}
    if case == 'core_only':
        target = source()
    if case != 'fresh':
        prior = target if case != 'wrong_source' else target | {'core_rpm_sha256':'d'*64}
        journal.begin('remove', prior)
        journal.native_result(0)
        journal.settle(exact_native_state=True, device_id=device)
        if case == 'wrong_generation':
            changed = journal.state()
            changed.update(generation_id=str(uuid4()))
            journal._save(changed)
    operation = journal.begin('install', target)
    if case != 'unknown_native':
        journal.native_result(0)
        journal.settle(exact_native_state=True, device_id=device)
    if case == 'wrong_event':
        store.data['event-2.json']['event_id'] = str(uuid4())

    class Transport:
        async def post(self, path, event, bearer):
            return {k: event[k] for k in ('device_id','event_id','generation_id','sequence')} | {
                'schema_version':'endpoint_installation_event_ack_v1',
                'state':'installed' if case == 'wrong_ack' else event['action'],
                'received_at':event['occurred_at']}

    backend = Backend()
    units = []
    backend._systemctl = lambda *args: units.append(args)
    monkeypatch.setattr(c, 'RPMBackend', lambda _: backend)
    monkeypatch.setattr(n, 'read_secret', lambda _: json.dumps({'gateway':{
        'endpoint':'https://example.invalid', 'ca_file':str(n.CA)}}).encode())
    monkeypatch.setattr(n, 'configured_endpoint_origin', lambda: 'https://example.invalid')
    monkeypatch.setattr(n, 'NotificationTransport', lambda *_: Transport())
    identity_calls = 0
    async def identity(*_, **kwargs):
        nonlocal identity_calls
        identity_calls += 1
        if case == 'recovered_identity' and identity_calls == 1:
            if 'note_identity_recovery' in kwargs:
                kwargs['note_identity_recovery']()
            return device, 'x'*43, False
        return (str(uuid4()) if case == 'wrong_device' else device), 'x'*43, case not in ('fresh',)
    monkeypatch.setattr(n, 'ensure_identity', identity)

    def fail_registration(**_kwargs):
        raise SupportError('https_unavailable' if case == 'other_https_failure' else 'registration_conflict')
    monkeypatch.setattr(support, 'install_from_enrollment', fail_registration)

    if case == 'retained':
        write = store.write
        def interrupted_readiness(name, raw):
            if name == 'core-ready':
                raise KeyboardInterrupt()
            write(name, raw)
        store.write = interrupted_readiness
        with pytest.raises(KeyboardInterrupt):
            asyncio.run(n.notify(store))
        assert store.data['support-pending']['operation_id'] == operation['id']
        assert 'core-ready' not in store.data and 'runtime-ready' not in store.data
        assert ('start', 'endpoint-agent.service') not in units
        store.write = write
    with pytest.raises((InstallationPending, SupportError)):
        asyncio.run(n.notify(store))
    assert 'runtime-ready' not in store.data
    assert journal.state()['operation']['bootstrap'] == 'pending'
    if case == 'retained':
        assert store.data['core-ready']['operation_id'] == operation['id']
        assert store.data['support-pending'] == store.data['core-ready']
        assert ('start', 'endpoint-agent.service') in units
        assert not any('endpoint-agent-update.path' in args or 'endpoint-agent-browser-policy.service' in args
            or args[:2] == ('enable', '--now') for args in units)
        repeated = LifecycleJournal(store)
        with pytest.raises((InstallationPending, SupportError)):
            asyncio.run(n.notify(store))
        assert repeated.state()['acknowledged'] == repeated.state()['sequence'] == 2
        assert repeated.state()['operation']['id'] == operation['id']
        monkeypatch.setattr(support, 'install_from_enrollment', lambda **_kwargs: None)
        monkeypatch.setattr(sensors, 'handoff_active_sensors', lambda **_kwargs: [])
        def interrupted_support_start(*args):
            if args[:2] == ('enable', '--now'):
                raise RuntimeError('interrupted during Support activation')
        backend._systemctl = interrupted_support_start
        with pytest.raises(RuntimeError):
            asyncio.run(n.notify(store))
        assert 'core-ready' in store.data and 'runtime-ready' not in store.data
        assert 'support-pending' not in store.data
        backend._systemctl = lambda *args: units.append(args)
        asyncio.run(n.notify(store))
        assert journal.state()['operation']['bootstrap'] == 'complete'
        assert journal.state()['operation']['id'] == operation['id']
        assert journal.state()['sequence'] == 2
        assert 'core-ready' not in store.data
        assert store.data['runtime-ready']['operation_id'] == operation['id']
    else:
        if case == 'recovered_identity':
            with pytest.raises(SupportError):
                asyncio.run(n.notify(store))
            assert journal.state()['acknowledged'] == 2
        assert 'core-ready' not in store.data
        assert ('start', 'endpoint-agent.service') not in units

def test_same_durable_delivery_recovers_partial_identity_without_retained_admission(monkeypatch, tmp_path):
    from pc_agent.platform.linux import installation_notification as n

    device = str(uuid4())
    delivery = {'schema_version':'agent_enrollment_delivery_v1', 'device_id':device,
        'device_token':'r'*43, 'enrollment_receipt':'e'*43, 'policy_id':'fixture',
        'policy':{}, 'issued_at':'2026-11-07T00:00:00Z'}
    pending = {'delivery':delivery, 'request':{'hardware_fingerprint':'fixture'}}
    activations = []
    posts = []

    class Private:
        def __init__(self, directory): pass
        @contextmanager
        def locked(self): yield self
        def read(self): return pending
        def write(self, value): assert value is pending

    class Transport:
        async def post(self, path, payload, bearer):
            posts.append(path)
            assert bearer == 'r'*43

    def identity():
        if not activations:
            raise InstallationPending('partial_canonical_identity_requires_recovery')
        return device, 'r'*43

    monkeypatch.setattr(n, 'LinuxPrivateEnrollmentStore', Private)
    monkeypatch.setattr(n, '_activate_delivery', lambda value: activations.append(value.device_id))
    monkeypatch.setattr(n, 'canonical_identity', identity)
    store = SimpleNamespace(paths=SimpleNamespace(private=tmp_path))
    assert asyncio.run(n.ensure_identity(store, {'action':'install'}, Transport(), {})) == (device, 'r'*43, False)
    assert len(activations) == 1 and posts == ['/agent/v1/enroll/ack']
    assert pending['canonical_acknowledged']
