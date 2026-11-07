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
