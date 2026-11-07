from contextlib import contextmanager
import copy
import json
from uuid import uuid4

import pytest


class MemoryStore:
    def __init__(self):
        self.data = {}
    def json(self, name, missing=False):
        return copy.deepcopy(self.data.get(name))
    def write(self, name, raw):
        self.data[name] = json.loads(raw)


def source():
    return {'version': '3.2.178', 'source_revision': 'a'*40,
        'core_nevra': 'endpoint-agent-3.2.178-alt6.x86_64', 'core_rpm_sha256': 'b'*64,
        'user_sensor_nevra': None, 'user_sensor_rpm_sha256': None}


def test_unknown_native_operation_cannot_be_replayed_or_settled_from_presence():
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    journal = LifecycleJournal(MemoryStore())
    journal.begin('install', source())
    with pytest.raises(InstallationPending):
        journal.begin('install', source())
    with pytest.raises(InstallationPending):
        journal.settle(exact_native_state=True, device_id=str(uuid4()))
    assert journal.pending_events() == []


def test_native_zero_and_exact_final_state_are_both_required():
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    for code, exact in ((1, True), (None, True), (0, False), (True, True)):
        journal = LifecycleJournal(MemoryStore())
        journal.begin('install', source())
        if code is not None:
            with pytest.raises(InstallationPending) if type(code) is not int else __import__('contextlib').nullcontext():
                journal.native_result(code)
        with pytest.raises(InstallationPending):
            journal.settle(exact_native_state=exact, device_id=str(uuid4()))
        assert journal.pending_events() == []


def test_offline_removed_event_precedes_reinstall_without_tokens_and_no_duplicates():
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal
    from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationEventV1
    store, device = MemoryStore(), str(uuid4())
    journal = LifecycleJournal(store)
    for action in ('install', 'remove', 'install'):
        journal.begin(action, source())
        journal.native_result(0)
        event = journal.settle(exact_native_state=True, device_id=device)
        assert journal.settle(exact_native_state=True, device_id=device) == event
    events = [LinuxInstallationEventV1.model_validate(x) for x in journal.pending_events()]
    assert [x.action for x in events] == ['installed', 'removed', 'installed']
    assert [x.sequence for x in events] == [1, 2, 3]
    assert events[2].previous_event_id == events[1].event_id
    assert events[0].generation_id != events[2].generation_id
    assert all('token' not in json.dumps(x) and 'bearer' not in json.dumps(x) for x in store.data.values())
    journal.acknowledge(events[0].model_dump(mode='json'))
    assert [x['sequence'] for x in journal.pending_events()] == [2, 3]


def test_scriptlet_intent_cannot_create_native_success():
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    journal = LifecycleJournal(MemoryStore())
    journal.scriptlet_intent('remove')
    with pytest.raises(InstallationPending):
        journal.begin('install', source())
    with pytest.raises(InstallationPending):
        journal.settle(exact_native_state=True, device_id=str(uuid4()))


def test_completed_bootstrap_is_terminal_until_new_native_operation():
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    journal = LifecycleJournal(MemoryStore())
    journal.begin('install', source())
    journal.native_result(0)
    journal.settle(exact_native_state=True, device_id=str(uuid4()))
    assert journal.bootstrap_pending()
    journal.complete_bootstrap()
    assert not journal.bootstrap_pending()
    # Runtime token revocation cannot turn completed native bootstrap into retry.
    with pytest.raises(InstallationPending):
        journal.request_bootstrap()
