from contextlib import contextmanager
from uuid import uuid4

import pytest

from pc_agent.tests.test_linux_installation_lifecycle import MemoryStore, source


class Backend:
    def __init__(self, code=0, exact=True):
        self.calls, self.code, self.exact = [], code, exact
    def prepare(self, action, source):
        self.calls.append('prepare')
    def preflight(self, action, source):
        pass
    def recover_preparation(self):
        self.calls.append('restore')
    def execute(self, action, inputs):
        self.calls.append('rpm')
        if self.code is None:
            raise TimeoutError()
        return self.code
    def matches(self, action, source):
        return self.exact
    def cleanup(self, action):
        self.calls.append('cleanup')
        return {'support': 'complete', 'browser': 'complete'}
    def arm_retry(self):
        self.calls.append('retry')


def test_coordinator_unknown_native_result_retains_authority_and_never_replays():
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    journal, backend = LifecycleJournal(MemoryStore()), Backend(code=None)
    coordinator = NativeCoordinator(journal, backend)
    with pytest.raises(InstallationPending):
        coordinator.operate('upgrade', source(), [], device_id=str(uuid4()))
    with pytest.raises(InstallationPending):
        coordinator.reconcile(device_id=str(uuid4()))
    assert backend.calls == ['prepare', 'rpm']
    assert journal.pending_events() == []


def test_coordinator_native_failure_and_final_state_mismatch_do_not_cleanup_or_notify():
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    for code, exact in ((1, True), (0, False)):
        journal, backend = LifecycleJournal(MemoryStore()), Backend(code, exact)
        with pytest.raises(InstallationPending):
            NativeCoordinator(journal, backend).operate('remove', source(), [], device_id=str(uuid4()))
        assert backend.calls == ['prepare', 'rpm']
        assert journal.pending_events() == []


def test_offline_fresh_install_keeps_known_zero_and_arms_only_installed_retry():
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal
    journal, backend = LifecycleJournal(MemoryStore()), Backend()
    outcome = NativeCoordinator(journal, backend).operate('install', source(), [], device_id=None)
    assert outcome == 'enrollment_pending'
    assert journal.state()['operation']['exit_code'] == 0
    assert journal.pending_events() == []
    assert 'retry' in backend.calls
    assert 'cleanup' not in backend.calls


def test_native_package_absence_requires_exact_successful_query_semantics():
    from pc_agent.platform.linux.installation_coordinator import native_state_matches
    absent = 'package endpoint-agent is not installed\npackage endpoint-agent-user-sensor is not installed\n'
    assert native_state_matches('remove', source(), 2, '', absent)
    assert not native_state_matches('remove', source(), 2, '')
    assert not native_state_matches('remove', source(), 1, 'error: rpmdb unavailable\n')
    assert not native_state_matches('remove', source(), 0, '')
    installed = 'endpoint-agent-3.2.178-alt6.x86_64\npackage endpoint-agent-user-sensor is not installed\n'
    assert native_state_matches('install', source(), 1, installed)
    assert not native_state_matches('install', source(), 1, installed + installed)


def test_preflight_refusal_keeps_receipt_without_reserving_unknown_native_owner():
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    journal, backend = LifecycleJournal(MemoryStore()), Backend()
    coordinator = NativeCoordinator(journal, backend)
    def refuse(*_): raise InstallationPending('core_update_ownership_pending')
    backend.preflight = refuse
    with pytest.raises(InstallationPending):
        coordinator.operate('upgrade', source(), [], device_id=str(uuid4()))
    assert journal.state()['operation'] is None
    assert any(name.startswith('refused-') for name in journal.store.data)
    backend.preflight = lambda *_: None
    coordinator.operate('upgrade', source(), [], device_id=str(uuid4()))
    assert backend.calls == ['prepare', 'rpm', 'retry']


def test_preparation_interruption_recovers_owned_state_without_rpm_and_preserves_receipt():
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal
    journal, backend = LifecycleJournal(MemoryStore()), Backend()
    coordinator = NativeCoordinator(journal, backend)
    def interrupted(*_): raise KeyboardInterrupt()
    backend.prepare = interrupted
    with pytest.raises(KeyboardInterrupt):
        coordinator.operate('upgrade', source(), [], device_id=str(uuid4()))
    operation_id = journal.state()['operation']['id']
    assert coordinator.reconcile(device_id=None) == 'preparation_recovered'
    assert backend.calls == ['restore']
    assert journal.store.data['receipt-' + operation_id + '.json']['phase'] == 'not_started_recovered'
    backend.prepare = lambda *_: None
    coordinator.operate('upgrade', source(), [], device_id=str(uuid4()))
    assert backend.calls.count('rpm') == 1


def test_invocation_boundary_is_unknown_even_if_no_exit_was_recorded():
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    journal, backend = LifecycleJournal(MemoryStore()), Backend()
    journal.begin('upgrade', source())
    journal.invocation_started()
    with pytest.raises(InstallationPending):
        NativeCoordinator(journal, backend).reconcile(device_id=None)
    assert backend.calls == []
