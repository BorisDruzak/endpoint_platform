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


class PreparationStore(MemoryStore):
    def read(self, name, missing=False):
        import json
        value = self.data.get(name)
        return None if value is None else json.dumps(value).encode()
    def save(self, name, value):
        import json
        self.write(name, json.dumps(value).encode())


@pytest.mark.parametrize('state', ['activating','deactivating','reloading'])
@pytest.mark.parametrize('foreign', [False, True])
def test_transitional_updater_never_crosses_native_invocation_boundary(monkeypatch, state, foreign):
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator, RPMBackend
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    from pc_agent.platform.linux import installation_user_sessions as sensors
    monkeypatch.setattr(sensors,'session_ids',lambda:[])
    store = PreparationStore()
    journal, backend = LifecycleJournal(store), RPMBackend(store)
    monkeypatch.setattr(backend,'preflight',lambda *_:None)
    unit = 'endpoint-agent-update.service'
    def status(name):
        return {'LoadState':'loaded','FragmentPath':('/foreign/' if foreign else '/usr/lib/systemd/system/')+unit,
            'DropInPaths':'','UnitFileState':'static','ActiveState':state,'Job':'91/start','MainPID':'123'} if name == unit else {'LoadState':'not-found'}
    monkeypatch.setattr(backend,'_unit_state',status)
    commands = []
    monkeypatch.setattr(backend,'_systemctl',lambda *args:commands.append(args))
    monkeypatch.setattr(backend,'execute',lambda *_:commands.append(('rpm',)))
    coordinator = NativeCoordinator(journal,backend)
    with pytest.raises(InstallationPending): coordinator.operate('upgrade',source(),[],device_id=None)
    assert journal.state()['operation']['phase'] == 'preparing'
    assert commands == []
    with pytest.raises(InstallationPending): coordinator.operate('upgrade',source(),[],device_id=None)
    assert not any(cmd[0] in ('rpm','stop') for cmd in commands)


@pytest.mark.parametrize('stop_phase', ['unchanged','uncertain','confirmed','failed_restore'])
def test_real_handoff_stop_interruption_cannot_silently_complete_preparation(monkeypatch, stop_phase):
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator, RPMBackend
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    from pc_agent.platform.linux import installation_user_sessions as sensors
    store = PreparationStore()
    journal, backend = LifecycleJournal(store), RPMBackend(store)
    monkeypatch.setattr(backend,'preflight',lambda *_:None)
    monkeypatch.setattr(backend,'_unit_state',lambda _: {'LoadState':'not-found'})
    monkeypatch.setattr(backend,'_capture_native_selector',lambda *_:None)
    context = {'sid':'6','uid':1000,'prefix':['user-manager'],'session':{'Leader':'123'},'boot':'fixture'}
    props = {'LoadState':'loaded','FragmentPath':'/usr/lib/systemd/user/endpoint-user-sensor.service',
        'DropInPaths':'','UnitFileState':'disabled','ActiveState':'active','InactiveEnterTimestampMonotonic':'10'}
    monkeypatch.setattr(sensors,'session_ids',lambda:['6'])
    monkeypatch.setattr(sensors,'session_context',lambda _:context.copy())
    monkeypatch.setattr(sensors,'unit_properties',lambda _:props.copy())
    commands = []
    def command(argv, **kwargs):
        commands.append(argv)
        if 'stop' in argv:
            if stop_phase != 'unchanged': props.update(ActiveState='inactive',InactiveEnterTimestampMonotonic='20')
            if stop_phase in ('unchanged','uncertain'): raise KeyboardInterrupt()
        if 'restart' in argv and stop_phase != 'failed_restore': props['ActiveState'] = 'active'
        return b''
    write = store.write
    def interrupt_after_receipt(name, raw):
        write(name, raw)
        if name == 'sensor-handoff.json' and store.data[name]['1000']['phase'] == 'stopped':
            raise KeyboardInterrupt()
    if stop_phase in ('confirmed','failed_restore'):
        store.write = interrupt_after_receipt
    monkeypatch.setattr(sensors,'run',command)
    monkeypatch.setattr(backend,'execute',lambda *_:commands.append(['rpm']))
    coordinator = NativeCoordinator(journal,backend)
    native = source() | {'user_sensor_nevra':'endpoint-agent-user-sensor-3.2.178-alt6.x86_64','user_sensor_rpm_sha256':'c'*64}
    with pytest.raises(KeyboardInterrupt): coordinator.operate('remove',native,[],device_id=None)
    assert store.data['sensor-handoff.json']['1000']['phase'] == ('stop_pending' if stop_phase in ('unchanged','uncertain') else 'stopped')
    if stop_phase in ('uncertain','failed_restore'):
        with pytest.raises(InstallationPending): coordinator.reconcile(device_id=None)
        assert journal.state()['operation']['phase'] == 'preparing'
        with pytest.raises(InstallationPending): coordinator.operate('upgrade',source(),[],device_id=None)
        assert props['ActiveState'] == 'inactive'
    else:
        assert coordinator.reconcile(device_id=None) == 'preparation_recovered'
        assert props['ActiveState'] == 'active'
    assert not any('rpm' in cmd for cmd in commands)
    if stop_phase in ('unchanged','uncertain'):
        assert not any('restart' in cmd for cmd in commands)


@pytest.mark.parametrize('pending', [{'Job':'19/start'},{'MainPID':'321'},{'ControlPID':'654'}])
def test_inactive_label_with_native_job_or_process_is_not_quiescent(pending):
    from pc_agent.platform.linux.installation_coordinator import RPMBackend
    assert not RPMBackend._quiescent({'ActiveState':'inactive'} | pending)


def test_native_quiescence_is_rechecked_after_all_preparation(monkeypatch):
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator, RPMBackend
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    store = PreparationStore()
    journal, backend = LifecycleJournal(store), RPMBackend(store)
    monkeypatch.setattr(backend,'preflight',lambda *_:None)
    reads = []
    def status(unit):
        if unit != 'endpoint-agent.service': return {'LoadState':'not-found'}
        reads.append(unit)
        return {'LoadState':'loaded','FragmentPath':'/usr/lib/systemd/system/'+unit,
            'DropInPaths':'','ActiveState':'inactive' if len(reads) == 1 else 'activating'}
    monkeypatch.setattr(backend,'_unit_state',status)
    executed = []
    monkeypatch.setattr(backend,'execute',lambda *_:executed.append(True))
    with pytest.raises(InstallationPending): NativeCoordinator(journal,backend).operate('upgrade',source(),[],device_id=None)
    assert not executed and journal.state()['operation']['phase'] == 'preparing'
