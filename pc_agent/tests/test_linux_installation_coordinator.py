from contextlib import contextmanager, nullcontext
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


def test_failed_payload_barrier_leaves_known_upgrade_before_event_and_requires_reboot():
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    journal, backend = LifecycleJournal(MemoryStore()), Backend()
    device = str(uuid4())

    class Durability:
        boot = str(uuid4())
        shutdown = None
        failure = True
        identity = {'device-credential': 'before'}
        flushes = 0

        def boot_id(self):
            return self.boot

        def assert_owner(self, operation):
            pass

        def identity_proof(self):
            return self.identity.copy()

        def flush(self, action, release):
            self.flushes += 1
            if self.failure:
                raise OSError('device writeback failed')

        def orderly_reboot_proved(self, operation, previous_boot):
            return self.shutdown == (operation['id'], operation['durability']['attempt'])

    durability = Durability()
    coordinator = NativeCoordinator(journal, backend, durability=durability)
    with pytest.raises(InstallationPending):
        coordinator.operate('upgrade', source(), [], device_id=device)
    operation = journal.state()['operation']
    assert operation['exit_code'] == 0 and not operation['settled']
    assert journal.state()['sequence'] == journal.state()['acknowledged'] == 0
    assert journal.pending_events() == []
    assert backend.calls.count('rpm') == durability.flushes == 1
    with pytest.raises(InstallationPending, match='native_durability_pending'):
        journal.settle(exact_native_state=True, device_id=device)

    durability.failure = False
    with pytest.raises(InstallationPending):
        coordinator.reconcile(device_id=device)
    durability.boot = str(uuid4())
    with pytest.raises(InstallationPending):
        coordinator.reconcile(device_id=device)
    assert durability.flushes == 1

    durability.shutdown = (operation['id'], operation['durability']['attempt'])
    durability.identity['device-credential'] = 'replaced'
    with pytest.raises(InstallationPending):
        coordinator.reconcile(device_id=device)
    assert journal.pending_events() == []

    durability.identity['device-credential'] = 'before'
    durability.failure = True
    with pytest.raises(InstallationPending):
        coordinator.reconcile(device_id=device)
    failed_again = journal.state()['operation']
    assert failed_again['id'] == operation['id'] and failed_again['durability']['attempt'] != durability.shutdown[1]
    assert journal.pending_events() == []
    durability.boot = str(uuid4())
    durability.failure = False
    with pytest.raises(InstallationPending):
        coordinator.reconcile(device_id=device)
    durability.shutdown = (failed_again['id'], failed_again['durability']['attempt'])
    assert coordinator.reconcile(device_id=device) == 'notification_pending'
    event, = journal.pending_events()
    assert event['event_id'] == operation['id'] and event['device_id'] == device
    assert backend.calls.count('rpm') == 1 and durability.flushes == 3


def test_native_durability_reboot_marker_is_bound_to_exact_attempt_and_boot(monkeypatch):
    from pc_agent.platform.linux.installation_durability import NativeDurability
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal
    journal = LifecycleJournal(MemoryStore())
    first_boot, next_boot = str(uuid4()), str(uuid4())
    operation = journal.begin('upgrade', source(), durability_identity={})
    journal.invocation_started()
    journal.native_result(0)
    attempt = {'boot': first_boot, 'id': str(uuid4())}
    journal.update_durability(operation['id'], attempt=attempt)
    operation = journal.state()['operation']
    native = NativeDurability(journal.store)
    monkeypatch.setattr(native, 'boot_id', lambda: first_boot)
    native.mark_orderly_reboot(operation)
    assert not native.orderly_reboot_proved(operation, first_boot)
    monkeypatch.setattr(native, 'boot_id', lambda: next_boot)
    assert native.orderly_reboot_proved(operation, first_boot)
    journal.update_durability(operation['id'], attempt={'boot': next_boot, 'id': str(uuid4())})
    assert not native.orderly_reboot_proved(journal.state()['operation'], next_boot)


def test_competing_executor_cannot_replace_original_pending_owner():
    from pc_agent.platform.linux.installation_coordinator import register_retained_executor
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    journal = LifecycleJournal(MemoryStore())
    owner = {'sha256': 'a' * 64}
    register_retained_executor(journal.store, owner)
    journal.begin('upgrade', source(), execution=owner, durability_identity={})
    with pytest.raises(InstallationPending, match='native_executor_pending_owner'):
        register_retained_executor(journal.store, {'sha256': 'b' * 64})
    assert journal.store.json('executor.json') == owner
    register_retained_executor(journal.store, owner)


def test_committed_writeback_does_not_authorize_replaced_identity_before_settlement(monkeypatch):
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator
    from pc_agent.platform.linux.installation_durability import NativeDurability
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    journal = LifecycleJournal(MemoryStore())
    owner = {'sha256': 'a' * 64}
    journal.store.data['executor.json'] = owner
    op = journal.begin('install', source(), execution=owner, durability_identity={'device-credential': 'old'})
    journal.invocation_started()
    journal.native_result(0)
    attempt = {'boot': str(uuid4()), 'id': str(uuid4())}
    journal.update_durability(op['id'], attempt=attempt)
    journal.update_durability(op['id'], attempt=attempt, complete=True)
    durability = NativeDurability(journal.store)
    monkeypatch.setattr(durability, 'identity_proof', lambda **_: {'device-credential': 'other'})
    with pytest.raises(InstallationPending, match='canonical_identity_changed'):
        NativeCoordinator(journal, Backend(), durability=durability).reconcile(device_id=str(uuid4()))
    assert journal.pending_events() == []


@pytest.mark.parametrize('partial', [True, False])
def test_completed_writeback_accepts_only_exact_fresh_delivery(monkeypatch, tmp_path, partial):
    import sys
    from types import SimpleNamespace
    from pc_agent.platform.linux import installation_durability as native
    from pc_agent.platform.linux import installation_notification as notification
    from pc_agent.platform.linux.installation_lifecycle import InstallationPending
    device = str(uuid4())
    delivery = {'schema_version': 'agent_enrollment_delivery_v1', 'device_id': device,
        'device_token': 'r' * 43, 'enrollment_receipt': 'e' * 43, 'policy_id': 'fixture',
        'policy': {}, 'issued_at': '2026-11-07T00:00:00Z'}
    operation = {'source': source(), 'identity_recovery_required': True}
    pending = {'delivery': delivery, 'request': {'native': operation['source']}}
    store = SimpleNamespace(paths=SimpleNamespace(private=tmp_path))
    proof = native.NativeDurability(store)
    files = {'device-credential': b'r' * 43}
    if not partial:
        files['enrollment-identity.json'] = notification.serialize_enrollment_identity(device)
    monkeypatch.setitem(sys.modules, 'pwd', SimpleNamespace(getpwnam=lambda _:
                         SimpleNamespace(pw_uid=123, pw_gid=123)))
    monkeypatch.setattr(native, '_existing', lambda path: path.name in files)
    monkeypatch.setattr(notification, 'read_secret', lambda path, **kwargs: files[path.name])
    monkeypatch.setattr(notification, 'LinuxPrivateEnrollmentStore', lambda root:
                        SimpleNamespace(locked=nullcontext, read=lambda: pending))
    assert proof.completed_identity_matches(operation, {})
    files['device-credential'] = b'x' * 43
    with pytest.raises(InstallationPending, match='canonical_identity_changed'):
        proof.completed_identity_matches(operation, {})


def test_notifier_cannot_enroll_or_drain_while_original_durability_attempt_is_held(monkeypatch):
    import asyncio
    from pc_agent.platform.linux import installation_coordinator as coordinator
    from pc_agent.platform.linux import installation_notification as notification
    from pc_agent.platform.linux.installation_durability import NativeDurability
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending
    journal = LifecycleJournal(MemoryStore())
    boot = str(uuid4())
    journal.store.locked = nullcontext
    execution = {'source_revision': source()['source_revision']}
    journal.store.data['executor.json'] = execution
    operation = journal.begin('install', source(), execution=execution, durability_identity={})
    journal.invocation_started()
    journal.native_result(0)
    journal.update_durability(operation['id'], attempt={'boot': boot, 'id': str(uuid4())})
    monkeypatch.setattr(NativeDurability, 'boot_id', staticmethod(lambda: boot))
    monkeypatch.setattr(coordinator, 'RPMBackend', lambda store: Backend())

    def must_not_read_or_send(*args, **kwargs):
        pytest.fail('notification touched configuration or transport before durability')

    monkeypatch.setattr(notification, 'read_secret', must_not_read_or_send)
    monkeypatch.setattr(notification, 'drain_events', must_not_read_or_send)
    with pytest.raises(InstallationPending, match='native_durability_reboot_required'):
        asyncio.run(notification.notify(journal.store))
    assert journal.pending_events() == []


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
            'DropInPaths':'','NeedDaemonReload':'no','UnitFileState':'static','ActiveState':state,'Job':'91/start','MainPID':'123'} if name == unit else {'LoadState':'not-found','NeedDaemonReload':'no'}
    monkeypatch.setattr(backend,'_unit_state',status)
    monkeypatch.setattr(backend,'_configuration_file',lambda _: {'identity':[1,2],'bytes':'[Service]\n'})
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
    monkeypatch.setattr(backend,'_unit_state',lambda _: {'LoadState':'not-found','NeedDaemonReload':'no'})
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
        if unit != 'endpoint-agent.service': return {'LoadState':'not-found','NeedDaemonReload':'no'}
        reads.append(unit)
        return {'LoadState':'loaded','FragmentPath':'/usr/lib/systemd/system/'+unit,
            'DropInPaths':'','NeedDaemonReload':'no','ActiveState':'inactive' if len(reads) == 1 else 'activating'}
    monkeypatch.setattr(backend,'_unit_state',status)
    monkeypatch.setattr(backend,'_configuration_file',lambda _: {'identity':[1,2],'bytes':'[Service]\n'})
    executed = []
    monkeypatch.setattr(backend,'execute',lambda *_:executed.append(True))
    with pytest.raises(InstallationPending): NativeCoordinator(journal,backend).operate('upgrade',source(),[],device_id=None)
    assert not executed and journal.state()['operation']['phase'] == 'preparing'

@pytest.mark.parametrize('condition', ['exact', 'changed_hash', 'missing_sensor', 'changed_identity'])
def test_local_repair_requires_the_exact_completed_pair_and_never_enqueues(condition):
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator
    from pc_agent.platform.linux.installation_lifecycle import InstallationPending, LifecycleJournal
    journal, backend = LifecycleJournal(MemoryStore()), Backend()
    device = str(uuid4())
    pair = source() | {'user_sensor_nevra': 'endpoint-agent-user-sensor-3.2.178-alt6.x86_64',
                       'user_sensor_rpm_sha256': 'c' * 64}
    journal.begin('install', pair)
    journal.native_result(0)
    journal.settle(exact_native_state=True, device_id=device)
    journal.complete_bootstrap()
    baseline = journal.state()
    coordinator = NativeCoordinator(journal, backend)
    backend.check_repair_inputs = backend.check_repair_selector = lambda _: None
    backend.restore_repair = lambda: backend.calls.append('restore_repair')
    requested = pair.copy()
    if condition == 'changed_hash':
        requested['core_rpm_sha256'] = 'd' * 64
    if condition == 'missing_sensor':
        requested.update(user_sensor_nevra=None, user_sensor_rpm_sha256=None)
    if condition == 'changed_identity':
        device = str(uuid4())
    if condition != 'exact':
        with pytest.raises(InstallationPending, match='repair_requires_exact_installed_pair'):
            coordinator.operate('repair', requested, ['core', 'sensor'], device_id=device)
        assert backend.calls == []
        return
    assert coordinator.operate('repair', pair, ['core', 'sensor'], device_id=device) == 'repair_complete'
    final = journal.state()
    assert backend.calls == ['prepare', 'rpm', 'restore_repair']
    for key in ('sequence', 'acknowledged', 'previous_event_id', 'generation_id', 'device_id'):
        assert final[key] == baseline[key]
    assert final['operation']['settled'] and final['operation']['bootstrap'] == 'complete'

def test_repair_resumes_known_zero_without_spawning_rpm_again(monkeypatch):
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator
    from pc_agent.platform.linux.installation_lifecycle import InstallationPending, LifecycleJournal
    journal, backend = LifecycleJournal(MemoryStore()), Backend()
    device = str(uuid4())
    pair = source() | {'user_sensor_nevra': 'endpoint-agent-user-sensor-3.2.178-alt6.x86_64',
                       'user_sensor_rpm_sha256': 'c' * 64}
    journal.begin('install', pair)
    journal.native_result(0)
    journal.settle(exact_native_state=True, device_id=device)
    journal.complete_bootstrap()
    backend.check_repair_inputs = backend.check_repair_selector = lambda _: None
    backend.restore_repair = lambda: (_ for _ in ()).throw(InstallationPending('retry_fixture'))
    coordinator = NativeCoordinator(journal, backend)
    with pytest.raises(InstallationPending, match='retry_fixture'):
        coordinator.operate('repair', pair, ['core', 'sensor'], device_id=device)
    assert journal.state()['operation']['exit_code'] == 0
    with pytest.raises(InstallationPending, match='canonical_identity_changed'):
        coordinator.reconcile(device_id=str(uuid4()))
    backend.restore_repair = lambda: backend.calls.append('restore_repair')
    assert coordinator.reconcile(device_id=device) == 'repair_complete'
    assert backend.calls == ['prepare', 'rpm', 'restore_repair']
    assert journal.state()['sequence'] == 1


def test_repair_uses_only_replacepkgs_and_keeps_scriptlets(monkeypatch):
    from types import SimpleNamespace
    from pc_agent.platform.linux import installation_coordinator as coordinator
    backend = coordinator.RPMBackend(MemoryStore())
    monkeypatch.setattr(backend, '_assert_prepared', lambda: {})
    calls = []
    monkeypatch.setattr(coordinator.subprocess, 'run',
                        lambda args, **kwargs: calls.append(args) or SimpleNamespace(returncode=0))
    assert backend.execute('repair', ['core', 'sensor']) == 0
    assert backend.execute('upgrade', ['core', 'sensor']) == 0
    assert calls == [
        ['/usr/bin/rpm', '-U', '--replacepkgs', 'core', 'sensor'],
        ['/usr/bin/rpm', '-U', '--oldpackage', 'core', 'sensor'],
    ]


def test_repair_post_scriptlets_keep_normal_checks_and_gate_enablement():
    from pathlib import Path
    spec = Path('packaging/alt/endpoint-agent.spec').read_text()
    core = spec.split('\n%post\n', 1)[1].split('\n%preun\n', 1)[0]
    sensor = spec.split('\n%post user-sensor\n', 1)[1].split('\n%preun user-sensor\n', 1)[0]
    for hook in (core, sensor):
        assert 'scriptlet --intent repair-check' in hook
        assert '*) exit 1 ;;' in hook
        assert ' --prepare-directories || exit 1' in hook
        assert 'systemctl daemon-reload || exit 1' in hook
        assert 'systemctl enable' in hook
    assert 'scriptlet --intent repair-core-done || exit 1' in core
    assert 'scriptlet --intent repair-sensor-done || exit 1' in sensor

@pytest.mark.parametrize('installed', ['partial', 'exact'])
def test_repair_queries_both_installed_nevras_before_file_repair(monkeypatch, installed):
    from types import SimpleNamespace
    from pc_agent.platform.linux import installation_coordinator as coordinator
    native = source() | {'user_sensor_nevra': 'endpoint-agent-user-sensor-3.2.178-alt6.x86_64',
                         'user_sensor_rpm_sha256': 'c' * 64}
    output = [native['core_nevra']]
    if installed == 'exact':
        output.append(native['user_sensor_nevra'])
    else:
        output.append('package endpoint-agent-user-sensor is not installed')
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        assert args[1] == '-q'
        return SimpleNamespace(returncode=int(installed != 'exact'),
                               stdout=('\n'.join(output) + '\n').encode(), stderr=b'')

    monkeypatch.setattr(coordinator.subprocess, 'run', run)
    backend = coordinator.RPMBackend(MemoryStore())
    assert backend.installed_packages_match('repair', native, verify_files=False) == (installed == 'exact')
    assert calls[0][-2:] == ['endpoint-agent', 'endpoint-agent-user-sensor']

def test_machine_unit_proof_keeps_legacy_shape_outside_repair(monkeypatch):
    from pc_agent.platform.linux.installation_coordinator import RPMBackend
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal
    store = MemoryStore()
    journal = LifecycleJournal(store)
    backend = RPMBackend(store)

    def show(_verb, _unit, query):
        common = b'ActiveState=active\nLoadState=loaded\n'
        return common + b'SubState=running\n' if 'SubState' in query else common

    monkeypatch.setattr(backend, '_systemctl', show)
    journal.begin('upgrade', source())
    legacy = backend._unit_state('endpoint-agent.service')
    assert 'SubState' not in legacy
    journal.preparation_recovered()
    journal.begin('repair', source())
    assert backend._unit_state('endpoint-agent.service') == {**legacy, 'SubState': 'running'}


@pytest.mark.parametrize('core_marker_written', [False, True])
def test_pre_native_abort_preserves_owned_partial_ready_files(monkeypatch, core_marker_written):
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator, RPMBackend
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal
    from pc_agent.platform.linux import installation_user_sessions as sensors

    store = PreparationStore()
    journal, backend = LifecycleJournal(store), RPMBackend(store)
    prior = journal.begin('install', source())
    journal.native_result(0)
    journal.settle(exact_native_state=True, device_id=str(uuid4()))
    proof = {'operation_id': prior['id'], 'source_revision': prior['source']['source_revision']}
    store.save('support-pending', proof)
    if core_marker_written:
        store.save('core-ready', proof)
    monkeypatch.setattr(backend, 'preflight', lambda *_: None)
    monkeypatch.setattr(backend, '_unit_state', lambda _: {'LoadState':'not-found','NeedDaemonReload':'no'})
    monkeypatch.setattr(sensors, 'session_ids', lambda: [])
    def interrupt():
        raise KeyboardInterrupt()
    monkeypatch.setattr(journal, 'invocation_started', interrupt)
    coordinator = NativeCoordinator(journal, backend)
    with pytest.raises(KeyboardInterrupt):
        coordinator.operate('upgrade', source(), [], device_id=None)
    assert store.json('support-pending') == proof
    assert store.json('core-ready', missing=True) == (proof if core_marker_written else None)
    assert coordinator.reconcile(device_id=None) == 'preparation_recovered'
    assert journal.state()['operation']['id'] == prior['id']
    assert store.json('support-pending') == proof
    assert store.json('core-ready', missing=True) == (proof if core_marker_written else None)
    assert store.read('runtime-ready', missing=True) is None

@pytest.mark.parametrize('fault', [
    None, 'same_boot', 'unknown_boot', 'missing_exit', 'running_core',
    'support_was_disabled', 'support_job', 'missing_pid', 'new_unit_activity',
    'missing_post', 'changed_private', 'changed_fragment', 'second_reconcile',
    'changed_sensor', 'support_restarted_again', 'unobserved_start', 'wrong_start_shape', 'late_private', 'late_sensor',
])
def test_cold_boot_repair_keeps_owned_support_and_never_repeats_rpm(monkeypatch, fault):
    from pathlib import Path

    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator, REPAIR_UNITS, RPMBackend
    from pc_agent.platform.linux.installation_lifecycle import InstallationPending, LifecycleJournal

    store = PreparationStore()
    journal, backend = LifecycleJournal(store), RPMBackend(store)
    pair = dict(source(), user_sensor_nevra='endpoint-agent-user-sensor-3.2.178-alt6.x86_64', user_sensor_rpm_sha256='c'*64)
    operation = journal.begin('repair', pair)
    state = journal.state()
    old_boot = str(uuid4())
    next_boot = old_boot if fault == 'same_boot' else str(uuid4())
    state['device_id'] = device = str(uuid4())
    state['operation']['owner_boot_id'] = 'invalid' if fault == 'unknown_boot' else old_boot
    journal._save(state)
    journal.invocation_started()
    if fault != 'missing_exit':
        journal.native_result(0)
    real_read = Path.read_text

    def read_text(path, *args, **kwargs):
        if path.as_posix() == '/proc/sys/kernel/random/boot_id':
            return next_boot
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', read_text)
    core, support = 'endpoint-agent.service', 'endpoint-support-access.service'
    originals, live, stopped_units = {}, {}, []
    for unit in REPAIR_UNITS:
        active = unit in (core, support)
        original = dict(LoadState='loaded', FragmentPath='/usr/lib/systemd/system/' + unit,
                        UnitFileState='enabled' if active else 'disabled', ActiveState='active' if active else 'inactive',
                        SubState='running' if active else 'dead', MainPID='120' if active else '0', Job='0', ControlPID='0',
                        ActiveEnterTimestampMonotonic='100', InactiveEnterTimestampMonotonic='0')
        if unit == support and fault == 'support_was_disabled':
            original['UnitFileState'] = 'disabled'
        originals[unit] = original
        if active:
            after = dict(original, ActiveState='inactive', SubState='dead', MainPID='0', InactiveEnterTimestampMonotonic='200')
            stopped_units.append(dict(unit=unit, before=original, after=after, restored=False))
        else:
            after = original
        live[unit] = dict(after, ActiveEnterTimestampMonotonic='0', InactiveEnterTimestampMonotonic='0')
    live[support].update(ActiveState='active', SubState='running', MainPID='300', ActiveEnterTimestampMonotonic='50')
    if fault == 'support_job':
        live[support]['Job'] = '200/start'
    if fault == 'missing_pid':
        live[support]['MainPID'] = '0'
    if fault == 'running_core':
        live[core].update(ActiveState='active', SubState='running', MainPID='302')
    if fault == 'new_unit_activity':
        live['endpoint-agent-update-rearm.service']['ActiveState'] = 'activating'
    if fault == 'changed_fragment':
        live[support]['FragmentPath'] += '.other'
    prep_name = backend._preparation_name()
    store.save(prep_name, dict(ready='{}', configuration={}, units=stopped_units,
                               repair=dict(private={'config': ['original']}, original_units=originals, sensors={})))
    for part in ('core', 'sensor'):
        if not (part == 'sensor' and fault == 'missing_post'):
            store.save(f"repair-{operation['id']}-{part}.json", {'operation_id': operation['id'], 'component': part})
    starts = []

    def systemctl(action, unit):
        assert action == 'start' and unit == core
        if fault in ('second_reconcile', 'support_restarted_again', 'unobserved_start'):
            raise InstallationPending('interrupted_after_check')
        starts.append(unit)
        live[unit] = dict(originals[unit], MainPID='400', ActiveEnterTimestampMonotonic='500')
        if fault == 'wrong_start_shape':
            live[unit]['FragmentPath'] += '.replaced'

    monkeypatch.setattr(backend, '_unit_state', lambda unit: live[unit].copy())
    monkeypatch.setattr(backend, '_systemctl', systemctl)
    monkeypatch.setattr(backend, '_assert_configuration', lambda *args, **kw: None)
    def drifted(early, late):
        return fault == early or (fault == late and store.json('runtime-ready', missing=True) is not None)

    monkeypatch.setattr(backend, '_repair_private_inputs',
                        lambda: {'config': ['other' if drifted('changed_private', 'late_private') else 'original']})
    monkeypatch.setattr(backend, '_repair_sensor_units',
                        lambda: {'changed': True} if drifted('changed_sensor', 'late_sensor') else {})
    monkeypatch.setattr(backend, 'matches', lambda *_: True)
    monkeypatch.setattr(backend, 'check_repair_selector', lambda *_: None)
    original_support = live[support].copy()
    coordinator = NativeCoordinator(journal, backend)
    if fault is None:
        assert coordinator.reconcile(device_id=device) == 'repair_complete'
        assert journal.state()['operation']['id'] == operation['id']
        assert journal.state()['operation']['settled']
        assert starts == [core] and live[support] == original_support
    else:
        with pytest.raises(InstallationPending):
            coordinator.reconcile(device_id=device)
        assert starts == ([core] if fault == 'wrong_start_shape' else [])
        assert not journal.state()['operation']['settled']
        if fault in ('second_reconcile', 'support_restarted_again', 'unobserved_start'):
            if fault == 'second_reconcile':
                live[core]['InactiveEnterTimestampMonotonic'] = '999'
            elif fault == 'support_restarted_again':
                live[support].update(MainPID='301', ActiveEnterTimestampMonotonic='99')
            else:
                live[core].update(ActiveState='active', SubState='running', MainPID='600')
            monkeypatch.setattr(backend, '_systemctl', lambda *_: pytest.fail('unproven state change in the same boot'))
            with pytest.raises(InstallationPending):
                coordinator.reconcile(device_id=device)

@pytest.mark.parametrize(('unit', 'accepted'), [
    ('endpoint-agent-update.path', True), ('endpoint-agent-update-rearm.timer', True),
    ('endpoint-support-access.service', False),
])
def test_restored_systemd_nonprocess_units_have_no_main_pid(unit, accepted):
    from pc_agent.platform.linux.installation_coordinator import RPMBackend

    # Real systemctl show for a path/timer omits MainPID and ControlPID.
    original = {'FragmentPath': '/usr/lib/systemd/system/' + unit, 'ActiveState': 'active',
                'SubState': 'waiting', 'Job': '', 'ActiveEnterTimestampMonotonic': '110'}
    active = dict(original, ActiveEnterTimestampMonotonic='90')
    backend = RPMBackend(PreparationStore())
    assert backend._matches_restored_unit(original, active) is accepted
    assert not backend._matches_restored_unit(original, dict(active, MainPID='321'))
