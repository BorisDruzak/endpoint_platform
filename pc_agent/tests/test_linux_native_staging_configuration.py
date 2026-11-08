"""Native staging admission must preserve exact configuration before any mutation."""
import copy
import json

import pytest

from pc_agent.platform.linux.installation_coordinator import NativeCoordinator, RPMBackend, public_unit_state
from pc_agent.platform.linux.installation_lifecycle import InstallationPending, LifecycleJournal
from pc_agent.tests.test_linux_installation_coordinator import PreparationStore
from pc_agent.tests.test_linux_installation_lifecycle import source

CORE = 'endpoint-agent.service'
DROPIN = '/etc/systemd/system/endpoint-agent.service.d/staging.conf'
STAGING = (b'[Service]\n'
    b'Environment=ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT=staging\n'
    b'Environment=CANARY_ENVIRONMENT=staging\n'
    b'Environment=CANARY_APPROVED=true\n'
    b'Environment=ENDPOINT_AGENT_ORIGIN=https://endpoint-staging.sosnadmin.local\n')
ENVIRONMENT = {'ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT':'staging', 'CANARY_ENVIRONMENT':'staging',
    'CANARY_APPROVED':'true', 'ENDPOINT_AGENT_ORIGIN':'https://endpoint-staging.sosnadmin.local'}


class ConfigurationBackend(RPMBackend):
    """External systemd/filesystem boundary only; preparation and journal are real."""
    def __init__(self, store, *, active=True):
        super().__init__(store)
        self.properties = {CORE:{'LoadState':'loaded','FragmentPath':'/usr/lib/systemd/system/'+CORE,
            'DropInPaths':DROPIN,'NeedDaemonReload':'no','UnitFileState':'enabled',
            'Environment':' '.join(name+'='+value for name,value in ENVIRONMENT.items()),
            'ActiveState':'active' if active else 'inactive','Job':'','MainPID':'11' if active else '0',
            'ControlPID':'0','InactiveEnterTimestampMonotonic':'10','ActiveEnterTimestampMonotonic':'9'}}
        self.files = {DROPIN:{'identity':[1,2,0o100644,0,0,1,215,1,1], 'ancestors':[[1,1]],
            'bytes':STAGING.decode()}, '/usr/lib/systemd/system/'+CORE:{'identity':[1,3], 'bytes':'[Service]\n'}}
        self.commands = []
        self.hook = lambda *_: None
    def preflight(self, *_):
        pass
    def _unit_state(self, unit):
        self.hook('read', unit)
        return public_unit_state(copy.deepcopy(self.properties.get(unit, {'LoadState':'not-found', 'NeedDaemonReload':'no'})))
    def _configuration_file(self, path):
        return copy.deepcopy(self.files[path])
    def _systemctl(self, command, unit):
        self.hook(command, unit)
        self.commands.append((command, unit))
        self.properties[unit].update(ActiveState='inactive' if command == 'stop' else 'active', MainPID='0' if command == 'stop' else '12')
    def execute(self, *_):
        self.commands.append(('rpm',))
        return 0
    def matches(self, *_):
        return True
    def arm_retry(self):
        pass


def native(monkeypatch, *, active=True):
    for name, value in ENVIRONMENT.items():
        monkeypatch.setenv(name, value)
    store = PreparationStore()
    store.data['runtime-ready'] = {'ready':True}
    backend = ConfigurationBackend(store, active=active)
    journal = LifecycleJournal(store)
    return store, journal, backend, NativeCoordinator(journal, backend)


@pytest.mark.parametrize('active', [True, False])
def test_exact_approved_staging_configuration_crosses_native_boundary_unchanged(monkeypatch, active):
    store, journal, backend, coordinator = native(monkeypatch, active=active)
    original = copy.deepcopy(backend.files)
    assert coordinator.operate('upgrade', source(), [], device_id=None) == 'enrollment_pending'
    assert backend.files == original
    assert backend.commands == ([('stop', CORE)] if active else []) + [('rpm',)]
    assert journal.state()['operation']['environment'] == ENVIRONMENT
    proof = store.json(backend._preparation_name())
    assert set(proof['configuration']) == {'endpoint-agent.service','endpoint-agent-update.path',
        'endpoint-agent-update.service','endpoint-support-access.service','endpoint-agent-setup-retry.timer'}


@pytest.mark.parametrize('change', ['production','approval','origin','extra-path','extra-directive','reload'])
def test_unapproved_staging_configuration_preserves_ready_and_all_units(monkeypatch, change):
    store, journal, backend, coordinator = native(monkeypatch)
    if change == 'production': monkeypatch.setenv('ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT','production')
    if change == 'approval': monkeypatch.delenv('CANARY_APPROVED')
    if change == 'origin': monkeypatch.setenv('ENDPOINT_AGENT_ORIGIN','https://endpoint.sosnadmin.local')
    if change == 'extra-path': backend.properties[CORE]['DropInPaths'] += ' /etc/foreign.conf'
    if change == 'extra-directive': backend.files[DROPIN]['bytes'] += 'ExecStart=/bin/true\n'
    if change == 'reload': backend.properties[CORE]['NeedDaemonReload'] = 'yes'
    with pytest.raises((InstallationPending, ValueError)):
        coordinator.operate('upgrade', source(), [], device_id=None)
    assert backend.commands == []
    assert store.data['runtime-ready'] == {'ready':True}


@pytest.mark.parametrize('active', [True, False])
@pytest.mark.parametrize('moment', ['before-stop','final','recovery'])
def test_changed_configuration_never_invokes_or_restores_native_owner(monkeypatch, active, moment):
    store, journal, backend, coordinator = native(monkeypatch, active=active)
    if moment == 'recovery':
        journal.begin('upgrade', source())
        backend.prepare('upgrade', source())
        backend.files[DROPIN]['identity'][1] += 1  # Same bytes, replaced inode.
        prior = list(backend.commands)
        with pytest.raises(InstallationPending): coordinator.reconcile(device_id=None)
        assert backend.commands == prior
        assert 'runtime-ready' not in store.data
        assert journal.state()['operation']['phase'] == 'preparing'
        return
    reads = []
    def mutate(event, unit):
        if event == 'read' and unit == CORE:
            reads.append(unit)
            if len(reads) == (2 if moment == 'before-stop' else 3):
                backend.files[DROPIN]['identity'][1] += 1
    backend.hook = mutate
    with pytest.raises(InstallationPending): coordinator.operate('upgrade', source(), [], device_id=None)
    assert ('rpm',) not in backend.commands
    assert not any(command[0] == 'start' for command in backend.commands)


@pytest.mark.parametrize('active', [True, False])
def test_unchanged_preparing_recovery_restores_original_ready_without_rpm(monkeypatch, active):
    store, journal, backend, coordinator = native(monkeypatch, active=active)
    journal.begin('upgrade', source())
    backend.prepare('upgrade', source())
    assert coordinator.reconcile(device_id=None) == 'preparation_recovered'
    assert store.data['runtime-ready'] == {'ready':True}
    assert backend.commands == ([('stop', CORE), ('start', CORE)] if active else [])
    assert journal.state()['operation']['phase'] == 'not_started_recovered'

@pytest.mark.parametrize('cached', ['', 'CANARY_APPROVED=false',
    'ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT=staging CANARY_ENVIRONMENT=staging CANARY_APPROVED=true ENDPOINT_AGENT_ORIGIN=https://endpoint.sosnadmin.local',
    'ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT=staging CANARY_ENVIRONMENT=staging CANARY_APPROVED=true CANARY_APPROVED=true ENDPOINT_AGENT_ORIGIN=https://endpoint-staging.sosnadmin.local'])
def test_stale_or_duplicate_cached_authority_cannot_use_current_staging_bytes(monkeypatch,cached):
    store, journal, backend, coordinator = native(monkeypatch)
    backend.properties[CORE]['Environment'] = cached
    with pytest.raises(InstallationPending): coordinator.operate('upgrade',source(),[],device_id=None)
    assert backend.commands == [] and store.data['runtime-ready'] == {'ready':True}

@pytest.mark.parametrize('active',[True,False])
def test_canonical_production_units_remain_admissible_without_staging_authority(monkeypatch,active):
    store, journal, backend, coordinator = native(monkeypatch,active=active)
    for name in ENVIRONMENT: monkeypatch.delenv(name)
    backend.properties[CORE].update(DropInPaths='',Environment='PC_AGENT_DATA_DIR=/var/lib/endpoint-agent')
    assert coordinator.operate('upgrade',source(),[],device_id=None) == 'enrollment_pending'
    assert backend.commands == ([('stop',CORE)] if active else []) + [('rpm',)]


@pytest.mark.parametrize('dropin', [DROPIN+' '+DROPIN, '/etc/systemd/system/endpoint-agent.service.d/other.conf',
    DROPIN+'\u200b'])
def test_duplicate_foreign_and_unicode_dropin_paths_are_not_approved(monkeypatch,dropin):
    store, journal, backend, coordinator = native(monkeypatch)
    backend.properties[CORE]['DropInPaths'] = dropin
    with pytest.raises(InstallationPending): coordinator.operate('upgrade',source(),[],device_id=None)
    assert not backend.commands and 'runtime-ready' in store.data


@pytest.mark.parametrize('value', [STAGING.replace(b'\n',b'\r\n'), STAGING+b'\n',
    STAGING.replace(b'CANARY_APPROVED=true',b'CANARY_APPROVED=\\\ntrue'),
    STAGING.replace(b'CANARY_ENVIRONMENT=staging',b'CANARY_ENVIRONMENT=staging\nEnvironment=CANARY_ENVIRONMENT=staging')])
def test_noncanonical_directives_never_change_ready_or_units(monkeypatch,value):
    store, journal, backend, coordinator = native(monkeypatch)
    backend.files[DROPIN]['bytes'] = value.decode()
    with pytest.raises(InstallationPending): coordinator.operate('upgrade',source(),[],device_id=None)
    assert not backend.commands and 'runtime-ready' in store.data


@pytest.mark.parametrize('foreign',['extra-dropin','reload','foreign-fragment'])
def test_all_unit_configuration_is_checked_before_ready_gate_invalidation(monkeypatch,foreign):
    store, journal, backend, coordinator = native(monkeypatch)
    unit = 'endpoint-support-access.service'
    props = copy.deepcopy(backend.properties[CORE])
    props.update(FragmentPath='/usr/lib/systemd/system/'+unit,DropInPaths='',ActiveState='inactive',MainPID='0')
    backend.properties[unit] = props
    if foreign == 'extra-dropin': props['DropInPaths'] = DROPIN
    if foreign == 'reload': props['NeedDaemonReload'] = 'yes'
    if foreign == 'foreign-fragment': props['FragmentPath'] = '/etc/systemd/system/'+unit
    with pytest.raises(InstallationPending): coordinator.operate('upgrade',source(),[],device_id=None)
    assert not backend.commands and 'runtime-ready' in store.data


@pytest.mark.parametrize('moment',['after-invalidation','final-quiescence','recovery-before-ready'])
@pytest.mark.parametrize('active',[True,False])
def test_configuration_identity_rechecked_at_actual_mutation_boundaries(monkeypatch,moment,active):
    from pc_agent.platform.linux import installation_user_sessions as sensors
    store, journal, backend, coordinator = native(monkeypatch,active=active)
    def change(): backend.files[DROPIN]['identity'][1] += 1
    if moment == 'after-invalidation':
        invalidate = store.invalidate_ready
        def invalidate_and_replace():
            invalidate()
            change()
        monkeypatch.setattr(store,'invalidate_ready',invalidate_and_replace)
    if moment == 'final-quiescence':
        final = backend._assert_prepared
        def final_with_replacement():
            change()
            final()
        monkeypatch.setattr(backend,'_assert_prepared',final_with_replacement)
    if moment == 'recovery-before-ready':
        journal.begin('upgrade',source())
        backend.prepare('upgrade',source())
        monkeypatch.setattr(sensors,'assert_preparation_handoffs',lambda _:change())
        with pytest.raises(InstallationPending): coordinator.reconcile(device_id=None)
        assert 'runtime-ready' not in store.data
    else:
        with pytest.raises(InstallationPending): coordinator.operate('upgrade',source(),[],device_id=None)
    assert ('rpm',) not in backend.commands and not any(x[0] == 'start' for x in backend.commands)
    assert journal.state()['operation']['phase'] == 'preparing'


def test_changed_configuration_at_execution_boundary_keeps_unknown_without_rpm(monkeypatch):
    from pc_agent.platform.linux import installation_coordinator as c
    store, journal, backend, coordinator = native(monkeypatch)
    monkeypatch.setattr(backend,'execute',lambda *args: RPMBackend.execute(backend,*args))
    native_calls = []
    monkeypatch.setattr(c.subprocess,'run',lambda *args,**kw:native_calls.append(args))
    write = store.write
    def after_invocation_marker(name, raw):
        write(name,raw)
        if name == 'state.json' and store.json(name)['operation']['phase'] == 'invocation_possible':
            backend.files[DROPIN]['identity'][1] += 1
    monkeypatch.setattr(store,'write',after_invocation_marker)
    with pytest.raises(InstallationPending): coordinator.operate('upgrade',source(),[],device_id=None)
    assert not native_calls
    assert journal.state()['operation']['phase'] == 'invocation_possible'
    with pytest.raises(InstallationPending): coordinator.reconcile(device_id=None)
    assert not any(x[0] == 'start' for x in backend.commands)


def test_preparation_receipts_never_capture_unexpected_loaded_environment(monkeypatch):
    store, journal, backend, coordinator = native(monkeypatch)
    backend.properties[CORE]['Environment'] += ' SECRET_TOKEN=do-not-retain-this'
    backend.files['/usr/lib/systemd/system/'+CORE]['bytes'] += 'Environment=SECRET_TOKEN=do-not-retain-this\n'
    assert coordinator.operate('upgrade',source(),[],device_id=None) == 'enrollment_pending'
    assert 'do-not-retain-this' not in json.dumps(store.data)


def test_preparing_recovery_uses_recorded_staging_authority_without_ambient_markers(monkeypatch):
    store, journal, backend, coordinator = native(monkeypatch)
    journal.begin('upgrade',source())
    backend.prepare('upgrade',source())
    for name in ENVIRONMENT: monkeypatch.delenv(name)
    assert coordinator.reconcile(device_id=None) == 'preparation_recovered'
    assert backend.commands == [('stop',CORE),('start',CORE)]


def test_notify_restores_explicit_staging_origin_from_receipt_before_delivery(monkeypatch):
    import os
    from types import SimpleNamespace
    from pc_agent.platform.linux import installation_coordinator as c, installation_notification as n
    store,journal,backend,coordinator = native(monkeypatch)
    journal.begin('upgrade',source())
    for name in ENVIRONMENT: monkeypatch.delenv(name)
    monkeypatch.setenv('ENDPOINT_AGENT_ORIGIN','https://endpoint.sosnadmin.local')
    monkeypatch.setattr(c,'os',SimpleNamespace(name='posix',geteuid=lambda:0,environ=os.environ))
    store.prepare = lambda:None
    monkeypatch.setattr(c,'InstallationStore',lambda:store)
    monkeypatch.setattr(c,'retain_executor',lambda *_:None)
    seen = {}
    async def notify(_):
        seen.update({name:os.environ.get(name) for name in ENVIRONMENT})
    monkeypatch.setattr(n,'notify',notify)
    assert c.main(['notify']) == 0
    assert seen == ENVIRONMENT


def test_changed_configuration_after_durable_stop_intent_never_stops_unit(monkeypatch):
    store,journal,backend,coordinator = native(monkeypatch)
    save = store.save
    def save_and_replace(name,proof):
        save(name,proof)
        if name.startswith('preparation-') and proof['units']:
            backend.files[DROPIN]['identity'][1] += 1
    monkeypatch.setattr(store,'save',save_and_replace)
    with pytest.raises(InstallationPending): coordinator.operate('upgrade',source(),[],device_id=None)
    assert backend.commands == []
