"""FoD preparation is separate from active Support and native MSI ownership."""
import importlib
import json
from pathlib import Path

import pytest


CLIENT = 'OpenSSH.Client~~~~0.0.1.0'
SERVER = 'OpenSSH.Server~~~~0.0.1.0'


def module():
    try:
        return importlib.import_module('pc_agent.platform.windows.support_access_os')
    except ModuleNotFoundError:
        pytest.fail('in-box OpenSSH provisioning is not implemented')


class Servicing:
    def __init__(self, states, *, outcome='complete', previous=None):
        self.states = dict(states)
        self.outcome = outcome
        self.receipt = previous
        self.events = []

    def capabilities(self):
        self.events.append('query')
        return dict(self.states)

    def read_receipt(self):
        return self.receipt

    def write_receipt(self, value):
        self.receipt = value
        self.events.append(('receipt', value['state']))

    def install(self, names):
        assert self.receipt['state'] == 'servicing'
        self.events.append(('install', tuple(names)))
        if self.outcome == 'timeout':
            raise TimeoutError()
        if self.outcome != 'failure':
            self.states.update({name: 'Installed' for name in names})
        return {'completed': self.outcome != 'failure',
                'restart_needed': self.outcome == 'reboot',
                'boundary_preserved': self.outcome != 'foreign-change'}

    def verify(self):
        self.events.append('verify')
        return {'profile': 'windows-openssh-fod-v1', 'hashes': {'sshd': 'a' * 64}}


def test_installed_fod_is_read_only_before_signature_selection():
    ops = Servicing({CLIENT: 'Installed', SERVER: 'Installed'})
    result = module().ensure_inbox_openssh(ops)
    assert result['profile'] == 'windows-openssh-fod-v1'
    assert ops.events == ['query', 'verify']
    assert ops.receipt is None


def test_missing_server_uses_only_exact_capability_after_durable_receipt():
    ops = Servicing({CLIENT: 'Installed', SERVER: 'NotPresent'})
    result = module().ensure_inbox_openssh(ops)
    assert ('install', (SERVER,)) in ops.events
    assert ops.events.index(('receipt', 'servicing')) < ops.events.index(('install', (SERVER,)))
    assert result['profile'] == 'windows-openssh-fod-v1'
    assert ops.receipt['state'] == 'complete'


@pytest.mark.parametrize('outcome,code,state', [
    ('failure', 'support_dependency_install_failed', 'failed'),
    ('reboot', 'support_dependency_reboot_required', 'reboot_required'),
    ('foreign-change', 'support_dependency_firewall_conflict', 'conflict'),
])
def test_unsuccessful_fod_never_reaches_new_support_or_verification(outcome, code, state):
    ops = Servicing({CLIENT: 'Installed', SERVER: 'NotPresent'}, outcome=outcome)
    with pytest.raises(ValueError, match=code):
        module().ensure_inbox_openssh(ops)
    assert 'verify' not in ops.events
    assert ops.receipt['state'] == state


def test_unknown_servicing_result_is_not_replayed():
    ops = Servicing({CLIENT: 'NotPresent', SERVER: 'NotPresent'}, outcome='timeout')
    with pytest.raises(ValueError, match='support_dependency_recovery_required'):
        module().ensure_inbox_openssh(ops)
    assert ops.receipt['state'] == 'servicing'
    ops.events.clear()
    with pytest.raises(ValueError, match='support_dependency_recovery_required'):
        module().ensure_inbox_openssh(ops)
    assert not any(isinstance(e, tuple) and e[0] == 'install' for e in ops.events)


@pytest.mark.parametrize('states', [
    {CLIENT: 'Installed'},
    {CLIENT: 'Installed', SERVER: 'InstallPending'},
    {CLIENT: 'Installed', SERVER: 'Installed', 'foreign': 'NotPresent'},
])
def test_ambiguous_capability_state_refuses_before_any_write(states):
    ops = Servicing(states)
    with pytest.raises(ValueError):
        module().ensure_inbox_openssh(ops)
    assert ops.events == ['query']


def test_pending_servicing_is_not_declared_recovered_from_file_presence():
    ops = Servicing({CLIENT: 'Installed', SERVER: 'Installed'}, previous={
        'state': 'servicing', 'capabilities': [SERVER]})
    with pytest.raises(ValueError, match='support_dependency_recovery_required'):
        module().ensure_inbox_openssh(ops)
    assert 'verify' not in ops.events


def test_os_dependency_refresh_reuses_verified_snapshot_without_signature_process():
    calls = []
    current = {'profile': 'windows-openssh-fod-v1', 'hashes': {'sshd': 'a' * 64}}
    monitor = module().OSDependencyMonitor(current, unchanged=lambda value: True,
        validate=lambda: calls.append('signature'))
    assert monitor.refresh() == current
    assert calls == []


def test_os_dependency_refresh_changes_only_after_full_validation():
    before = {'profile': 'windows-openssh-fod-v1', 'hashes': {'sshd': 'a' * 64}}
    after = {'profile': 'windows-openssh-fod-v1', 'hashes': {'sshd': 'b' * 64}}
    persisted = []
    monitor = module().OSDependencyMonitor(before, unchanged=lambda value: False,
        validate=lambda: after, persist=lambda old, new: persisted.append((old, new)))
    assert monitor.refresh() == after
    assert before['hashes']['sshd'] == 'a' * 64
    assert persisted == [(before, after)]


def test_invalid_os_replacement_never_overwrites_last_verified_snapshot():
    before = {'profile': 'windows-openssh-fod-v1', 'hashes': {'sshd': 'a' * 64}}
    def rejected():
        raise ValueError('support_dependency_signature_invalid')
    persisted = []
    monitor = module().OSDependencyMonitor(before, unchanged=lambda _: False,
        validate=rejected, persist=lambda *args: persisted.append(args))
    with pytest.raises(ValueError):
        monitor.refresh()
    assert monitor.dependencies == before and not persisted


@pytest.fixture
def os_snapshot(tmp_path, monkeypatch):
    import hashlib
    from pc_agent.platform.windows import support_access_native as native
    mod = module()
    root = tmp_path/'System32/OpenSSH';root.mkdir(parents=True)
    rows = []
    for name in ('ssh.exe', 'sshd.exe', 'ssh-keygen.exe'):
        (root/name).write_bytes(b'OS fixture')
        rows.append(dict(name=name, size=10, sha256=hashlib.sha256(b'OS fixture').hexdigest(),
                         version='9.5.6.4', publisher_thumbprint='A'*40))
    monkeypatch.setattr(native, 'windows_root', lambda: tmp_path)
    monkeypatch.setattr(mod, 'assert_os_path', lambda path: None)
    value = {'profile': mod.PROFILE, 'capability_version': '0.0.1.0', 'files': rows,
             'moduli_sha256': None, 'hashes': {}, 'versions': {}}
    for role, name in mod.ROLES.items():
        value[role] = str(root/name)
        value['hashes'][role] = rows[0]['sha256']
        value['versions'][role] = '9.5.6.4'
    return mod, root, value


def test_complete_snapshot_rejects_mixed_servicing_versions(os_snapshot):
    mod, root, value = os_snapshot
    value['files'][0]['version'] = '10.0.0.0'
    value['versions']['ssh'] = '10.0.0.0'
    with pytest.raises(ValueError):mod.verify_os_snapshot(value)


def test_snapshot_requires_recorded_microsoft_publisher_fingerprint(os_snapshot):
    mod, root, value = os_snapshot
    value['files'][0]['publisher_thumbprint'] = ''
    with pytest.raises(ValueError):mod.verify_os_snapshot(value)


def test_added_or_changed_helper_invalidates_cached_signature_closure(os_snapshot):
    mod, root, value = os_snapshot
    mod.verify_os_snapshot(value)
    (root/'ssh-shellhost.exe').write_bytes(b'new helper')
    assert not mod.snapshot_unchanged(value)


def test_service_refresh_validation_can_block_without_extending_the_existing_lease():
    from datetime import datetime, timezone
    from threading import Event, Thread
    from pc_agent.tests.windows.test_support_access import DEVICE, Children, policy
    from pc_agent.platform.windows.support_access import SupportSupervisor
    now = datetime.now(timezone.utc);children = Children();state = SupportSupervisor(DEVICE, children)
    state.accept(policy(now), now=now, monotonic_now=100)
    entered, release = Event(), Event()
    def validate():
        entered.set();release.wait(2)
        return {'profile': module().PROFILE}
    monitor = module().OSDependencyMonitor({'profile': module().PROFILE},
        unchanged=lambda _: False, validate=validate)
    worker = Thread(target=monitor.refresh);worker.start()
    assert entered.wait(1)
    try:
        state.tick(monotonic_now=161)
        assert not children.active
    finally:
        release.set();worker.join(2)
    state.tick(monotonic_now=162)
    assert not children.active


def test_unit_suite_blocks_native_operator_servicing_without_an_adapter():
    ops = object.__new__(module().WindowsFOD)
    with pytest.raises(pytest.fail.Exception, match='operator Windows servicing'):
        ops.capabilities()
    with pytest.raises(pytest.fail.Exception, match='operator Windows servicing'):
        ops.install((SERVER,))


def test_known_reboot_completion_can_revalidate_without_replaying_fod():
    ops = Servicing({CLIENT: 'Installed', SERVER: 'Installed'}, previous={
        'schema_version': 1, 'state': 'reboot_required', 'capabilities': [SERVER]})
    ops.reboot_completed = lambda old: True
    assert module().ensure_inbox_openssh(ops)['profile'] == module().PROFILE
    assert ops.receipt['state'] == 'complete'
    assert not any(isinstance(e, tuple) and e[0] == 'install' for e in ops.events)


def test_new_support_build_includes_metadata_for_cleanup_without_preview_archive(monkeypatch):
    from tools.canary.support_openssh_payload import resource_datas
    monkeypatch.delenv('ENDPOINT_SUPPORT_OPENSSH_ZIP', raising=False)
    repo = Path(__file__).resolve().parents[3]
    rows = resource_datas(repo, include_archive=False)
    assert {Path(source).name for source, target in rows} == {
        'manifest.json', 'LICENSE.txt', 'NOTICE.txt', 'QUALIFICATION.md'}
    assert all(target == 'support-openssh' for source, target in rows)


def test_completed_fod_with_transient_signature_failure_retries_only_verification():
    ops=Servicing({CLIENT:'Installed',SERVER:'NotPresent'})
    original=ops.verify
    ops.verify=lambda:(_ for _ in ()).throw(ValueError('temporary signature transport'))
    with pytest.raises(ValueError):module().ensure_inbox_openssh(ops)
    assert ops.receipt['state']=='installed_unverified'
    ops.verify=original;ops.events.clear()
    assert module().ensure_inbox_openssh(ops)['profile']==module().PROFILE
    assert ops.receipt['state']=='complete'
    assert not any(isinstance(e,tuple) and e[0]=='install' for e in ops.events)


def test_concurrent_foreign_default_firewall_rule_is_never_deleted():
    """Execute the actual fixed script with only in-memory cmdlet doubles."""
    import ast
    tree=ast.parse(Path(module().__file__).read_text())
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='WindowsFOD')
    method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='install')
    call=next(n for n in ast.walk(method) if isinstance(n,ast.Call)
              and isinstance(n.func,ast.Name) and n.func.id=='run_fixed_powershell')
    script=ast.literal_eval(call.args[0])
    prefix=r'''
$script:rule=$null
function Prop($name,$value){[pscustomobject]@{Name=$name;Value=$value}}
function MakeRule($description){[pscustomobject]@{Name='OpenSSH-Server-In-TCP';InstanceID='rule-id';Description=$description;Direction='Inbound';Action='Allow';Enabled='True';Profile='Any';PolicyStoreSourceType='Local';CimInstanceProperties=@((Prop 'Name' 'OpenSSH-Server-In-TCP'),(Prop 'Description' $description))}}
function Get-CimInstance {param($ClassName,$Filter);return $null}
function Get-NetFirewallRule {param($Name,$PolicyStore,$ErrorAction);if($script:rule){return $script:rule}}
function New-NetFirewallRule {param($Name,$DisplayName,$Description,$Direction,$Action,$Enabled,$Protocol,$LocalPort,$Program,$Profile,$PolicyStore,$ErrorAction);$script:rule=MakeRule $Description;return $script:rule}
function Add-WindowsCapability {param([switch]$Online,$Name,$ErrorAction);$script:rule=MakeRule 'Created by an unrelated administrator';@{RestartNeeded=$false}}
function Remove-NetFirewallRule {param([Parameter(ValueFromPipeline=$true)]$InputObject,$ErrorAction);throw 'Must preserve concurrent foreign rule'}
function Get-NetFirewallPortFilter {param([Parameter(ValueFromPipeline=$true)]$InputObject);[pscustomobject]@{Protocol='TCP';LocalPort='22';RemotePort='Any';CimInstanceProperties=@((Prop 'LocalPort' '22'))}}
function Get-NetFirewallAddressFilter {param([Parameter(ValueFromPipeline=$true)]$InputObject);[pscustomobject]@{LocalAddress='Any';RemoteAddress='Any';CimInstanceProperties=@((Prop 'LocalAddress' 'Any'))}}
function Get-NetFirewallApplicationFilter {param([Parameter(ValueFromPipeline=$true)]$InputObject);[pscustomobject]@{Program='Any';CimInstanceProperties=@((Prop 'Program' 'Any'))}}
function Get-NetFirewallServiceFilter {param([Parameter(ValueFromPipeline=$true)]$InputObject);[pscustomobject]@{CimInstanceProperties=@((Prop 'Service' 'Any'))}}
function Get-NetFirewallSecurityFilter {param([Parameter(ValueFromPipeline=$true)]$InputObject);[pscustomobject]@{CimInstanceProperties=@((Prop 'Authentication' 'NotRequired'))}}
function Get-NetFirewallInterfaceFilter {param([Parameter(ValueFromPipeline=$true)]$InputObject);[pscustomobject]@{CimInstanceProperties=@((Prop 'InterfaceAlias' 'Any'))}}
function Get-NetFirewallInterfaceTypeFilter {param([Parameter(ValueFromPipeline=$true)]$InputObject);[pscustomobject]@{CimInstanceProperties=@((Prop 'InterfaceType' 'Any'))}}
'''
    result=module().run_fixed_powershell(prefix+script,variables={
        'ENDPOINT_SUPPORT_FOD_NAMES':json.dumps([SERVER]),
        'ENDPOINT_SUPPORT_FOD_OPERATION':'a'*32},timeout=10)
    assert result['boundary_preserved'] is False
