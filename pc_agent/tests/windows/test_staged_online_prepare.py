"""Online capture is allowed before quiescence; native entry still is not."""
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import installer_transaction_bridge as bridge
from pc_agent.platform.windows import installation_provenance, staged_update_state
from pc_agent.platform.windows import durable_state, installer_fence
from pc_agent.tests.windows.test_installation_provenance import handoff_input
from pc_agent.tests.windows.test_staged_update_state import release
from pc_agent.tests.windows.test_installer_fence import native_protected_root


@pytest.fixture
def tmp_path(request, tmp_path_factory):
    # This unit exercises the real settled-state namespace gate. Its hermetic
    # files therefore need a trusted parent, not the ordinary writable TEMP.
    return (request.getfixturevalue('native_protected_root') if os.name == 'nt'
            else tmp_path_factory.mktemp('staged-online'))


@pytest.fixture
def online(handoff_input, monkeypatch):
    provenance, paths, root, request, expected = handoff_input
    owner = {'pid': os.getpid(), 'created': 1, 'hash': 'd' * 64, 'sid': 'S-1-5-18', 'elevated': True}
    cap = {'operation': 'install', 'recovery': False, 'uninstall_finalization': False,
           'package': request['release'], 'transaction_id': request['transaction_id'],
           'session_id': '22222222-2222-4222-8222-222222222222', 'owner': owner,
           'selected': request['selected'], 'previous': request['previous']}
    monkeypatch.setattr(bridge, '_request_data', lambda *_: request)
    old_release = release('3.2.81', 'e')
    monkeypatch.setattr(provenance, 'verified_foundation_release', lambda _: old_release)
    checkpoints = []
    client = SimpleNamespace(capability=cap, phase='stage-online',
                             checkpoint=lambda: checkpoints.append('grant'))
    return client, paths, root, request, expected, checkpoints


def test_stage_completes_before_service_stop(online, monkeypatch):
    client, paths, _, _, _, checkpoints = online
    before = paths.current_path.read_bytes()
    def no_scm(*_args, **_kwargs):
        pytest.fail('online preparation attempted SCM quarantine or stop')
    monkeypatch.setattr(bridge, 'InstallerServices', no_scm)
    prepared = bridge.stage_online_update(client, paths)
    assert prepared.phase == 'prepared'
    assert checkpoints
    assert paths.current_path.read_bytes() == before
    assert installer_fence.read_fence(paths) is None
    assert (installer_fence.state_root(paths) / 'provenance' / prepared.binding.operation_id / 'plan.json').is_file()


def test_installed_tree_is_distinct_from_authored_msi_tree(online):
    client, paths, _, request, expected, _ = online
    assert request['release']['initial_runtime_tree_sha256'] != expected.identity.tree_sha256
    record = bridge.stage_online_update(client, paths)
    assert record.binding.candidate_tree_sha256 == expected.identity.tree_sha256
    assert record.binding.new_release == request['release']


def test_online_metrics_do_not_leak_paths_or_identities(online):
    client, paths, _, _, _, checkpoints = online
    bridge.stage_online_update(client, paths)
    assert set(client.phase_metrics) == {'grant_count', 'grant_seconds', 'total_seconds', 'preparation_seconds'}
    assert client.phase_metrics['grant_count'] == len(checkpoints)
    assert client.phase_metrics['total_seconds'] >= client.phase_metrics['preparation_seconds'] >= 0
    assert all(isinstance(value, (int, float)) for value in client.phase_metrics.values())


@pytest.mark.parametrize('defect', ['selector', 'media', 'pending'])
def test_selector_or_media_change_invalidates_prepared_switch(online, monkeypatch, defect):
    client, paths, _, _, _, _ = online
    prepared = bridge.stage_online_update(client, paths)
    client.phase = 'seal-staged-switch'
    if defect == 'selector':
        paths.current_path.write_text(json.dumps({'version': '3.2.999'}))
    elif defect == 'media':
        from pc_agent.platform.windows import msi_inventory
        def changed(*_args, **_kwargs): raise ValueError('PROVENANCE_CONFLICT')
        monkeypatch.setattr(msi_inventory, 'read_expected_package', changed)
    else:
        paths.updates_root.mkdir(parents=True)
        paths.pending_path.write_text(json.dumps({'operation_id': 'operation', 'version': '3.2.83'}))
    with pytest.raises(ValueError):
        bridge.seal_staged_switch(client, paths, prepared.binding.operation_id)
    assert staged_update_state.read_staged_update(paths).phase == 'prepared'
    assert installer_fence.read_fence(paths) is None


def test_sealed_prepare_does_not_repeat_retention_writes(online, monkeypatch):
    client, paths, _, request, _, _ = online
    prepared = bridge.stage_online_update(client, paths)
    client.phase = 'seal-staged-switch'
    sealed = bridge.seal_staged_switch(client, paths, prepared.binding.operation_id)
    assert sealed.phase == 'switching'
    def no_copy(*_args, **_kwargs):
        pytest.fail('quiescent preparation repeated an admitted media/payload copy')
    monkeypatch.setattr(durable_state, 'durable_copy_file', no_copy)
    with durable_state.installer_mutation_checkpoints(client.checkpoint):
        assert installation_provenance.prepare_installer_provenance(paths, request) == 'handoff'


@pytest.mark.skipif(os.name != 'nt', reason='actual compiled owner policy')
def test_online_phase_does_not_grant_native_entry(tmp_path):
    source = Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'staged-owner.ps1'
    script.write_text(r'''param($Source)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $node.Extent.Text;Initialize-InstallerBridgeTypes
function Reject([scriptblock]$Action){$denied=$false;try{& $Action|Out-Null}catch{$denied=$true};if(!$denied){throw 'unsafe staged admission'}}
$owner=[EndpointInstallerBridge.Identity]::new(100,1000,('a'*64),'S-1-5-18',$true)
$peer=[EndpointInstallerBridge.Identity]::new(200,2000,('b'*64),'S-1-5-18',$true)
$seal=[EndpointInstallerBridge.Identity]::new(201,2001,('b'*64),'S-1-5-18',$true)
$policy=[EndpointInstallerBridge.Policy]::new('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222',('c'*64),'install',$owner,('b'*64),[byte[]](1..32))
Reject {$policy.RegisterHelper($peer,'prepare')}
$policy.RegisterHelper($peer,'stage-online')
foreach($action in @('begin','mutation','complete')){
 $grant=$policy.Issue($peer,'stage-online',$action,('d'*64),$policy.SessionId)
 $policy.Accept($peer,$grant,$policy.Sign('request',$grant))|Out-Null
}
$policy.MarkHelperExited($peer,0)
Reject {$policy.RegisterMsi($peer,'install')}
Reject {$policy.RegisterHelper($seal,'stage-online')}
Reject {$policy.RegisterHelper($seal,'seal-staged-switch')}
$policy.MarkQuiescent();$policy.RegisterHelper($seal,'seal-staged-switch')
foreach($action in @('begin','mutation','complete')){
 $grant=$policy.Issue($seal,'seal-staged-switch',$action,('d'*64),$policy.SessionId)
 $policy.Accept($seal,$grant,$policy.Sign('request',$grant))|Out-Null
}
Reject {$policy.RegisterMsi($peer,'install')}
$policy.OwnerLost();Reject {$policy.Issue($seal,'seal-staged-switch','mutation',('d'*64),$policy.SessionId)}
'passed'
''', encoding='utf-8')
    completed = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source)],
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == 'passed'


@pytest.mark.skipif(os.name != 'nt', reason='actual PowerShell orchestration')
@pytest.mark.parametrize('service', ['running', 'stopped', 'absent', 'restarted'])
def test_owner_keeps_services_running_until_online_capture_finishes(tmp_path, service):
    source = Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'online-order.ps1'
    script.write_text(r'''param($Source,$Service)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
foreach($name in @('Invoke-StagedOnlinePreparation')){
 $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 if(!$node){throw 'online preparation orchestration missing'}
 Invoke-Expression $node.Extent.Text
}
$script:events=[Collections.Generic.List[string]]::new()
function New-TestBridge {
 $policy=[pscustomobject]@{AllHelpersComplete=$true;NativeEntered=$false}
 $policy|Add-Member ScriptMethod OwnerLost { $script:events.Add('revoke') }
 $resource=[pscustomobject]@{}
 $resource|Add-Member ScriptMethod Dispose { }
 return [pscustomobject]@{RollbackMediaPath=$null;TransactionId='11111111-1111-4111-8111-111111111111';SessionId='22222222-2222-4222-8222-222222222222';Policy=$policy;Channel=$resource;Owner=$resource;Peers=@();Capability=@{operation='install';recovery=$false;transaction_id='11111111-1111-4111-8111-111111111111';session_id='22222222-2222-4222-8222-222222222222'}}
}
function New-InstallerBridge {param($Manifest,$HelperPath,$HelperHash,$StateRoot,$ServiceStates,$Intent,$TransactionId,$Selection);return New-TestBridge}
function Get-StagedAgentObservation {
 if($Service -in @('stopped','absent')){throw 'UPDATE_IN_PROGRESS'}
 if($Service -eq 'restarted' -and $script:events.Contains('prepared')){return 'changed-process'}
 return 'same-process'
}
function Stop-ManagedAgentServices {throw 'old services stopped during capture'}
function Get-StagedRollbackMedia {param($Item,$StateRoot,$CacheRoot)
 $script:events.Add('media');return 'verified-old-media'
}
function Invoke-InstallerHelper {param($Bridge,$Phase)
 if($Phase -cne 'stage-online'){throw 'unexpected helper phase'}
 $script:events.Add('prepared')
 return [pscustomobject]@{result='staged-prepared';phase='prepared';operation_id=$Bridge.TransactionId;
  rollback_media=@{old=@{};new=@{release=@{package_sha256=('c'*64)};helper_sha256=('a'*64)}}}
}
$old=New-TestBridge
$denied=$false
try{$new=Invoke-StagedOnlinePreparation -Bridge $old -Manifest @{package_sha256=('c'*64)} -HelperPath 'helper' -HelperHash ('a'*64) -StateRoot 'state' -CacheRoot 'cache' -ServiceStates @{} -Selection ([pscustomobject]@{selected=('b'*64);previous=$null})}catch{$denied=$true}
if($Service -eq 'running'){
 if($denied -or $new -eq $old -or [string]::Join(',', $script:events) -cne 'prepared,media,revoke'){throw 'unsafe staging handoff'}
}elseif(!$denied){throw 'unsafe service observation accepted'}
'passed'
''', encoding='utf-8')
    completed = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source), service],
                               capture_output=True, text=True, timeout=15)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == 'passed'


def test_new_native_session_adopts_original_proof_without_rebaselining(online, monkeypatch):
    from pc_agent.platform.windows import installer_data_security as data_security
    client, paths, _, request, _, _ = online
    prepared = bridge.stage_online_update(client, paths)
    client.phase = 'seal-staged-switch'
    bridge.seal_staged_switch(client, paths, prepared.binding.operation_id)
    source_cap = dict(client.capability)
    proof = installer_fence.state_root(paths) / 'transactions' / prepared.binding.operation_id / 'data-root-before.json'
    before = proof.read_bytes()
    successor = {**source_cap, 'session_id': '33333333-3333-4333-8333-333333333333'}
    monkeypatch.setattr(bridge, '_read_capability', lambda _paths, session: source_cap if session == source_cap['session_id'] else successor)
    client.capability = successor
    client.phase = 'adopt-staged-switch'
    bridge.adopt_staged_switch(client, paths)
    with durable_state.installer_mutation_checkpoints(client.checkpoint):
        data_security.prepare(paths, {**request, 'session_id': successor['session_id'], 'recovery': False})
        data_security.before_native(paths, {**request, 'session_id': successor['session_id'], 'recovery': False})
    assert proof.read_bytes() == before
    original = json.loads(before)
    assert original['binding']['session_id'] == source_cap['session_id']


@pytest.mark.parametrize('defect', ['owner', 'package', 'selector', 'capture', 'phase', 'same-session'])
def test_session_adoption_rejects_different_owner_or_capture(online, monkeypatch, defect):
    client, paths, _, request, _, _ = online
    prepared = bridge.stage_online_update(client, paths)
    client.phase = 'seal-staged-switch'
    bridge.seal_staged_switch(client, paths, prepared.binding.operation_id)
    source_cap = dict(client.capability)
    monkeypatch.setattr(bridge, '_read_capability', lambda *_: source_cap)
    client.capability = {**source_cap, 'session_id': '33333333-3333-4333-8333-333333333333'}
    if defect == 'owner': client.capability['owner'] = {**source_cap['owner'], 'created': 2}
    elif defect == 'package': client.capability['package'] = {**source_cap['package'], 'package_sha256': 'f' * 64}
    elif defect == 'selector': client.capability['selected'] = 'f' * 64
    elif defect == 'phase':
        with durable_state.installer_mutation_checkpoints(client.checkpoint):
            staged_update_state.advance_staged_update(paths, prepared.binding.operation_id, 'switching', 'recovery-required')
    elif defect == 'same-session': client.capability['session_id'] = source_cap['session_id']
    else:
        from pc_agent.platform.windows import installer_data_security
        monkeypatch.setattr(installer_data_security, '_snapshot', lambda _: {'root': None, 'leaves': {'changed': None}})
    client.phase = 'adopt-staged-switch'
    with pytest.raises(ValueError): bridge.adopt_staged_switch(client, paths)
