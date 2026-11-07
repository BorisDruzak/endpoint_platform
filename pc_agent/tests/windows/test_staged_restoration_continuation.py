"""Terminal rollback may derive old restoration completion, never rewrite it."""
from contextlib import nullcontext
from dataclasses import replace
import hashlib
import json
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest

from pc_agent.platform.windows import durable_state, installer_fence as fence
from pc_agent.platform.windows import staged_update_state as state, native_setup_continuation as continuation
from pc_agent.tests.windows.test_staged_update_state import staged, native_protected_root, release


@pytest.fixture
def restored(staged, monkeypatch, request):
    from pc_agent.platform.windows import installer_transaction_bridge as bridge, staged_foundation_rollback as rollback
    _, paths, original, owner = staged
    owner = {**owner, 'sid': getattr(request, 'param', 'S-1-5-18')}
    old = release('3.2.172', 'a'); new = release('3.2.173', 'b')
    selected = json.dumps({'schema_version': 1, 'version': '3.2.172', 'source_revision': 'a'*40}).encode()
    previous = json.dumps({'schema_version': 1, 'version': '3.2.167', 'source_revision': 'e'*40}).encode()
    binding = replace(original, old_release=old, new_release=new, selected_before=selected,
        previous_before=previous, previous_tree_sha256_before='e'*64,
        candidate_version='3.2.173', candidate_source_revision='b'*40)
    # The parent record is real and terminal. Its original previous selector
    # will be restored only AFTER the immutable old172 native finish grant.
    record = state.StagedUpdateRecord(binding, 'rolled-back', 7, str(uuid4()), owner, None, None)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        state._write(paths, record)
    paths.current_path.write_bytes(selected)
    fence.protect_state(paths.current_path)
    sessions = [str(uuid4()) for _ in range(3)]
    transactions = [binding.operation_id, str(uuid4()), str(uuid4())]
    def capability(index):
        session = sessions[index]
        return dict(schema_version=1, transaction_id=transactions[index], session_id=session,
            operation='uninstall' if index == 1 else 'install', package=old if index == 2 else new,
            helper_sha256=('c' if index == 2 else 'd')*64, owner=owner,
            recovery=False, uninstall_finalization=False, selected=None, previous=None,
            pipe_name='EndpointInstaller-'+session+'-'+'f'*32, secret='f'*64,
            service_states={'EndpointAgent': 'running', 'EndpointAgentUpdater': 'stopped'})
    control, removal, restoration = [capability(i) for i in range(3)]
    control['staged_rollback'] = dict(role='control', operation_id=binding.operation_id,
        removal_session_id=sessions[1], restoration_session_id=sessions[2])
    removal['staged_rollback'] = dict(role='remove', operation_id=binding.operation_id, control_session_id=sessions[0])
    private = fence.state_root(paths) / 'capabilities'; private.mkdir(); fence.protect_state(private, secret=True)
    def write(path, value, secret=True):
        durable_state.write_json_atomic(path, value, trusted_root=path.parent, max_bytes=65536,
            protect=lambda leaf: fence.protect_state(leaf, secret=secret))
    with durable_state.installer_mutation_checkpoints(lambda: None):
        for cap in (control, removal, restoration):
            write(private / (cap['session_id']+'.json'), cap)
    root = fence.state_root(paths) / 'staged-rollback'; root.mkdir(); fence.protect_state(root)
    root = root / binding.operation_id; root.mkdir(); fence.protect_state(root)
    media = lambda value, helper: dict(relative_path='packages/'+value['package_sha256']+'/EndpointAgent.msi', release=value, helper_sha256=helper)
    plan = dict(schema_version=1, operation_id=binding.operation_id, rollback_id=str(uuid4()),
        binding_sha256=rollback._binding_hash(record), old=media(old, 'c'*64), new=media(new, 'd'*64), archives=[], phase='complete')
    roles = dict(schema_version=1, owner=owner, plan_sha256=rollback.plan_identity_sha256(plan),
        control=rollback._role_projection(control), removal=rollback._role_projection(removal), restoration=rollback._role_projection(restoration))
    with durable_state.installer_mutation_checkpoints(lambda: None):
        write(root/'plan.json', plan)
        write(root/('roles-'+sessions[0]+'.json'), roles)
    monkeypatch.setattr(continuation, '_capture_authority', lambda *_: {'session_id': sessions[2], 'capture_sha256': '7'*64})
    inspected = SimpleNamespace(current=SimpleNamespace(identity=SimpleNamespace(tree_sha256=binding.selected_tree_sha256_before)))
    monkeypatch.setattr(continuation.provenance, 'inspect_installed_core', lambda *a, **kw: inspected)
    completed = bridge._public_fence(SimpleNamespace(package=SimpleNamespace(sha256=old['package_sha256'],
        product_code=old['product_code'], package_code='{11111111-1111-4111-8111-111111111111}', version=old['version']),
        identity=SimpleNamespace(source_revision=old['source_revision'])), restoration)
    completed.update(phase='complete', startup_restored=True, sequence=4)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        continuation.reserve_native_continuation(paths, restoration, completed, {**completed, 'phase': 'reconciling'})
        write(continuation._grant_path(paths, transactions[2]).with_name('completed.json'), completed, secret=False)
    paths.previous_path.write_bytes(previous); fence.protect_state(paths.previous_path)
    calls = []
    monkeypatch.setattr(rollback, '_verify_native_restore', lambda *_: calls.append('native'))
    monkeypatch.setattr(rollback, '_verify_original_core', lambda *_: calls.append('core'))
    monkeypatch.setattr(rollback, '_verify_original_data', lambda *_: calls.append('private'))
    monkeypatch.setattr(continuation.recovery, '_assert_owner_dead', lambda value: calls.append(('dead', value['pid'])))
    recovery_cap = dict(capability(0), transaction_id=str(uuid4()), session_id=str(uuid4()),
        package=release('3.2.174', '9'), restoration_transaction_id=transactions[2],
        owner={**owner, 'sid': 'S-1-5-18', 'pid': owner['pid']+100, 'hash': '9'*64})
    recovery_cap['pipe_name'] = 'EndpointInstaller-' + recovery_cap['session_id'] + '-' + 'f'*32
    with durable_state.installer_mutation_checkpoints(lambda: None):
        write(private / (recovery_cap['session_id']+'.json'), recovery_cap)
    from pc_agent.platform.windows import installer_data_security
    monkeypatch.setattr(installer_data_security, 'verify_preserved', lambda *_: calls.append('native-private'))
    client = SimpleNamespace(phase='finalize-staged-restoration-continuation', capability=recovery_cap,
        checkpoint=lambda: calls.append('checkpoint'))
    return SimpleNamespace(paths=paths, binding=binding, record=record, control=control,
        restoration=restoration, client=client, plan=plan, root=root, write=write, calls=calls,
        target=transactions[2], owner=owner)


def test_legacy172_restoration_leak_is_real_without_weakening_generic_reader(restored):
    r = restored
    assert continuation.pending_continuation(r.paths)['transaction_id'] == r.target
    with pytest.raises(ValueError, match='RECOVERY_REQUIRED'):
        continuation.read_continuation_grant(r.paths, r.restoration)


def test_exact_role_bound_finalizer_retains_old_evidence_and_selectors(restored, monkeypatch):
    from pc_agent.platform.windows import staged_restoration_continuation as module
    r = restored
    monkeypatch.setattr(module, '_restored_services', lambda *_: {'EndpointAgent': {'start_type': 2, 'delayed_auto': False, 'state': 'running'}})
    monkeypatch.setattr(module, '_no_other_operations', lambda *_: None)
    monkeypatch.setattr(module, '_runner_authority', lambda *_: None)
    before = {leaf: leaf.read_bytes() for leaf in (r.paths.current_path, r.paths.previous_path,
        continuation._grant_path(r.paths, r.target), continuation._grant_path(r.paths, r.target).with_name('completed.json'))}
    with durable_state.installer_mutation_checkpoints(r.client.checkpoint):
        result = module.finalize_restoration_continuation(r.client, r.paths, r.target)
    assert result['result'] == 'staged-restoration-complete' and result['operation_id'] == r.target
    assert continuation.pending_continuation(r.paths) is None
    assert all(leaf.read_bytes() == data for leaf, data in before.items())
    assert not continuation._grant_path(r.paths, r.target).with_name('native-continuation-finished.json').exists()
    receipt = json.loads((r.root/'restoration-continuation-finalized.json').read_text())
    assert receipt['proof']['restoration_transaction_id'] == r.target
    assert {'native', 'core', 'private'} <= set(value for value in r.calls if isinstance(value, str))
    with durable_state.installer_mutation_checkpoints(r.client.checkpoint):
        assert module.finalize_restoration_continuation(r.client, r.paths, r.target) == result
    with pytest.raises(ValueError, match='RECOVERY_REQUIRED'):
        continuation.read_continuation_grant(r.paths, r.restoration)


@pytest.mark.parametrize('defect', ['current', 'previous', 'hold-package', 'role', 'grant-helper', 'completion', 'stage-phase', 'plan-phase', 'owner-alive'])
def test_finalizer_rejects_unproven_delta_without_retiring_hold(restored, monkeypatch, defect):
    from pc_agent.platform.windows import staged_restoration_continuation as module
    r = restored
    monkeypatch.setattr(module, '_restored_services', lambda *_: {})
    monkeypatch.setattr(module, '_no_other_operations', lambda *_: None)
    monkeypatch.setattr(module, '_runner_authority', lambda *_: None)
    if defect in {'current', 'previous'}:
        (r.paths.current_path if defect == 'current' else r.paths.previous_path).write_bytes(b'foreign selector')
    elif defect == 'owner-alive':
        monkeypatch.setattr(continuation.recovery, '_assert_owner_dead', lambda *_: (_ for _ in ()).throw(ValueError('RECOVERY_REQUIRED')))
    else:
        leaf = (fence.state_root(r.paths)/'native-continuation.json' if defect == 'hold-package' else
            r.root/('roles-'+r.control['session_id']+'.json') if defect == 'role' else
            continuation._grant_path(r.paths,r.target) if defect == 'grant-helper' else
            continuation._grant_path(r.paths,r.target).with_name('completed.json') if defect == 'completion' else
            fence.state_root(r.paths)/'staged-update.json' if defect == 'stage-phase' else r.root/'plan.json')
        value = json.loads(leaf.read_text())
        if defect == 'hold-package': value['package']['version'] = '3.2.171'
        elif defect == 'role': value['restoration']['transaction_id'] = str(uuid4())
        elif defect == 'grant-helper': value['helper_sha256'] = '0'*64
        elif defect == 'completion': value['startup_restored'] = False
        elif defect == 'stage-phase': value['phase'] = 'trial'
        else: value['phase'] = 'native-committed'
        with durable_state.installer_mutation_checkpoints(lambda: None): r.write(leaf, value)
    with durable_state.installer_mutation_checkpoints(r.client.checkpoint):
        with pytest.raises(ValueError): module.finalize_restoration_continuation(r.client, r.paths, r.target)
    assert (fence.state_root(r.paths)/'native-continuation.json').exists()
    assert not (r.root/'restoration-continuation-finalized.json').exists()


@pytest.fixture
def finalizer(restored, monkeypatch):
    from pc_agent.platform.windows import staged_restoration_continuation as module
    monkeypatch.setattr(module, '_restored_services', lambda *_: {'EndpointAgent': {'start_type': 2, 'delayed_auto': False, 'state': 'running'}})
    monkeypatch.setattr(module, '_no_other_operations', lambda *_: None)
    monkeypatch.setattr(module, '_runner_authority', lambda *_: None)
    return module, restored


@pytest.mark.parametrize('restored', ['S-1-5-18', 'S-1-5-21-123'], indirect=True)
def test_parent_bound_live_owner_does_not_require_its_own_death(finalizer, monkeypatch):
    module, r = finalizer
    monkeypatch.setattr(recovery := continuation.recovery, '_assert_owner_dead', lambda *_: pytest.fail('bound live parent was required dead'))
    client = SimpleNamespace(phase='verify-foundation-rollback', capability=r.control, checkpoint=lambda: None)
    with durable_state.installer_mutation_checkpoints(client.checkpoint):
        result = module.finalize_restoration_continuation(client, r.paths, r.binding.operation_id)
    assert result['operation_id'] == r.target
    assert continuation.pending_continuation(r.paths) is None


def test_missing_hold_is_not_success_without_derived_receipt(finalizer):
    module, r = finalizer
    with durable_state.installer_mutation_checkpoints(r.client.checkpoint):
        continuation.finish_continuation_hold(r.paths, r.restoration)
        with pytest.raises(ValueError):
            module.finalize_restoration_continuation(r.client, r.paths, r.target)
    assert not (r.root/'restoration-continuation-finalized.json').exists()


def test_durable_receipt_precedes_hold_retirement_and_crash_can_resume(finalizer, monkeypatch):
    module, r = finalizer
    original = continuation.finish_continuation_hold
    def crash(paths, cap):
        assert (r.root/'restoration-continuation-finalized.json').exists()
        assert continuation.pending_continuation(paths)['transaction_id'] == cap['transaction_id']
        raise OSError('simulated process failure after durable derived receipt')
    monkeypatch.setattr(continuation, 'finish_continuation_hold', crash)
    with durable_state.installer_mutation_checkpoints(r.client.checkpoint):
        with pytest.raises(OSError): module.finalize_restoration_continuation(r.client, r.paths, r.target)
    receipt = (r.root/'restoration-continuation-finalized.json').read_bytes()
    monkeypatch.setattr(continuation, 'finish_continuation_hold', original)
    with durable_state.installer_mutation_checkpoints(r.client.checkpoint):
        module.finalize_restoration_continuation(r.client, r.paths, r.target)
    assert (r.root/'restoration-continuation-finalized.json').read_bytes() == receipt
    assert continuation.pending_continuation(r.paths) is None


@pytest.mark.parametrize('defect', ['grant-previous', 'private-current', 'checkpoint', 'recovery-account', 'derived-proof'])
def test_additional_proof_failures_cannot_clear_hold(finalizer, monkeypatch, defect):
    module, r = finalizer
    if defect == 'grant-previous':
        leaf = continuation._grant_path(r.paths, r.target)
        value = json.loads(leaf.read_text()); value['selection']['previous_sha256'] = '0'*64
        with durable_state.installer_mutation_checkpoints(lambda: None): r.write(leaf, value)
    elif defect == 'private-current':
        from pc_agent.platform.windows import installer_data_security
        monkeypatch.setattr(installer_data_security, 'verify_preserved', lambda *_: (_ for _ in ()).throw(ValueError('RECOVERY_REQUIRED')))
    elif defect == 'checkpoint':
        r.client.checkpoint = lambda: (_ for _ in ()).throw(ValueError('OWNER_AUTH_FAILED'))
    elif defect == 'recovery-account':
        r.client.capability['owner'] = {**r.client.capability['owner'], 'sid': 'S-1-5-21-123'}
    else:
        with durable_state.installer_mutation_checkpoints(r.client.checkpoint):
            module.finalize_restoration_continuation(r.client, r.paths, r.target)
        leaf = r.root/'restoration-continuation-finalized.json'
        value = json.loads(leaf.read_text()); value['proof']['grant_sha256'] = '0'*64
        with durable_state.installer_mutation_checkpoints(lambda: None):
            r.write(leaf, value)
            continuation.begin_continuation_hold(r.paths, r.restoration)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        with pytest.raises(ValueError): module.finalize_restoration_continuation(r.client, r.paths, r.target)
    assert continuation.pending_continuation(r.paths)['transaction_id'] == r.target


def test_recovery_code_must_match_its_own_msi_helper(restored, monkeypatch):
    from pc_agent.platform.windows import staged_restoration_continuation as module, installer_transaction_bridge as bridge, msi_inventory
    r = restored
    cap = r.client.capability
    raw = b'new174 signed helper model'
    cap['helper_sha256'] = hashlib.sha256(raw).hexdigest()
    r.client.identity = SimpleNamespace(value={'hash': cap['helper_sha256']})
    monkeypatch.setattr(bridge, '_read_capability', lambda *_: cap)
    monkeypatch.setattr(bridge, '_request_data', lambda *_: {'package_path': r.root/'runner174.msi'})
    monkeypatch.setattr(msi_inventory, 'read_expected_package', lambda *_: SimpleNamespace(identity=SimpleNamespace(source_revision=cap['package']['source_revision'])))
    monkeypatch.setattr(msi_inventory, 'read_binary', lambda *_a, **_kw: raw)
    module._runner_authority(r.client, r.paths, r.record)
    monkeypatch.setattr(msi_inventory, 'read_binary', lambda *_a, **_kw: b'old172 or foreign helper')
    with pytest.raises(ValueError): module._runner_authority(r.client, r.paths, r.record)


def test_future_canonical_parent_finalizes_old172_hold_after_terminal_proof(finalizer, monkeypatch):
    from datetime import UTC, datetime
    from pc_agent.platform.windows import staged_foundation_rollback as rollback
    module, r = finalizer
    monkeypatch.setattr(rollback, '_assert_quiescent', lambda *_: None)
    parent = SimpleNamespace(phase='verify-foundation-rollback', capability=r.control, checkpoint=lambda: None)
    before = (r.paths.current_path.read_bytes(), r.paths.previous_path.read_bytes())
    with durable_state.installer_mutation_checkpoints(parent.checkpoint):
        state._write(r.paths, replace(r.record, phase='rolling-back', switched_at=datetime.now(UTC)))
        r.write(r.root/'plan.json', {**r.plan, 'phase': 'native-committed'})
        rollback.verify_foundation_rollback(r.paths, r.binding.operation_id, continuation_client=parent)
    assert state.read_staged_update(r.paths).phase == 'rolled-back'
    assert continuation.pending_continuation(r.paths) is None
    assert (r.paths.current_path.read_bytes(), r.paths.previous_path.read_bytes()) == before
    assert (r.root/'restoration-continuation-finalized.json').is_file()


@pytest.mark.parametrize('defect', ['none', 'image', 'account', 'startup', 'delayed', 'pending'])
def test_restored_service_observation_is_read_only_and_requires_canonical_config(restored, monkeypatch, defect):
    import sys
    from pc_agent.platform.windows import staged_restoration_continuation as module
    r = restored
    specs = {'EndpointAgent': ('endpoint-agent-service.exe', '--agent-service', 'NT AUTHORITY\\LocalService', 2),
        'EndpointAgentUpdater': ('endpoint-agent-updater.exe', '--updater-service', 'LocalSystem', 3),
        'EndpointBrowserPolicy': ('EndpointBrowserPolicy.exe', '', 'LocalSystem', 2)}
    calls = []
    def opened(_manager, name, access):
        assert access == 5
        calls.append(name)
        return name
    def config(name):
        file, arg, account, startup = specs[name]
        image = '"' + str(r.paths.install_root/file) + '"' + (' '+arg if arg else '')
        if name == 'EndpointAgent':
            if defect == 'image': image = '"C:\\foreign.exe"'
            elif defect == 'account': account = 'LocalSystem'
            elif defect == 'startup': startup = 4
        return (16, startup, 1, image, '', 0, [], account, name)
    scm = SimpleNamespace(SC_MANAGER_CONNECT=1, SERVICE_QUERY_CONFIG=1, SERVICE_QUERY_STATUS=4,
        SERVICE_RUNNING=4, SERVICE_STOPPED=1, OpenSCManager=lambda *_: 'manager', OpenService=opened,
        QueryServiceConfig=config, QueryServiceConfig2=lambda *_: defect == 'delayed',
        QueryServiceStatus=lambda name: (16, 2 if defect == 'pending' else 4 if name != 'EndpointAgentUpdater' else 1),
        CloseServiceHandle=lambda *_: None)
    monkeypatch.setitem(sys.modules, 'win32service', scm)
    if defect == 'none':
        result = module._restored_services(r.paths, r.record)
        assert result['EndpointAgent']['state'] == 'running'
        assert result['EndpointAgentUpdater']['state'] == 'stopped'
        assert set(calls) == set(specs)
    else:
        with pytest.raises(ValueError): module._restored_services(r.paths, r.record)


@pytest.mark.parametrize('defect', ['none', 'top-fence', 'child-fence', 'compound', 'other-operation'])
def test_no_other_operation_gate_observes_native_and_ota_exclusion(restored, monkeypatch, defect):
    from pc_agent.platform.windows import staged_restoration_continuation as module, update_transaction, compound_upgrade_plan
    r = restored
    monkeypatch.setattr(fence, 'read_fence', lambda *_: {} if defect == 'top-fence' else None)
    monkeypatch.setattr(compound_upgrade_plan, 'has_active_upgrade', lambda *_: defect == 'compound')
    monkeypatch.setattr(update_transaction, 'active_update_state', lambda *_: 'pending' if defect == 'other-operation' else 'native-continuation-pending')
    if defect == 'child-fence':
        children = fence.state_root(r.paths)/'children'; children.mkdir(); fence.protect_state(children)
        child = children/str(uuid4()); child.mkdir(); fence.protect_state(child)
        (child/'transaction.json').write_text('{}'); fence.protect_state(child/'transaction.json')
    if defect == 'none':
        module._no_other_operations(r.paths, r.target, r.restoration['package'])
    else:
        with pytest.raises(ValueError): module._no_other_operations(r.paths, r.target, r.restoration['package'])
