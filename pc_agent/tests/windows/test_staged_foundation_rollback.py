"""Reverse native authority is restricted to one unaccepted staged binding."""
from contextlib import nullcontext
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from pc_agent.platform.windows import durable_state, installer_fence, staged_update_state as state
from pc_agent.tests.windows.test_staged_update_state import staged, begin, move, native_protected_root
from pc_agent.tests.windows.test_retained_storage import retained, promote


@pytest.fixture
def reverse(staged, monkeypatch):
    from pc_agent.platform.windows import staged_foundation_rollback as rollback
    from pc_agent.platform.windows import installation_provenance as provenance, msi_inventory as msi
    _, paths, binding, _ = staged
    begin(staged)
    for before, after in (('preparing', 'prepared'), ('prepared', 'switching'), ('switching', 'native-settled')):
        move(staged, before, after)
    move(staged, 'native-settled', 'trial', attempt_id=str(uuid4()))
    paths.current_path.write_text(json.dumps({'schema_version': 1, 'version': binding.candidate_version,
                                             'source_revision': binding.candidate_source_revision}))
    native_states = {binding.old_release['product_code']: -1, binding.new_release['product_code']: 5}
    packages = {role: SimpleNamespace(sha256=release['package_sha256'], product_code=release['product_code'], version=release['version'],
        package_code='{' + str(uuid4()).upper() + '}', features={}, components={}, files=())
        for role, release in (('old', binding.old_release), ('new', binding.new_release))}
    native = SimpleNamespace(product=lambda code: native_states[code],
        feature=lambda code, _: 3 if native_states[code] == 5 else -1,
        property=lambda code, key: next(getattr(pkg, 'version' if key == 'VersionString' else 'package_code')
                                     for pkg in packages.values() if pkg.product_code == code))
    monkeypatch.setattr(msi, 'NativeMsi', lambda: native)
    media = {role: {'relative_path': f"packages/{release['package_sha256']}/EndpointAgent.msi",
                    'release': release, 'helper_sha256': ('e' if role == 'old' else 'f') * 64}
             for role, release in (('old', binding.old_release), ('new', binding.new_release))}
    monkeypatch.setattr(rollback, '_resolve_media', lambda *_: media)
    monkeypatch.setattr(rollback, '_read_expected_media', lambda _paths, item: SimpleNamespace(package=
        packages['old' if item['release'] == binding.old_release else 'new'],
        identity=SimpleNamespace(version=item['release']['version'], source_revision=item['release']['source_revision'])))
    checks = []
    monkeypatch.setattr(rollback, '_verify_original_data', lambda *_: checks.append('data'))
    monkeypatch.setattr(rollback, '_forward_archives', lambda *_: ())
    monkeypatch.setattr(rollback, '_assert_quiescent', lambda *_: checks.append('stopped'))
    monkeypatch.setattr(provenance, 'verified_foundation_release', lambda _: binding.old_release
                        if native_states[binding.old_release['product_code']] == 5 else binding.new_release)
    def shared(_expected, _root):
        checks.append('shared-bytes')
        return nullcontext()
    monkeypatch.setattr(msi, 'verified_foundation_bytes', shared)
    old_identity = SimpleNamespace(version='3.2.121', source_revision='c' * 40,
                                  tree_sha256=binding.selected_tree_sha256_before)
    monkeypatch.setattr(provenance, '_inspect_core_value', lambda *_: SimpleNamespace(identity=old_identity))
    return rollback, paths, binding, native_states, media, checks


def prepare(reverse):
    rollback, paths, binding, *_ = reverse
    with durable_state.installer_mutation_checkpoints(lambda: None):
        return rollback.prepare_foundation_rollback(paths, binding.operation_id)


def settle(reverse):
    rollback, paths, binding, native, *_ = reverse
    native[binding.new_release['product_code']] = -1
    native[binding.old_release['product_code']] = 5
    with durable_state.installer_mutation_checkpoints(lambda: None):
        rollback.record_foundation_rollback_commit(paths, binding.operation_id)


def test_post_commit_rollback_preserves_native_ownership(reverse):
    rollback, paths, binding, native, _, checks = reverse
    plan = prepare(reverse)
    assert plan['phase'] == 'prepared'
    with durable_state.installer_mutation_checkpoints(lambda: None):
        with pytest.raises(ValueError): rollback.verify_foundation_rollback(paths, binding.operation_id)
    settle(reverse)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        rollback.verify_foundation_rollback(paths, binding.operation_id)
    assert native[binding.old_release['product_code']] == 5
    assert native[binding.new_release['product_code']] == -1
    assert paths.current_path.read_bytes() == binding.selected_before
    assert not paths.previous_path.exists()
    assert state.read_staged_update(paths).phase == 'rolled-back'
    assert {'data', 'shared-bytes', 'stopped'} <= set(checks)


def test_compensation_requires_stopped_candidate(reverse, monkeypatch):
    rollback, paths, _, _, _, checks = reverse
    def running(_): raise ValueError('UPDATE_IN_PROGRESS')
    monkeypatch.setattr(rollback, '_assert_quiescent', running)
    with pytest.raises(ValueError): prepare(reverse)
    assert state.read_staged_update(paths).phase == 'trial'
    assert not (installer_fence.state_root(paths) / 'staged-rollback').exists()
    assert checks == []


@pytest.mark.parametrize('defect', ['accepted', 'media', 'operation'])
def test_reverse_authority_cannot_authorize_arbitrary_downgrade(reverse, defect):
    rollback, paths, binding, _, media, _ = reverse
    if defect == 'accepted':
        with durable_state.installer_mutation_checkpoints(lambda: None):
            state.advance_staged_update(paths, binding.operation_id, 'trial', 'accepted')
    elif defect == 'media': media['old'] = {**media['old'], 'release': binding.new_release}
    with durable_state.installer_mutation_checkpoints(lambda: None):
        with pytest.raises(ValueError): rollback.prepare_foundation_rollback(paths,
            str(uuid4()) if defect == 'operation' else binding.operation_id)


def test_immutable_helper_receives_valid_legacy_layout(reverse, monkeypatch):
    rollback, paths, binding, *_ = reverse
    from pc_agent.platform.windows import retained_storage
    monkeypatch.setattr(rollback, '_forward_archives', lambda *_: ('a' * 64,))
    called = []
    def materialize(actual, archive, operation):
        assert actual is paths and operation == binding.operation_id
        assert state.read_staged_update(paths).phase == 'rolling-back'
        called.append(archive)
    monkeypatch.setattr(retained_storage, 'materialize_legacy_retention', materialize)
    prepare(reverse)
    assert called == ['a' * 64]


@pytest.mark.parametrize('defect', ['missing-old', 'new-still-present', 'shared-bytes', 'core'])
def test_incomplete_or_incompatible_compensation_never_claims_rollback(reverse, monkeypatch, defect):
    from pc_agent.platform.windows import installation_provenance as provenance, msi_inventory as msi
    rollback, paths, binding, native, *_ = reverse
    prepare(reverse)
    settle(reverse)
    if defect == 'missing-old': native[binding.old_release['product_code']] = -1
    elif defect == 'new-still-present': native[binding.new_release['product_code']] = 5
    else:
        def invalid(*_args, **_kwargs): raise ValueError('PROVENANCE_CONFLICT')
        monkeypatch.setattr(msi if defect == 'shared-bytes' else provenance,
                            'verified_foundation_bytes' if defect == 'shared-bytes' else '_inspect_core_value', invalid)
    before = paths.current_path.read_bytes()
    with durable_state.installer_mutation_checkpoints(lambda: None):
        with pytest.raises(ValueError): rollback.verify_foundation_rollback(paths, binding.operation_id)
    assert paths.current_path.read_bytes() == before
    assert state.read_staged_update(paths).phase == 'rolling-back'


def test_legacy79_catalog_requires_genuine_package_table(monkeypatch, tmp_path):
    from pc_agent.platform.windows import legacy_foundation_upgrade as legacy, msi_inventory as msi
    from pc_agent.platform.windows.runtime_identity import _LEGACY_MSI_CONTRACTS
    digest = legacy._SHARED79_PACKAGE
    contract = _LEGACY_MSI_CONTRACTS[digest]
    release = legacy.canonical_release({'schema_version': 'endpoint_windows_release_v1',
        'package_sha256': digest, 'product_code': legacy._PRODUCTS[digest], 'version': contract['version'],
        'source_revision': contract['source_revision'], 'initial_runtime_tree_sha256': contract['tree_sha256']})
    rows = legacy.rollback_foundation_catalog(release)
    assert len(rows) == 8
    files = [SimpleNamespace(name=row['file'], component=row['component'], path=row['path'], size=row['size']) for row in rows]
    package = SimpleNamespace(sha256=digest, product_code=release['product_code'], version=release['version'], files=files)
    monkeypatch.setattr(msi, 'read_package', lambda *_: package)
    expected = legacy.rollback_foundation_inventory(tmp_path / 'unexecuted.msi', release)
    assert expected.foundation_files == rows
    files[0].size += 1
    with pytest.raises(ValueError): legacy.rollback_foundation_inventory(tmp_path / 'unexecuted.msi', release)


@pytest.mark.parametrize('phase',['preparing','prepared','native-settled'])
def test_original_legacy_floor_is_scoped_to_captured_pair(staged, phase):
    from dataclasses import replace
    from pc_agent.platform.windows import staged_foundation_rollback as rollback, legacy_foundation_upgrade as legacy
    from pc_agent.platform.windows.runtime_identity import _LEGACY_MSI_CONTRACTS
    _, paths, binding, owner = staged
    digest = legacy._SHARED79_PACKAGE
    contract = _LEGACY_MSI_CONTRACTS[digest]
    old = legacy.canonical_release({'schema_version': 'endpoint_windows_release_v1',
        'package_sha256': digest, 'product_code': legacy._PRODUCTS[digest], 'version': contract['version'],
        'source_revision': contract['source_revision'], 'initial_runtime_tree_sha256': contract['tree_sha256']})
    raw = json.dumps({'version': '3.2.79'}).encode()
    binding = replace(binding, old_release=old, selected_before=raw,
                      selected_tree_sha256_before=contract['tree_sha256'])
    paths.current_path.write_bytes(raw)
    identity = SimpleNamespace(version='3.2.79', source_revision=contract['source_revision'],
                               tree_sha256=contract['tree_sha256'])
    with durable_state.installer_mutation_checkpoints(lambda: None):
        state.begin_staged_update(paths, binding, owner)
        for before, after in (('preparing','prepared'),('prepared','switching'),('switching','native-settled')):
            if state.read_staged_update(paths).phase == phase: break
            state.advance_staged_update(paths,binding.operation_id,before,after)
    assert rollback.original_foundation_runtime_allowed(paths, raw, identity, digest, '3.2.79')
    assert not rollback.original_foundation_runtime_allowed(paths, raw, identity, digest, '3.2.81')
    assert not rollback.original_foundation_runtime_allowed(paths, raw, identity, '0' * 64, '3.2.79')
    assert not rollback.original_foundation_runtime_allowed(paths, b'{"version":"3.2.79"}', identity, digest, '3.2.79')


@pytest.mark.parametrize('defect', ['none', 'owner', 'restore-package', 'session-replay', 'control-session', 'extra-restore'])
def test_reverse_roles_are_bound_to_fresh_exact_capabilities(reverse, monkeypatch, defect):
    from pc_agent.platform.windows import installer_transaction_bridge as bridge
    rollback, paths, binding, *_ = reverse
    prepare(reverse)
    owner = state.read_staged_update(paths).owner
    control_session, removal_session, restoration_session = (str(uuid4()) for _ in range(3))
    def cap(operation, package, helper, transaction, session, selected):
        return {'operation': operation, 'package': package, 'helper_sha256': helper, 'owner': owner,
                'transaction_id': transaction, 'session_id': session, 'selected': selected, 'previous': None,
                'recovery': False, 'uninstall_finalization': False}
    control = cap('install', binding.new_release, 'f' * 64, binding.operation_id, control_session, '2' * 64)
    control['staged_rollback'] = {'role': 'control', 'operation_id': binding.operation_id,
        'removal_session_id': removal_session, 'restoration_session_id': restoration_session}
    removal = cap('uninstall', binding.new_release, 'f' * 64, str(uuid4()), removal_session, '2' * 64)
    removal['staged_rollback'] = {'role': 'remove', 'operation_id': binding.operation_id,
                                 'control_session_id': control_session}
    restoration = cap('install', binding.old_release, 'e' * 64, str(uuid4()), restoration_session, '1' * 64)
    if defect == 'owner': removal['owner'] = {**owner, 'created': 99999}
    elif defect == 'restore-package': restoration['package'] = binding.new_release
    elif defect == 'session-replay': restoration['session_id'] = removal_session
    elif defect == 'control-session': removal['staged_rollback']['control_session_id'] = str(uuid4())
    elif defect == 'extra-restore': restoration['compound'] = {}
    caps = {control_session: control, removal_session: removal, restoration_session: restoration}
    monkeypatch.setattr(bridge, '_read_capability', lambda _paths, session: caps[session])
    monkeypatch.setattr(rollback, '_restoration_selection', lambda *_: {'selected': '1' * 64, 'previous': None})
    with durable_state.installer_mutation_checkpoints(lambda: None):
        if defect == 'none':
            receipt = rollback.bind_foundation_rollback_roles(paths, control)
            assert receipt['removal']['session_id'] == removal_session
            assert receipt['restoration']['session_id'] == restoration_session
        else:
            with pytest.raises(ValueError): rollback.bind_foundation_rollback_roles(paths, control)


def test_old_installer_receives_absent_candidate_directory_and_original_archive(retained, monkeypatch):
    from pc_agent.platform.windows import staged_foundation_rollback as rollback, runtime_identity
    _, paths, archive, identity, binding = retained
    target = promote(retained)
    ids = {item.path: (target / item.path).stat().st_ino for item in identity.files}
    monkeypatch.setattr(rollback, '_verify_original_data', lambda *_: None)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        record = state.advance_staged_update(paths, binding.operation_id, 'native-settled', 'rolling-back')
        media = {role: {'relative_path': f"packages/{release['package_sha256']}/EndpointAgent.msi",
                        'release': release, 'helper_sha256': ('e' if role == 'old' else 'f') * 64}
                 for role, release in (('old', binding.old_release), ('new', binding.new_release))}
        plan = {'schema_version': 1, 'operation_id': binding.operation_id, 'rollback_id': str(uuid4()),
                'binding_sha256': rollback._binding_hash(record), **media, 'archives': [archive.name],
                'phase': 'candidate-removed'}
        rollback._write(paths, record, plan)
        rollback.stage_original_runtime_for_restoration(paths, binding.operation_id)
        rollback.stage_original_runtime_for_restoration(paths, binding.operation_id)
    assert not target.exists()
    displaced = rollback._root(paths, binding.operation_id) / 'displaced-original-3.2.120'
    assert {item.path: (displaced / item.path).stat().st_ino for item in identity.files} == ids
    assert runtime_identity.verify_retained_archive(paths, archive.name).identity == identity
    assert not paths.current_path.exists()
    assert rollback.read_foundation_rollback(paths, binding.operation_id)['phase'] == 'restoring'


def test_lost_acceptance_reply_is_inspected_without_stopping_runtime(reverse):
    rollback, paths, binding, *_ = reverse
    record = state.read_staged_update(paths)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        state.advance_staged_update(paths, binding.operation_id, 'trial', 'accepted')
    sent = []
    cap = {'package': binding.new_release, 'operation': 'install', 'owner': record.owner,
           'transaction_id': binding.operation_id, 'session_id': str(uuid4()),
           'recovery': False, 'uninstall_finalization': False,
           'staged_rollback': {'role': 'control', 'operation_id': binding.operation_id,
               'removal_session_id': str(uuid4()), 'restoration_session_id': str(uuid4())}}
    def no_mutation(): pytest.fail('accepted candidate was stopped or modified')
    client = SimpleNamespace(capability=cap, phase='inspect-staged-state', checkpoint=no_mutation,
                             request=lambda action, payload: sent.append((action, payload)))
    result = rollback.execute_rollback_control_phase(client, paths)
    assert result['phase'] == 'accepted'
    assert sent == [('complete', result)]


def test_reverse_plan_rejects_boolean_schema(reverse):
    rollback, paths, binding, *_ = reverse
    plan = prepare(reverse)
    path = rollback._root(paths, binding.operation_id) / 'plan.json'
    path.write_text(json.dumps({**plan, 'schema_version': True}))
    with pytest.raises(ValueError): rollback.read_foundation_rollback(paths, binding.operation_id)


@pytest.mark.parametrize('committed', [True, False])
def test_candidate_fence_retirement_requires_actual_delayed_callback(reverse, monkeypatch, committed):
    from pc_agent.platform.windows import installer_transaction_bridge as bridge
    rollback, paths, binding, *_ = reverse
    prepare(reverse); settle(reverse)
    plan = rollback.read_foundation_rollback(paths, binding.operation_id)
    removal = {'transaction_id': str(uuid4()), 'session_id': str(uuid4()), 'operation': 'uninstall',
               'package': binding.new_release, 'selected': None, 'previous': None,
               'service_states': {'EndpointAgent': 'running', 'EndpointAgentUpdater': 'stopped'}}
    monkeypatch.setattr(rollback, 'read_bound_rollback_roles', lambda *_: {'removal': {'session_id': removal['session_id']}})
    monkeypatch.setattr(bridge, '_read_capability', lambda *_: removal)
    expected = rollback._read_expected_media(paths, plan['new'])
    payload = bridge._public_fence(expected, removal)
    payload['phase'] = 'msi-executing'
    payload['helpers'] = ([{'pid': 200, 'creation_time': 2000, 'image_sha256': 'f' * 64,
                           'phase': 'msi-executing', 'complete': True}] if committed else [])
    with durable_state.installer_mutation_checkpoints(lambda: None):
        root = installer_fence.state_root(paths)
        from pc_agent.platform.windows.installation_provenance import _archive_directory
        for name in ('children', removal['transaction_id'], plan['rollback_id']):
            root = _archive_directory(root, name)
        with installer_fence.child_fence(removal['transaction_id'], attempt_id=plan['rollback_id']):
            installer_fence.publish_fence(paths, payload)
            leaf = installer_fence.fence_path(paths)
            if committed:
                rollback._record_candidate_completion(paths, SimpleNamespace(capability=removal, phase='msi-complete'), plan)
        if committed:
            rollback.retire_candidate_removal_fence(paths, {'transaction_id': binding.operation_id})
            assert not leaf.exists()
            saved = json.loads((rollback._root(paths, binding.operation_id) / 'candidate-removal-completed.json').read_bytes())
            assert saved['native_fence'] == payload
            assert saved['kind'] == 'staged-candidate-removal'
        else:
            before = leaf.read_bytes()
            with pytest.raises(ValueError): rollback.retire_candidate_removal_fence(paths, {'transaction_id': binding.operation_id})
            assert leaf.read_bytes() == before


def test_staged_successors_admit_genuine79_without_rewriting_history():
    from pc_agent.platform.windows import runtime_identity
    digest = '2f7d778799f1e32645af7936dfaf3f090d6ad4df5bb883827ea8a0a5d859f72a'
    assert runtime_identity.legacy_foundation_compatible(digest,'3.2.122')
    assert not runtime_identity.legacy_foundation_compatible('0'*64,'3.2.122')
    assert runtime_identity.legacy_foundation_compatible(digest,'3.2.123')
    assert runtime_identity.legacy_foundation_compatible(digest,'3.2.124')
    assert runtime_identity.legacy_foundation_compatible(digest,'3.2.125')
    assert not runtime_identity.legacy_foundation_compatible(digest,'3.2.126')
    assert runtime_identity._LEGACY_MSI_CONTRACTS[digest]['approved_foundations'] == ('3.2.82',)


from pc_agent.tests.windows.test_installer_data_security import operation


def test_pre_switch_recovery_rechecks_prepared_capture_without_rebaselining(operation, monkeypatch):
    from pc_agent.platform.windows import staged_foundation_rollback as rollback, installer_data_security as data
    paths, request = operation
    data.prepare(paths,request)
    capture = data._transaction_root(paths,request) / 'data-root-before.json'
    before = capture.read_bytes()
    monkeypatch.setattr(rollback,'_capture_request',lambda *_:request)
    rollback._verify_original_data(paths,SimpleNamespace(phase='preparing'))
    rollback._verify_original_data(paths,SimpleNamespace(phase='prepared'))
    assert capture.read_bytes() == before
    monkeypatch.setattr(data,'_snapshot',lambda *_:{'root':None,'leaves':{'different':None}})
    with pytest.raises(ValueError): rollback._verify_original_data(paths,SimpleNamespace(phase='prepared'))


def test_forward_archives_adapts_data_capture_to_provenance_request(staged, monkeypatch):
    from pc_agent.platform.windows import staged_foundation_rollback as rollback
    from pc_agent.platform.windows import installation_provenance as provenance, msi_inventory
    _, paths, binding, _ = staged
    begin(staged)
    record = state.read_staged_update(paths)
    request = {'package_path': paths.install_root / 'fixture.msi', 'release': binding.new_release,
               'transaction_id': binding.operation_id, 'selected': 'a' * 64, 'previous': 'b' * 64,
               'session_id': str(uuid4()), 'recovery': False}
    monkeypatch.setattr(rollback, '_capture_request', lambda *_: request)
    monkeypatch.setattr(msi_inventory, 'read_expected_package', lambda *_: object())
    def read_plan(_root, actual, _expected):
        assert set(actual) == {'package_path', 'release', 'transaction_id', 'selected', 'previous'}
        return {'current_before': binding.selected_before.hex(),
                'previous_before': binding.previous_before.hex() if binding.previous_before else None, 'archives': ['d' * 64]}
    monkeypatch.setattr(provenance, '_read_plan', read_plan)
    assert rollback._forward_archives(paths, record) == ('d' * 64,)
