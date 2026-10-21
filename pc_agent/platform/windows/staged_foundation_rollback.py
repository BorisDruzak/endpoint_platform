"""Exact reverse plans for unaccepted candidates; native execution stays in owner."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from uuid import uuid4, UUID

from endpoint_contracts.runtime_payload import read_json
from . import durable_state, installer_fence as fence, staged_update_state as state
from . import installation_provenance as provenance, msi_inventory as msi

_LIMIT = 32768
_FIELDS = {'schema_version', 'operation_id', 'rollback_id', 'binding_sha256',
           'old', 'new', 'archives', 'phase'}
_PHASES = {'prepared', 'candidate-removed', 'restoring', 'native-committed', 'complete'}


def _fail():
    raise ValueError('PROVENANCE_CONFLICT')


def _binding_hash(record):
    return hashlib.sha256(json.dumps(state._binding_value(record.binding),
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _operation(paths, operation_id):
    record = state.read_staged_update(paths)
    if (record is None or record.binding.operation_id != operation_id
            or record.phase not in {'switching', 'native-settled', 'trial', 'rolling-back', 'recovery-required'}):
        _fail()
    return record


def _root(paths, operation_id, *, create=False):
    if str(UUID(operation_id)) != operation_id:
        _fail()
    root = fence.state_root(paths) / 'staged-rollback' / operation_id
    if create:
        from .installation_provenance import _archive_directory
        _archive_directory(_archive_directory(root.parent.parent, root.parent.name), root.name)
    return root


def _media_path(paths, item):
    relative = item['relative_path']
    if not isinstance(relative, str) or not re.fullmatch(
            r'(packages/[0-9a-f]{64}/EndpointAgent\.msi|retained/[0-9a-f]{64}/package\.msi)', relative):
        _fail()
    path = fence.state_root(paths) / Path(relative)
    fence.assert_state_security(path)
    return path


def _read_expected_media(paths, item):
    path = _media_path(paths, item)
    from .legacy_foundation_upgrade import canonical_release
    if canonical_release(item['release']) is not None:
        # Legacy Foundation catalogs must be extracted from their genuine pinned
        # media and reviewed explicitly, never inferred from installed bytes.
        from .legacy_foundation_upgrade import rollback_foundation_inventory
        return rollback_foundation_inventory(path, item['release'])
    return msi.read_expected_package(path, item['release'])


def _capture_request(paths, record):
    from . import installer_data_security as data
    from .installer_transaction_bridge import _read_capability, _request_data
    request = {'transaction_id': record.binding.operation_id,
               'session_id': record.binding.operation_id, 'release': record.binding.new_release, 'recovery': True}
    capture = data._read(paths, request)
    phases = {'prepared', 'configured'} if record.phase in {'preparing', 'prepared', 'switching'} else {'configured'}
    if capture['phase'] not in phases:
        _fail()
    cap = _read_capability(paths, capture['binding']['session_id'])
    if (cap['transaction_id'] != record.binding.operation_id or cap['package'] != record.binding.new_release
            or cap['operation'] != 'install' or cap['recovery'] or cap['owner'] != record.owner):
        _fail()
    return {**_request_data(paths, cap), 'session_id': cap['session_id'], 'recovery': False}


def _verify_original_data(paths, record):
    from . import installer_data_security as data
    request = _capture_request(paths, record)
    if record.phase in {"preparing", "prepared"}:
        data.before_native(paths, request)
    else:
        data.verify_preserved(paths, request)


def _forward_archives(paths, record):
    capture = _capture_request(paths, record)
    # Data capture also carries its immutable source session and recovery bit.
    # The provenance plan consumes its original, narrower request contract.
    request = {key: capture[key] for key in
               ('package_path', 'release', 'transaction_id', 'selected', 'previous')}
    expected = provenance._expected_request(request)
    root = fence.state_root(paths) / 'provenance' / record.binding.operation_id
    plan = provenance._read_plan(root, request, expected)
    if (plan['current_before'] != record.binding.selected_before.hex()
            or plan['previous_before'] != (record.binding.previous_before.hex() if record.binding.previous_before else None)):
        _fail()
    return tuple(plan['archives'])


def _resolve_media(paths, record):
    from .runtime_identity import verify_retained_archive
    from .legacy_foundation_upgrade import canonical_release
    result = {}
    for role, release in (('old', record.binding.old_release), ('new', record.binding.new_release)):
        relative = f"packages/{release['package_sha256']}/EndpointAgent.msi"
        path = fence.state_root(paths) / relative
        if not path.exists():
            matches = []
            for archive in _forward_archives(paths, record):
                retained = verify_retained_archive(paths, archive)
                if retained.record['package']['sha256'] == release['package_sha256']:
                    matches.append(f'retained/{archive}/package.msi')
            if len(matches) != 1:
                _fail()
            relative = matches[0]
        item = {'relative_path': relative, 'release': release, 'helper_sha256': None}
        path = _media_path(paths, item)
        _read_expected_media(paths, item)
        if canonical_release(release) is None:
            item['helper_sha256'] = hashlib.sha256(msi.read_binary(path, 'EndpointInstallerHost',
                maximum=128 * 1024 * 1024)).hexdigest()
        result[role] = item
    return result


def _assert_quiescent(paths):
    from .installer_transaction_bridge import InstallerServices
    with InstallerServices(paths, include_browser=True) as services:
        services.snapshot()


def _validate_plan(paths, record, plan):
    if (not isinstance(plan, dict) or set(plan) != _FIELDS or type(plan['schema_version']) is not int or plan['schema_version'] != 1
            or plan['operation_id'] != record.binding.operation_id
            or str(UUID(plan['rollback_id'])) != plan['rollback_id']
            or plan['binding_sha256'] != _binding_hash(record) or plan['phase'] not in _PHASES
            or not isinstance(plan['archives'], list) or len(plan['archives']) > 2
            or len(set(plan['archives'])) != len(plan['archives'])
            or any(not isinstance(item, str) or not re.fullmatch('[0-9a-f]{64}', item) for item in plan['archives'])):
        _fail()
    for role, release in (('old', record.binding.old_release), ('new', record.binding.new_release)):
        item = plan[role]
        if (not isinstance(item, dict) or set(item) != {'relative_path', 'release', 'helper_sha256'}
                or item['release'] != release
                or (item['helper_sha256'] is not None and (
                    not isinstance(item['helper_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', item['helper_sha256'])))):
            _fail()
        if not isinstance(item['relative_path'], str) or not re.fullmatch(
                r'(packages/[0-9a-f]{64}/EndpointAgent\.msi|retained/[0-9a-f]{64}/package\.msi)', item['relative_path']):
            _fail()
    if plan['new']['helper_sha256'] is None:
        _fail()
    return plan


def read_foundation_rollback(paths, operation_id):
    record = _operation(paths, operation_id)
    path = _root(paths, operation_id) / 'plan.json'
    fence.assert_state_security(path, secret=True)
    return _validate_plan(paths, record, read_json(provenance._read(path, _LIMIT), _LIMIT))


def _write(paths, record, plan):
    durable_state.installer_mutation_checkpoint(required=True)
    _validate_plan(paths, record, plan)
    root = _root(paths, record.binding.operation_id, create=True)
    durable_state.write_json_atomic(root / 'plan.json', plan, trusted_root=root, max_bytes=_LIMIT,
                                    protect=lambda path: fence.protect_state(path, secret=True))
    return plan


def plan_identity_sha256(plan):
    value = {key: value for key, value in plan.items() if key != 'phase'}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_rollback_capability_shape(cap):
    extra = cap.get('staged_rollback')
    if (not isinstance(extra, dict) or cap['recovery'] or cap['uninstall_finalization']
            or 'compound' in cap or 'recovery_parent' in cap):
        _fail()
    if str(UUID(extra['operation_id'])) != extra['operation_id']:
        _fail()
    if extra.get('role') == 'control':
        if (set(extra) != {'role', 'operation_id', 'removal_session_id', 'restoration_session_id'}
                or cap['operation'] != 'install' or cap['transaction_id'] != extra['operation_id']):
            _fail()
        sessions = [cap['session_id'], extra['removal_session_id']]
        if extra['restoration_session_id'] is not None:
            sessions.append(extra['restoration_session_id'])
    elif extra.get('role') == 'remove':
        if (set(extra) != {'role', 'operation_id', 'control_session_id'} or cap['operation'] != 'uninstall'
                or cap['transaction_id'] == extra['operation_id']):
            _fail()
        sessions = [cap['session_id'], extra['control_session_id']]
    else:
        _fail()
    if len(set(sessions)) != len(sessions) or any(str(UUID(value)) != value for value in sessions):
        _fail()


def _restoration_selection(paths, record):
    if state._selector(record.binding.selected_before)['version'] == record.binding.old_release['version']:
        return {'selected': None, 'previous': None}
    original = _capture_request(paths, record)
    return {'selected': original['selected'], 'previous': None}


def _role_projection(cap):
    from .installer_transaction_bridge import _identity
    from .compound_upgrade_plan import _release
    _identity(cap['owner'])
    _release(cap['package'])
    if (cap['recovery'] or cap['uninstall_finalization'] or 'compound' in cap or 'recovery_parent' in cap
            or str(UUID(cap['transaction_id'])) != cap['transaction_id']
            or str(UUID(cap['session_id'])) != cap['session_id']
            or not re.fullmatch('[0-9a-f]{64}', cap['helper_sha256'])):
        _fail()
    return {key: cap[key] for key in ('transaction_id', 'session_id', 'package', 'helper_sha256',
                                      'operation', 'selected', 'previous')}


def _role_receipt(paths, control):
    from .staged_recovery import owner_authorized
    from .installer_transaction_bridge import _read_capability
    validate_rollback_capability_shape(control)
    extra = control['staged_rollback']
    if extra['role'] != 'control':
        _fail()
    record = _operation(paths, extra['operation_id'])
    plan = read_foundation_rollback(paths, record.binding.operation_id)
    if (record.phase != 'rolling-back' or not owner_authorized(paths, record, control['owner'])
            or control['package'] != record.binding.new_release
            or control['helper_sha256'] != plan['new']['helper_sha256']):
        _fail()
    removal = _read_capability(paths, extra['removal_session_id'])
    validate_rollback_capability_shape(removal)
    if (removal['staged_rollback'] != {'role': 'remove', 'operation_id': extra['operation_id'],
                                     'control_session_id': control['session_id']}
            or removal['session_id'] != extra['removal_session_id'] or removal['owner'] != control['owner']
            or removal['package'] != control['package'] or removal['helper_sha256'] != control['helper_sha256']):
        _fail()
    restoration = None
    if plan['old']['helper_sha256'] is not None:
        if extra['restoration_session_id'] is None:
            _fail()
        restoration = _read_capability(paths, extra['restoration_session_id'])
        selection = _restoration_selection(paths, record)
        if (restoration['session_id'] != extra['restoration_session_id'] or restoration['owner'] != control['owner']
                or restoration['operation'] != 'install' or restoration['package'] != plan['old']['release']
                or restoration['helper_sha256'] != plan['old']['helper_sha256'] or 'staged_rollback' in restoration
                or any(restoration[key] != selection[key] for key in ('selected', 'previous'))):
            _fail()
    elif extra['restoration_session_id'] is not None:
        _fail()
    caps = [control, removal] + ([restoration] if restoration is not None else [])
    projections = [_role_projection(cap) for cap in caps]
    if any(len({item[key] for item in projections}) != len(projections) for key in ('transaction_id', 'session_id')):
        _fail()
    return {'schema_version': 1, 'owner': control['owner'], 'plan_sha256': plan_identity_sha256(plan),
            'control': projections[0], 'removal': projections[1],
            'restoration': projections[2] if len(projections) == 3 else None}


def bind_foundation_rollback_roles(paths, control):
    durable_state.installer_mutation_checkpoint(required=True)
    receipt = _role_receipt(paths, control)
    extra = control['staged_rollback']
    root = _root(paths, extra['operation_id'])
    path = root / ('roles-' + control['session_id'] + '.json')
    if path.exists():
        fence.assert_state_security(path, secret=True)
        if read_json(provenance._read(path, _LIMIT), _LIMIT) != receipt:
            _fail()
        return receipt
    durable_state.write_json_atomic(path, receipt, trusted_root=root, max_bytes=_LIMIT,
                                    protect=lambda leaf: fence.protect_state(leaf, secret=True))
    return receipt


def read_bound_rollback_roles(paths, cap):
    from .installer_transaction_bridge import _read_capability
    validate_rollback_capability_shape(cap)
    extra = cap['staged_rollback']
    control = cap if extra['role'] == 'control' else _read_capability(paths, extra['control_session_id'])
    desired = _role_receipt(paths, control)
    path = _root(paths, extra['operation_id']) / ('roles-' + control['session_id'] + '.json')
    fence.assert_state_security(path, secret=True)
    if read_json(provenance._read(path, _LIMIT), _LIMIT) != desired:
        _fail()
    role = 'control' if extra['role'] == 'control' else 'removal'
    if _role_projection(cap) != desired[role]:
        _fail()
    return desired


def stage_original_runtime_for_restoration(paths, operation_id):
    """Make the genuine old MSI's candidate namespace available, preserving bytes."""
    from .runtime_identity import verify_retained_archive
    from .retained_storage import materialize_legacy_retention
    durable_state.installer_mutation_checkpoint(required=True)
    record = _operation(paths, operation_id)
    plan = read_foundation_rollback(paths, operation_id)
    native = msi.NativeMsi()
    if (record.phase != 'rolling-back' or plan['phase'] not in {'candidate-removed', 'restoring'}
            or any(native.product(release['product_code']) != -1 for release in
                   (record.binding.old_release, record.binding.new_release))):
        _fail()
    _verify_original_data(paths, record)
    if plan['phase'] == 'candidate-removed':
        _verify_original_core(paths, record)
        plan = _write(paths, record, {**plan, 'phase': 'restoring'})
    for archive_id in plan['archives']:
        materialize_legacy_retention(paths, archive_id, operation_id)
        retained = verify_retained_archive(paths, archive_id)
        if retained.identity.version != record.binding.old_release['version']:
            continue
        source = paths.versions_root / retained.identity.version
        destination = _root(paths, operation_id) / ('displaced-original-' + retained.identity.version)
        if source.exists() and destination.exists():
            _fail()
        current = source if source.exists() else destination
        if not current.exists():
            _fail()
        fence.assert_state_security(current)
        identity = provenance._verify_retention_payload(current, retained.record['manifest'],
            retained.record['package']['sha256'], retained.record['compatibility_foundations'],
            excluded=frozenset({'.endpoint-retained-msi.json'}))
        if identity != retained.identity:
            _fail()
        if current == source:
            fence.assert_namespace_security(destination.parent, include_self=True)
            durable_state.durable_rename_directory(source, destination, trusted_root=paths.install_root.parent)
    durable_state.durable_unlink(paths.previous_path, trusted_root=paths.install_root, missing_ok=True)
    binding = record.binding
    selector = state._selector(binding.selected_before)
    if selector['version'] == binding.old_release['version']:
        durable_state.durable_unlink(paths.current_path, trusted_root=paths.install_root, missing_ok=True)
    else:
        core = provenance._inspect_core_value(paths, binding.selected_before, selector, binding.old_release['version'])
        if core.identity.tree_sha256 != binding.selected_tree_sha256_before:
            _fail()
        durable_state.write_bytes_atomic(paths.current_path, binding.selected_before, trusted_root=paths.install_root,
                                        max_bytes=4096, protect=fence.protect_state)
    return _restoration_selection(paths, record)


def record_foundation_candidate_removed(paths, control):
    from .installer_transaction_bridge import _read_capability, _request_data, _public_fence
    record = _operation(paths, control['transaction_id'])
    plan = read_foundation_rollback(paths, record.binding.operation_id)
    roles = read_bound_rollback_roles(paths, control)
    removal = _read_capability(paths, roles['removal']['session_id'])
    if plan['phase'] not in {'prepared', 'candidate-removed', 'restoring'}:
        _fail()
    native = msi.NativeMsi()
    if any(native.product(release['product_code']) != -1 for release in
           (record.binding.old_release, record.binding.new_release)):
        _fail()
    expected = _read_expected_media(paths, plan['new'])
    with fence.child_fence(removal['transaction_id'], attempt_id=plan['rollback_id']):
        observed = fence.read_fence(paths)
        wanted = _public_fence(expected, removal)
        if (observed is None or observed['phase'] != 'msi-executing' or observed['startup_restored']
                or any(observed[key] != wanted[key] for key in
                       ('transaction_id', 'operation', 'package', 'selected', 'previous', 'service_states'))):
            _fail()
    _verify_original_data(paths, record)
    if plan['phase'] == 'prepared':
        plan = _write(paths, record, {**plan, 'phase': 'candidate-removed'})
    provenance.retire_maintenance_authority(paths, _request_data(paths, removal), 'uninstall')
    selection = stage_original_runtime_for_restoration(paths, record.binding.operation_id)
    if roles['restoration'] is not None and any(
            roles['restoration'][key] != selection[key] for key in ('selected', 'previous')):
        _fail()
    return selection


def retire_candidate_removal_fence(paths, control):
    from .installer_transaction_bridge import _read_capability, _public_fence
    roles = read_bound_rollback_roles(paths, control)
    record = _operation(paths, control['transaction_id'])
    plan = read_foundation_rollback(paths, record.binding.operation_id)
    if plan['phase'] != 'native-committed':
        _fail()
    _assert_quiescent(paths)
    _verify_native_restore(paths, record, plan)
    _verify_original_core(paths, record)
    _verify_original_data(paths, record)
    removal = _read_capability(paths, roles['removal']['session_id'])
    expected = _read_expected_media(paths, plan['new'])
    root = _root(paths, record.binding.operation_id)
    archived = root / 'candidate-removal-completed.json'
    with fence.child_fence(removal['transaction_id'], attempt_id=plan['rollback_id']):
        observed = fence.read_fence(paths)
        if observed is None:
            fence.assert_state_security(archived, secret=True)
            saved = read_json(provenance._read(archived, _LIMIT), _LIMIT)
        else:
            saved = {'schema_version': 1, 'kind': 'staged-candidate-removal',
                     'operation_id': record.binding.operation_id, 'plan_sha256': plan_identity_sha256(plan),
                     'native_fence': observed}
        if (not isinstance(saved, dict) or set(saved) != {'schema_version', 'kind', 'operation_id', 'plan_sha256', 'native_fence'}
                or type(saved['schema_version']) is not int or saved['schema_version'] != 1 or saved['kind'] != 'staged-candidate-removal'
                or saved['operation_id'] != record.binding.operation_id or saved['plan_sha256'] != plan_identity_sha256(plan)):
            _fail()
        original = saved['native_fence']
        fence.validate_fence(original)
        wanted = _public_fence(expected, removal)
        if (original['phase'] != 'msi-executing' or original['startup_restored']
                or not any(item['phase'] == 'msi-executing' and item['complete'] for item in original['helpers'])
                or any(original[key] != wanted[key] for key in
                       ('transaction_id', 'operation', 'package', 'selected', 'previous', 'service_states'))):
            _fail()
        callback = root / ('candidate-callback-' + removal['session_id'] + '.json')
        fence.assert_state_security(callback, secret=True)
        if read_json(provenance._read(callback, _LIMIT), _LIMIT) != _candidate_completion(removal, plan, original):
            _fail()
        if archived.exists():
            fence.assert_state_security(archived, secret=True)
            if read_json(provenance._read(archived, _LIMIT), _LIMIT) != saved:
                _fail()
        else:
            durable_state.write_json_atomic(archived, saved, trusted_root=root, max_bytes=_LIMIT,
                                            protect=lambda leaf: fence.protect_state(leaf, secret=True))
        durable_state.durable_unlink(fence.fence_path(paths), trusted_root=fence.fence_path(paths).parent, missing_ok=True)


def _candidate_completion(capability, plan, observed):
    return {'schema_version': 1, 'session_id': capability['session_id'],
            'transaction_id': capability['transaction_id'], 'plan_sha256': plan_identity_sha256(plan),
            'phase': 'msi-complete', 'native_fence': observed}


def _record_candidate_completion(paths, client, plan):
    if client.phase != 'msi-complete':
        _fail()
    observed = fence.read_fence(paths)
    if observed is None or observed['phase'] != 'msi-executing':
        _fail()
    root = _root(paths, plan['operation_id'])
    leaf = root / ('candidate-callback-' + client.capability['session_id'] + '.json')
    value = _candidate_completion(client.capability, plan, observed)
    if leaf.exists():
        fence.assert_state_security(leaf, secret=True)
        if read_json(provenance._read(leaf, _LIMIT), _LIMIT) != value:
            _fail()
    else:
        durable_state.write_json_atomic(leaf, value, trusted_root=root, max_bytes=_LIMIT,
                                        protect=lambda path: fence.protect_state(path, secret=True))


def execute_candidate_removal_phase(client, paths, **kwargs):
    from . import installer_transaction_bridge as bridge
    cap = client.capability
    roles = read_bound_rollback_roles(paths, cap)
    plan = read_foundation_rollback(paths, cap['staged_rollback']['operation_id'])
    if (cap['staged_rollback']['role'] != 'remove' or roles['removal']['session_id'] != cap['session_id']
            or client.phase not in {'prepare', 'msi-preflight', 'msi-enter', 'msi-complete'}):
        _fail()
    with durable_state.installer_mutation_checkpoints(client.checkpoint):
        root = fence.state_root(paths)
        for name in ('children', cap['transaction_id'], plan['rollback_id']):
            root = provenance._archive_directory(root, name)
    with fence.child_fence(cap['transaction_id'], attempt_id=plan['rollback_id']):
        result = bridge._execute_authorized_phase(client, paths, complete=False, **kwargs)
        if client.phase == 'msi-complete':
            with durable_state.installer_mutation_checkpoints(client.checkpoint):
                _record_candidate_completion(paths, client, plan)
        client.request('complete', result)
        return result


def execute_rollback_control_phase(client, paths):
    from .staged_recovery import owner_authorized
    cap = client.capability
    validate_rollback_capability_shape(cap)
    extra = cap['staged_rollback']
    record = state.read_staged_update(paths)
    if (extra['role'] != 'control' or record is None or not owner_authorized(paths, record, cap['owner'])
            or cap['transaction_id'] != record.binding.operation_id or cap['package'] != record.binding.new_release):
        _fail()
    operation = record.binding.operation_id
    if client.phase == 'inspect-staged-state':
        result = {'result': 'staged-state', 'phase': record.phase, 'operation_id': operation,
                  'old_release': record.binding.old_release}
        if record.phase in {'switching', 'native-settled', 'trial'}:
            inspected = provenance.inspect_installed_core(paths, resulting_foundation=record.binding.new_release['version'])
            result.update(selected=inspected.current.digest if inspected.current else None,
                          previous=inspected.previous.digest if inspected.previous else None)
    else:
        with durable_state.installer_mutation_checkpoints(client.checkpoint):
            if client.phase == 'prepare-foundation-rollback':
                plan = prepare_foundation_rollback(paths, operation)
                result = {'result': 'rollback-prepared', 'operation_id': operation, 'plan': plan,
                          'plan_sha256': plan_identity_sha256(plan),
                          'restoration_selection': _restoration_selection(paths, record)}
            elif client.phase == 'bind-foundation-rollback-roles':
                receipt = bind_foundation_rollback_roles(paths, cap)
                result = {'result': 'rollback-roles-bound', 'operation_id': operation,
                          'plan_sha256': receipt['plan_sha256']}
            else:
                read_bound_rollback_roles(paths, cap)
                if client.phase == 'rollback-candidate-removed':
                    selection = record_foundation_candidate_removed(paths, cap)
                    result = {'result': 'rollback-candidate-removed', 'operation_id': operation, **selection}
                elif client.phase == 'rollback-native-committed':
                    record_foundation_rollback_commit(paths, operation)
                    result = {'result': 'rollback-native-committed', 'operation_id': operation}
                elif client.phase == 'verify-foundation-rollback':
                    retire_candidate_removal_fence(paths, cap)
                    verify_foundation_rollback(paths, operation)
                    result = {'result': 'rolled-back', 'operation_id': operation}
                else:
                    _fail()
    client.request('complete', result)
    return result


def prepare_foundation_rollback(paths, operation_id):
    durable_state.installer_mutation_checkpoint(required=True)
    record = _operation(paths, operation_id)
    _assert_quiescent(paths)
    _verify_original_data(paths, record)
    if record.phase == 'rolling-back':
        plan = read_foundation_rollback(paths, operation_id)
    else:
        media = _resolve_media(paths, record)
        for role, release in (('old', record.binding.old_release), ('new', record.binding.new_release)):
            if media[role]['release'] != release:
                _fail()
        native = msi.NativeMsi()
        if (native.product(record.binding.old_release['product_code']) != -1
                or native.product(record.binding.new_release['product_code']) != 5
                or provenance.verified_foundation_release(paths) != record.binding.new_release):
            _fail()
        _verify_original_core(paths, record)
        archives = list(_forward_archives(paths, record))
        plan = {'schema_version': 1, 'operation_id': operation_id, 'rollback_id': str(uuid4()),
                'binding_sha256': _binding_hash(record), 'old': media['old'], 'new': media['new'],
                'archives': archives, 'phase': 'prepared'}
        _validate_plan(paths, record, plan)
        if record.phase == 'recovery-required':
            _fail()  # A fresh recovery owner must classify native settlement first.
        record = state.advance_staged_update(paths, operation_id, record.phase, 'rolling-back')
        _write(paths, record, plan)
    from .retained_storage import materialize_legacy_retention
    for archive in plan['archives']:
        materialize_legacy_retention(paths, archive, operation_id)
    return plan


def _verify_native_restore(paths, record, plan):
    old = _read_expected_media(paths, plan['old'])
    new = _read_expected_media(paths, plan['new'])
    msi.verify_replaced_product(new.package, old.package, paths.install_root)
    if provenance.verified_foundation_release(paths) != record.binding.old_release:
        _fail()
    from .legacy_foundation_upgrade import canonical_release, verified_rollback_foundation_bytes
    context = (verified_rollback_foundation_bytes(paths, old) if canonical_release(plan['old']['release']) is not None
               else msi.verified_foundation_bytes(old, paths.install_root))
    with context:
        pass


def _verify_original_core(paths, record):
    binding = record.binding
    pairs = [(binding.selected_before, binding.selected_tree_sha256_before)]
    if binding.previous_before is not None:
        pairs.append((binding.previous_before, binding.previous_tree_sha256_before))
    for raw, tree in pairs:
        selector = state._selector(raw)
        core = provenance._inspect_core_value(paths, raw, selector, binding.old_release['version'])
        if (core.identity.version != selector['version'] or core.identity.tree_sha256 != tree
                or (selector.get('source_revision') is not None
                    and selector['source_revision'] != core.identity.source_revision)):
            _fail()


def original_foundation_runtime_allowed(paths, raw, identity, package_sha256, foundation):
    """Inspect the exact captured legacy pair without broadening its old ABI."""
    from .legacy_foundation_upgrade import canonical_release
    record = state.read_staged_update(paths)
    if record is None or record.phase not in {'preparing', 'prepared', 'switching', 'native-settled', 'trial', 'rolling-back'}:
        return False
    binding = record.binding
    release = canonical_release(binding.old_release)
    if (release is None or package_sha256 != release['package_sha256'] or foundation != release['version']
            or identity.version != release['version'] or identity.source_revision != release['source_revision']):
        return False
    return any(raw == selected and identity.tree_sha256 == tree for selected, tree in (
        (binding.selected_before, binding.selected_tree_sha256_before),
        (binding.previous_before, binding.previous_tree_sha256_before)))


def record_foundation_rollback_commit(paths, operation_id):
    """Owner phase only, after actual reverse End(Commit) and all callbacks."""
    durable_state.installer_mutation_checkpoint(required=True)
    record = _operation(paths, operation_id)
    plan = read_foundation_rollback(paths, operation_id)
    if record.phase != 'rolling-back' or plan['phase'] not in {'prepared', 'restoring', 'native-committed'}:
        _fail()
    _assert_quiescent(paths)
    _verify_native_restore(paths, record, plan)
    _verify_original_data(paths, record)
    return _write(paths, record, {**plan, 'phase': 'native-committed'})


def verify_foundation_rollback(paths, operation_id):
    durable_state.installer_mutation_checkpoint(required=True)
    record = _operation(paths, operation_id)
    plan = read_foundation_rollback(paths, operation_id)
    if record.phase != 'rolling-back' or plan['phase'] != 'native-committed':
        _fail()
    _assert_quiescent(paths)
    _verify_native_restore(paths, record, plan)
    _verify_original_core(paths, record)
    _verify_original_data(paths, record)
    binding = record.binding
    if binding.previous_before is None:
        durable_state.durable_unlink(paths.previous_path, trusted_root=paths.install_root, missing_ok=True)
    else:
        durable_state.write_bytes_atomic(paths.previous_path, binding.previous_before,
            trusted_root=paths.install_root, max_bytes=4096, protect=fence.protect_state)
    durable_state.write_bytes_atomic(paths.current_path, binding.selected_before,
        trusted_root=paths.install_root, max_bytes=4096, protect=fence.protect_state)
    _verify_native_restore(paths, record, plan)
    _verify_original_data(paths, record)
    _write(paths, record, {**plan, 'phase': 'complete'})
    state.advance_staged_update(paths, operation_id, 'rolling-back', 'rolled-back')
