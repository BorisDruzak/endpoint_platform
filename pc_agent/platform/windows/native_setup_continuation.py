"""Fixed native post-settlement work under the existing authenticated owner.

The parent keeps its mutex. This child never opens the observer mutex or
manufactures a Core update assignment to bootstrap a fresh native install.
"""
from __future__ import annotations
import hashlib
import re

from . import durable_state, installer_fence as fence, installation_provenance as provenance
from . import staged_update_state as state, staged_recovery as recovery


def _fail():
    raise ValueError('RECOVERY_REQUIRED')


def _digest(value):
    return hashlib.sha256(state._canonical(value)).hexdigest()


def _grant_path(paths, transaction):
    state._uuid(transaction)
    return fence.state_root(paths) / 'transactions' / transaction / 'native-continuation-grant.json'


def _capture_authority(paths, capability):
    from .installer_transaction_bridge import _request_data, _read_capability
    from . import installer_data_security as security
    request = {**_request_data(paths, capability), 'session_id': capability['session_id'], 'recovery': True}
    capture = security._read(paths, request)
    original = _read_capability(paths, capture['binding']['session_id'])
    if (capture['phase'] != 'configured' or original['operation'] != 'install'
            or any(original[key] != capability[key] for key in ('transaction_id', 'package', 'helper_sha256'))):
        _fail()
    return {'session_id': capture['binding']['session_id'], 'capture_sha256': security._capture_hash(capture)}


def _selected_scope(paths, capability):
    inspected = provenance.inspect_installed_core(paths, resulting_foundation=capability['package']['version'])
    if inspected.current is None:
        _fail()
    return {'selected_sha256': hashlib.sha256(paths.current_path.read_bytes()).hexdigest(),
            'previous_sha256': hashlib.sha256(paths.previous_path.read_bytes()).hexdigest() if paths.previous_path.exists() else None,
            'tree_sha256': inspected.current.identity.tree_sha256}


def reserve_native_continuation(paths, capability, completion, before):
    """Called by authenticated native finish BEFORE publishing/retiring its fence.

    This private scoped grant records the successful native finish admission,
    original capture and exact completed receipt. Public idle/completion data
    cannot create it. It also covers a crash before completed.json is written.
    """
    from .installer_transaction_bridge import completion_root
    from .compound_upgrade_plan import _validate_completed, read_plan
    durable_state.installer_mutation_checkpoint(required=True)
    _validate_completed(completion, capability['package'], capability['transaction_id'], 'install')
    capture = _capture_authority(paths, capability)
    relative = (completion_root(paths, capability, create=True) / 'completed.json').relative_to(fence.state_root(paths)).as_posix()
    value = {'schema_version': 1, 'transaction_id': capability['transaction_id'], 'package': capability['package'],
             'owner': capability['owner'], 'helper_sha256': capability['helper_sha256'], 'capture': capture,
             'selection': _selected_scope(paths, capability), 'completion': completion,
             'before_fence_sha256': _digest(before), 'completion_relative': relative,
             'native_fence_relative': fence.fence_path(paths).relative_to(fence.state_root(paths)).as_posix(),
             'native_session_id': capability['session_id'], 'native_capability_sha256': _digest(capability),
             'compound_plan_sha256': _digest(read_plan(paths, capability)) if 'compound' in capability else None}
    leaf = _grant_path(paths, capability['transaction_id'])
    if leaf.exists():
        if recovery._read(leaf) != value:
            _fail()
    else:
        durable_state.write_json_atomic(leaf, value, trusted_root=leaf.parent, max_bytes=32768,
            protect=lambda path: fence.protect_state(path, secret=True))
    begin_continuation_hold(paths, capability)


def read_continuation_grant(paths, capability):
    from .compound_upgrade_plan import _validate_completed
    try:
        value = recovery._read(_grant_path(paths, capability['transaction_id']))
    except OSError:
        _fail()
    fields = {'schema_version', 'transaction_id', 'package', 'owner', 'helper_sha256', 'capture',
              'selection', 'completion', 'before_fence_sha256', 'completion_relative',
              'native_session_id', 'native_capability_sha256', 'compound_plan_sha256', 'native_fence_relative'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['transaction_id'] != capability['transaction_id']
            or value['package'] != capability['package'] or value['helper_sha256'] != capability['helper_sha256']
            or not isinstance(value['before_fence_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', value['before_fence_sha256'])
            or not isinstance(value['completion_relative'], str) or not re.fullmatch(
                r'transactions/' + re.escape(capability['transaction_id']) + r'/(?:attempts/[0-9a-f-]{36}/)?completed\.json', value['completion_relative'])):
        _fail()
    state._owner(value['owner'])
    native_path = value['native_fence_relative']
    if (not isinstance(native_path, str) or native_path != 'transaction.json' and not re.fullmatch(
            r'children/' + re.escape(capability['transaction_id']) + r'/(?:[0-9a-f-]{36}/)?transaction\.json', native_path)):
        _fail()
    state._uuid(value['native_session_id'])
    if (not isinstance(value['native_capability_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', value['native_capability_sha256'])
            or value['compound_plan_sha256'] is not None and
            (not isinstance(value['compound_plan_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', value['compound_plan_sha256']))):
        _fail()
    _validate_completed(value['completion'], capability['package'], capability['transaction_id'], 'install')
    if value['capture'] != _capture_authority(paths, capability) or value['selection'] != _selected_scope(paths, capability):
        _fail()
    return value


def _owner_receipt(paths, capability):
    return _grant_path(paths, capability['transaction_id']).with_name('native-continuation-owner.json')


def mark_continuation_finished(paths, capability):
    grant = read_continuation_grant(paths, capability)
    leaf = _grant_path(paths, capability['transaction_id']).with_name('native-continuation-finished.json')
    value = {'schema_version': 1, 'grant_sha256': _digest(grant)}
    if leaf.exists():
        if recovery._read(leaf) != value:
            _fail()
    else:
        durable_state.write_json_atomic(leaf, value, trusted_root=leaf.parent, max_bytes=4096,
            protect=lambda path: fence.protect_state(path, secret=True))


def authorize_continuation_recovery(paths, capability):
    """Exact scoped adoption after retained native/capture authority and death proof."""
    durable_state.installer_mutation_checkpoint(required=True)
    if pending_continuation(paths) != {key: capability[key] for key in ('transaction_id', 'package')}:
        _fail()
    grant = read_continuation_grant(paths, capability)
    _assert_recovery_owners_dead(paths, capability, grant)
    leaf = _owner_receipt(paths, capability)
    receipt = {'schema_version': 1, 'grant_sha256': _digest(grant), 'owner': capability['owner']}
    durable_state.write_json_atomic(leaf, receipt, trusted_root=leaf.parent, max_bytes=4096,
        protect=lambda path: fence.protect_state(path, secret=True))
    return grant


def _assert_recovery_owners_dead(paths, capability, grant):
    recovery._assert_owner_dead(grant['owner'])
    leaf = _owner_receipt(paths, capability)
    if leaf.exists():
        prior = recovery._read(leaf)
        if (not isinstance(prior, dict) or set(prior) != {'schema_version', 'grant_sha256', 'owner'}
                or type(prior['schema_version']) is not int or prior['schema_version'] != 1
                or prior['grant_sha256'] != _digest(grant)):
            _fail()
        if prior.get('owner') != capability['owner']:
            state._owner(prior.get('owner'))
            recovery._assert_owner_dead(prior['owner'])


def recover_native_continuation(client, paths):
    """Finish this retained native success without entering/replaying MSI."""
    from .installer_transaction_bridge import _request_data
    from .compound_upgrade_plan import _read, has_active_upgrade
    from .update_transaction import active_update_state
    from . import installer_data_security, msi_inventory
    cap = client.capability
    if (cap['operation'] != 'install' or cap['recovery'] or cap['uninstall_finalization']
            or any(key in cap for key in ('compound', 'staged_rollback', 'recovery_parent'))):
        _fail()
    grant = read_continuation_grant(paths, cap)
    finished = _grant_path(paths, cap['transaction_id']).with_name('native-continuation-finished.json')
    if finished.exists():
        if (recovery._read(finished) != {'schema_version': 1, 'grant_sha256': _digest(grant)}
                or pending_continuation(paths) is None):
            _fail()
    staged = state.read_staged_update(paths)
    staged_scope = staged is not None and staged.binding.operation_id == cap['transaction_id']
    if staged is not None and (staged_scope and staged.phase not in {'switching', 'native-settled', 'trial', 'accepted'}
            or not staged_scope and staged.phase not in {'accepted', 'rolled-back'}):
        _fail()
    if active_update_state(paths) not in (None, 'native-continuation-pending'):
        _fail()
    compound_pending = has_active_upgrade(paths)
    if compound_pending and grant['compound_plan_sha256'] is None:
        _fail()
    completion = fence.state_root(paths) / grant['completion_relative']
    if completion.exists() and _read(completion, maximum=16384) != grant['completion']:
        _fail()
    native_leaf = fence.state_root(paths) / grant['native_fence_relative']
    native = _read(native_leaf, maximum=16384) if native_leaf.exists() else None
    if native is not None:
        fence.validate_fence(native)
    if grant['native_fence_relative'] != 'transaction.json' and fence.read_fence(paths) is not None:
        _fail()
    if native is not None and native != grant['completion'] and _digest(native) != grant['before_fence_sha256']:
        _fail()
    request = _request_data(paths, cap)
    data_request = {**request, 'session_id': cap['session_id'], 'recovery': True}
    expected = msi_inventory.read_expected_package(request['package_path'], cap['package'])
    if provenance.verified_foundation_release(paths) != cap['package']:
        _fail()
    installer_data_security.verify_preserved(paths, data_request)
    with durable_state.installer_mutation_checkpoints(client.checkpoint):
        with msi_inventory.verified_foundation_bytes(expected, paths.install_root):
            # The owner policy separately supplied a fresh genuine MsiBegin/End
            # settlement proof before granting this fixed recovery phase.
            # The private grant may have become durable immediately before a
            # crash publishing its public hold. The retained native fence and
            # full scoped grant above span that boundary without MSI replay.
            _assert_recovery_owners_dead(paths, cap, grant)
            begin_continuation_hold(paths, cap)
            authorize_continuation_recovery(paths, cap)
            if not completion.exists():
                durable_state.write_json_atomic(completion, grant['completion'], trusted_root=completion.parent,
                    max_bytes=16384, protect=fence.protect_state)
            if native is not None:
                if _read(native_leaf, maximum=16384) != native:
                    _fail()
                durable_state.durable_unlink(native_leaf, trusted_root=native_leaf.parent)
            if compound_pending:
                _finish_reserved_compound(paths, cap, grant)
    if staged_scope:
        # Native completion is now durably settled. Existing staged recovery
        # must adopt its own original owner and run trial/rollback; this grant
        # never activates an observer for an unaccepted staged candidate.
        result = {'operation_id': cap['transaction_id'], 'result': 'native-settled-for-staged-recovery'}
        client.request('complete', result)
        return result
    return execute_native_continuation(client, paths)


def _finish_reserved_compound(paths, capability, grant):
    """Resume only post-End(Commit) finalization captured by native finish.

    The original authenticated finish grant is private durable authority for
    this exact plan/capability. Public completion plus an idle MSI is insufficient.
    No package script, installer callback or native install API is invoked.
    """
    from .installer_transaction_bridge import _read_capability
    from . import compound_upgrade_plan as plan, msi_inventory
    original = _read_capability(paths, grant['native_session_id'])
    if (_digest(original) != grant['native_capability_sha256'] or 'compound' not in original
            or original['owner'] != grant['owner']
            or any(original[key] != capability[key] for key in ('transaction_id', 'package', 'helper_sha256'))):
        _fail()
    record = plan.read_plan(paths, original)
    normalized = {**record, 'phase': 'reconciled', 'sequence': plan._phases(record).index('reconciled')}
    if record['phase'] not in {'reconciled', 'ready'} or _digest(normalized) != grant['compound_plan_sha256']:
        _fail()
    if msi_inventory.NativeMsi().product(record['old']['package']['product_code']) != -1:
        _fail()
    if record['phase'] == 'reconciled':
        marker = plan.ready_receipt(paths, original)
    else:
        history = fence.state_root(paths) / 'upgrade-history' / record['upgrade_id']
        raw = plan._read_bytes(history / 'ready.json', maximum=4096)
        ready = plan._read(history / 'ready.json', maximum=4096)
        wanted = {**plan._barrier(record), 'successor_product_code': capability['package']['product_code'],
                  'source_revision': capability['package']['source_revision'], 'phase': 'ready'}
        if ready != wanted:
            _fail()
        marker = {**{key: value for key, value in ready.items() if key != 'phase'},
                  'ready_sha256': hashlib.sha256(raw).hexdigest()}
    history = fence.state_root(paths) / 'upgrade-history' / record['upgrade_id']
    plan._immutable_json(history / 'complete.json', marker)
    if plan.committed_marker(paths, barrier=plan._barrier(record)) != marker or plan.has_active_upgrade(paths):
        _fail()


def release_preaccept_hold(paths, capability, record):
    """Rollback keeps staged exclusion while retiring only this pending hold."""
    if (record.phase not in {'switching', 'native-settled', 'trial', 'rolling-back', 'rolled-back'}
            or record.binding.operation_id != capability['transaction_id']
            or record.binding.new_release != capability['package']
            or not recovery.owner_authorized(paths, record, capability['owner'])):
        _fail()
    hold = pending_continuation(paths)
    if hold is not None:
        read_continuation_grant(paths, capability)
        finish_continuation_hold(paths, capability)


def _settled_native(paths):
    from .update_transaction import active_update_state
    from .compound_upgrade_plan import has_active_upgrade
    if active_update_state(paths) not in (None, 'native-continuation-pending'):
        _fail()
    if fence.read_fence(paths) is not None or has_active_upgrade(paths):
        _fail()


def pending_continuation(paths):
    from .compound_upgrade_plan import _read
    leaf = fence.state_root(paths) / 'native-continuation.json'
    if not leaf.exists():
        return None
    value = _read(leaf, maximum=4096)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'transaction_id', 'package'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1):
        _fail()
    state._uuid(value['transaction_id'])
    state._release(value['package'])
    return {key: value[key] for key in ('transaction_id', 'package')}


def begin_continuation_hold(paths, capability):
    wanted = {key: capability[key] for key in ('transaction_id', 'package')}
    existing = pending_continuation(paths)
    if existing is not None and existing != wanted:
        _fail()
    if existing is None:
        root = fence.state_root(paths)
        durable_state.write_json_atomic(root / 'native-continuation.json', {'schema_version': 1, **wanted},
            trusted_root=root, max_bytes=4096, protect=fence.protect_state)


def finish_continuation_hold(paths, capability):
    if pending_continuation(paths) != {key: capability[key] for key in ('transaction_id', 'package')}:
        _fail()
    root = fence.state_root(paths)
    durable_state.durable_unlink(root / 'native-continuation.json', trusted_root=root)


def _completed_native_receipt(paths, capability):
    from .compound_upgrade_plan import _validate_completed, _read
    grant = read_continuation_grant(paths, capability)
    leaf = fence.state_root(paths) / grant['completion_relative']
    value = _read(leaf, maximum=16384)
    _validate_completed(value, capability['package'], capability['transaction_id'], 'install')
    if value != grant['completion']:
        _fail()
    assert_original_native_owner(paths, capability)


def assert_original_native_owner(paths, capability):
    grant = read_continuation_grant(paths, capability)
    if grant['owner'] == capability['owner']:
        return
    try:
        receipt = recovery._read(_owner_receipt(paths, capability))
    except OSError:
        _fail()
    if receipt != {'schema_version': 1, 'grant_sha256': _digest(grant), 'owner': capability['owner']}:
        _fail()


def accepted_native_record(paths, capability):
    if (capability['operation'] != 'install' or capability['recovery']
            or capability['uninstall_finalization'] or any(key in capability for key in
                ('compound', 'staged_rollback', 'recovery_parent'))):
        _fail()
    _settled_native(paths)
    hold = pending_continuation(paths)
    if hold is not None and hold != {key: capability[key] for key in ('transaction_id', 'package')}:
        _fail()
    record = state.read_staged_update(paths)
    if record is not None and record.binding.operation_id == capability['transaction_id']:
        if (record.phase != 'accepted' or record.binding.new_release != capability['package']
                or not recovery.owner_authorized(paths, record, capability['owner'])):
            _fail()
        assert_original_native_owner(paths, capability)
        return record
    if record is not None and record.phase not in {'accepted', 'rolled-back'}:
        _fail()
    _completed_native_receipt(paths, capability)
    return None


def execute_native_continuation(client, paths):
    from .installer_transaction_bridge import _request_data
    from . import installer_data_security, msi_inventory
    from .native_setup_observer import provision_packaged_observer
    cap = client.capability
    record = accepted_native_record(paths, cap)
    with durable_state.installer_mutation_checkpoints(client.checkpoint):
        begin_continuation_hold(paths, cap)
    request = _request_data(paths, cap)
    expected = msi_inventory.read_expected_package(request['package_path'], cap['package'])
    if provenance.verified_foundation_release(paths) != cap['package']:
        _fail()
    inspected = provenance.inspect_installed_core(paths, resulting_foundation=expected.package.version)
    if inspected.current is None:
        _fail()
    # This fresh authenticated continuation session reads the ORIGINAL capture
    # after accepted-native authority above. Recovery read permits only session
    # handoff; it still checks exact transaction/package and every private
    # identity/security descriptor, and never writes or rebaselines a capture.
    data_request = {**request, 'session_id': cap['session_id'], 'recovery': True}
    installer_data_security.verify_preserved(paths, data_request)
    with durable_state.installer_mutation_checkpoints(client.checkpoint):
        with msi_inventory.verified_foundation_bytes(expected, paths.install_root):
            observer = provision_packaged_observer(paths)
            users = recovery.restore_expected_companions(paths, cap['transaction_id'], checkpoint=client.checkpoint)
        # Recheck accepted/private/native authority after all external work.
        accepted_native_record(paths, cap)
        installer_data_security.verify_preserved(paths, data_request)
        services = recovery._service_outcomes(paths, record) if record is not None else None
        if services is not None and any(value not in {'running', 'not-required'} for value in services.values()):
            _fail()
        mark_continuation_finished(paths, cap)
        finish_continuation_hold(paths, cap)
    result = {'operation_id': cap['transaction_id'], 'observer': observer, 'users': users}
    if services is not None:
        result['services'] = services
    client.request('complete', result)
    return result
