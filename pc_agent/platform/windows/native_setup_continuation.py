"""Fixed native post-settlement work under the existing authenticated owner.

The parent keeps its mutex. This child never opens the observer mutex or
manufactures a Core update assignment to bootstrap a fresh native install.
"""
from __future__ import annotations

from . import durable_state, installer_fence as fence, installation_provenance as provenance
from . import staged_update_state as state, staged_recovery as recovery


def _fail():
    raise ValueError('RECOVERY_REQUIRED')


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
    from .installer_transaction_bridge import completion_root
    from .compound_upgrade_plan import _validate_completed, _read
    leaf = completion_root(paths, capability) / 'completed.json'
    value = _read(leaf, maximum=16384)
    _validate_completed(value, capability['package'], capability['transaction_id'], 'install')
    assert_original_native_owner(paths, capability)


def assert_original_native_owner(paths, capability):
    from .installer_transaction_bridge import _read_capability, _request_data
    from . import installer_data_security
    request = {**_request_data(paths, capability), 'session_id': capability['session_id'], 'recovery': True}
    capture = installer_data_security._read(paths, request)
    original = _read_capability(paths, capture['binding']['session_id'])
    if (original['operation'] != 'install' or any(original[key] != capability[key] for key in
            ('owner', 'helper_sha256', 'transaction_id', 'package'))):
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
        finish_continuation_hold(paths, cap)
    result = {'operation_id': cap['transaction_id'], 'observer': observer, 'users': users}
    if record is not None:
        result['services'] = recovery._service_outcomes(paths, record)
    client.request('complete', result)
    return result
