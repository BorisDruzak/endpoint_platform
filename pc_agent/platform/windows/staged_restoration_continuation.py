"""Derive completion of one terminal rollback's exact old native reservation.

This does not relax the historical continuation reader, adopt an arbitrary
native outcome, repair an installation or rewind selectors/private material.
Only a new derived receipt and retirement of its exact public hold are writes.
The authenticated caller retains the canonical update owner and real native
settlement proof; recovery enters only through the fixed signed owner phase.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re

from endpoint_contracts.runtime_payload import read_json, version_tuple
from . import durable_state, installer_fence as fence, installation_provenance as provenance
from . import native_setup_continuation as continuation, staged_update_state as state
from . import staged_foundation_rollback as rollback, staged_recovery as recovery, msi_inventory as msi

_LIMIT = 65536
_RECEIPT = 'restoration-continuation-finalized.json'


def _fail():
    raise ValueError('RECOVERY_REQUIRED')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _digest(value):
    return _sha(state._canonical(value))


def _read(path, *, secret=True, maximum=_LIMIT):
    fence.assert_state_security(path, secret=secret)
    raw = provenance._read(path, maximum)
    return read_json(raw, maximum), _sha(raw)


def _terminal_roles(paths, record, plan, target, control_session=None):
    """Terminal-only validation; do not broaden the live rollback role reader."""
    from .installer_transaction_bridge import _read_capability
    root = rollback._root(paths, record.binding.operation_id)
    candidates = list(root.glob('roles-*.json'))
    if not 0 < len(candidates) <= 16:
        _fail()
    matches = []
    for leaf in candidates:
        value, digest = _read(leaf)
        if not isinstance(value, dict) or set(value) != {'schema_version', 'owner', 'plan_sha256', 'control', 'removal', 'restoration'}:
            _fail()
        role = value['restoration']
        if not isinstance(role, dict):
            continue
        if target is not None and role.get('transaction_id') != target:
            continue
        if control_session is not None and value['control'].get('session_id') != control_session:
            continue
        if (type(value['schema_version']) is not int or value['schema_version'] != 1
                or value['plan_sha256'] != rollback.plan_identity_sha256(plan)):
            _fail()
        caps = [_read_capability(paths, value[name]['session_id']) for name in ('control', 'removal', 'restoration')]
        control, removal, restoration = caps
        rollback.validate_rollback_capability_shape(control)
        rollback.validate_rollback_capability_shape(removal)
        extra = control['staged_rollback']
        if (extra['role'] != 'control' or extra['operation_id'] != record.binding.operation_id
                or control['transaction_id'] != record.binding.operation_id
                or control['package'] != record.binding.new_release
                or control['helper_sha256'] != plan['new']['helper_sha256']
                or not recovery.owner_authorized(paths, record, control['owner'])
                or leaf.name != 'roles-' + control['session_id'] + '.json'
                or removal['staged_rollback'] != {'role': 'remove', 'operation_id': record.binding.operation_id,
                    'control_session_id': control['session_id']}
                or removal['session_id'] != extra['removal_session_id']
                or restoration['session_id'] != extra['restoration_session_id']
                or removal['package'] != control['package'] or removal['helper_sha256'] != control['helper_sha256']
                or restoration['operation'] != 'install' or 'staged_rollback' in restoration
                or restoration['package'] != record.binding.old_release
                or restoration['helper_sha256'] != plan['old']['helper_sha256']
                or any(cap['owner'] != control['owner'] for cap in caps)
                or value['owner'] != control['owner']):
            _fail()
        selection = rollback._restoration_selection(paths, record)
        if any(restoration[key] != selection[key] for key in ('selected', 'previous')):
            _fail()
        projections = [rollback._role_projection(cap) for cap in caps]
        if (any(value[name] != item for name, item in zip(('control', 'removal', 'restoration'), projections))
                or any(len({cap[key] for cap in caps}) != 3 for key in ('transaction_id', 'session_id'))):
            _fail()
        matches.append((value, digest, caps))
    if len(matches) != 1:
        _fail()
    return matches[0]


def _grant(paths, record, restoration):
    """Validate the old grant with one explicit parent-authorized scope delta."""
    from .compound_upgrade_plan import _validate_completed
    leaf = continuation._grant_path(paths, restoration['transaction_id'])
    value, grant_digest = _read(leaf)
    fields = {'schema_version', 'transaction_id', 'package', 'owner', 'helper_sha256', 'capture',
              'selection', 'completion', 'before_fence_sha256', 'completion_relative',
              'native_session_id', 'native_capability_sha256', 'compound_plan_sha256', 'native_fence_relative'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['transaction_id'] != restoration['transaction_id']
            or value['package'] != restoration['package'] or value['owner'] != restoration['owner']
            or value['helper_sha256'] != restoration['helper_sha256']
            or value['native_session_id'] != restoration['session_id']
            or value['native_capability_sha256'] != _digest(restoration)
            or value['compound_plan_sha256'] is not None or value['native_fence_relative'] != 'transaction.json'
            or value['completion_relative'] != 'transactions/' + restoration['transaction_id'] + '/completed.json'
            or not isinstance(value['before_fence_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', value['before_fence_sha256'])):
        _fail()
    if value['capture'] != continuation._capture_authority(paths, restoration):
        _fail()
    _validate_completed(value['completion'], restoration['package'], restoration['transaction_id'], 'install')
    completion, completion_digest = _read(fence.state_root(paths) / value['completion_relative'], secret=False)
    if completion != value['completion']:
        _fail()
    # Old native finish captured no previous selector. The parent subsequently
    # restored its exact original previous bytes/tree as part of reverse proof.
    expected_native_scope = {'selected_sha256': _sha(record.binding.selected_before),
        'previous_sha256': None, 'tree_sha256': record.binding.selected_tree_sha256_before}
    if value['selection'] != expected_native_scope:
        _fail()
    return value, grant_digest, completion_digest


def _no_other_operations(paths, target, package):
    from .update_transaction import active_update_state
    from .compound_upgrade_plan import has_active_upgrade
    hold = continuation.pending_continuation(paths)
    if hold is not None and hold != {'transaction_id': target, 'package': package}:
        _fail()
    if (fence.read_fence(paths) is not None or has_active_upgrade(paths)
            or active_update_state(paths) not in (None, 'native-continuation-pending')):
        _fail()
    children = fence.state_root(paths) / 'children'
    if children.exists():
        fence.assert_state_security(children)
        # A surviving child native fence is unresolved, irrespective of PID/age.
        entries = 0
        for index, (folder, directories, files) in enumerate(os.walk(children, followlinks=False)):
            entries += len(directories) + len(files)
            fence.reject_reparse_ancestors(Path(folder))
            if index >= 512 or entries > 4096 or 'transaction.json' in files:
                _fail()
            for name in directories:
                fence.reject_reparse_ancestors(Path(folder) / name)


def _restored_services(paths, record):
    """Read canonical startup/image/account and live state without stopping it."""
    import win32service as scm
    specifications = {'EndpointAgent': ('endpoint-agent-service.exe', '--agent-service', 'NT AUTHORITY\\LocalService', 2),
        'EndpointAgentUpdater': ('endpoint-agent-updater.exe', '--updater-service', 'LocalSystem', 3),
        'EndpointBrowserPolicy': ('EndpointBrowserPolicy.exe', '', 'LocalSystem', 2)}
    manager = scm.OpenSCManager(None, None, scm.SC_MANAGER_CONNECT)
    result = {}
    try:
        for name, (filename, argument, account, start) in specifications.items():
            handle = scm.OpenService(manager, name, scm.SERVICE_QUERY_CONFIG | scm.SERVICE_QUERY_STATUS)
            try:
                config = scm.QueryServiceConfig(handle)
                expected = '"' + str(paths.install_root / filename) + '"' + (' ' + argument if argument else '')
                delayed = scm.QueryServiceConfig2(handle, 3)
                status = scm.QueryServiceStatus(handle)[1]
                if (config[0] != 16 or config[1] != start or config[3].casefold() != expected.casefold()
                        or config[7].casefold() != account.casefold() or delayed is not False
                        or status not in {scm.SERVICE_RUNNING, scm.SERVICE_STOPPED}):
                    _fail()
                result[name] = {'start_type': start, 'delayed_auto': False,
                    'state': 'running' if status == scm.SERVICE_RUNNING else 'stopped'}
            finally:
                scm.CloseServiceHandle(handle)
    finally:
        scm.CloseServiceHandle(manager)
    return result


def _runner_authority(client, paths, record):
    """Bind new recovery code to its own media, never to the old172 package."""
    from .installer_transaction_bridge import _read_capability, _request_data
    cap = client.capability
    if _read_capability(paths, cap['session_id']) != cap or client.identity.value['hash'] != cap['helper_sha256']:
        _fail()
    if version_tuple(cap['package']['version']) < version_tuple(record.binding.new_release['version']):
        _fail()
    request = _request_data(paths, cap)
    expected = msi.read_expected_package(request['package_path'], cap['package'])
    binary = msi.read_binary(request['package_path'], 'EndpointInstallerHost', maximum=128 * 1024 * 1024)
    if _sha(binary) != cap['helper_sha256'] or expected.identity.source_revision != cap['package']['source_revision']:
        _fail()


def _proof(client, paths, target):
    from .installer_transaction_bridge import _identity
    cap = client.capability
    _identity(cap['owner'])
    recovering = client.phase == 'finalize-staged-restoration-continuation'
    parent = client.phase == 'verify-foundation-rollback'
    if not recovering and not parent:
        _fail()
    if recovering:
        if (cap['owner']['sid'] != 'S-1-5-18'
                or cap.get('restoration_transaction_id') != target or cap['transaction_id'] == target
                or cap['operation'] != 'install' or cap['recovery'] or cap['uninstall_finalization']
                or any(key in cap for key in ('compound', 'staged_rollback', 'recovery_parent'))):
            _fail()
    else:
        rollback.validate_rollback_capability_shape(cap)
        if cap['staged_rollback']['role'] != 'control' or cap['transaction_id'] != target:
            _fail()
    record = state.read_staged_update(paths)
    if record is None or record.phase != 'rolled-back' or parent and record.binding.operation_id != target:
        _fail()
    root = rollback._root(paths, record.binding.operation_id)
    plan, plan_digest = _read(root / 'plan.json')
    rollback._validate_plan(paths, record, plan)
    if plan['phase'] != 'complete':
        _fail()
    roles, roles_digest, caps = _terminal_roles(paths, record, plan,
        target if recovering else None, cap['session_id'] if parent else None)
    control, removal, restoration = caps
    target = restoration['transaction_id']
    if parent and (cap != control or not recovery.owner_authorized(paths, record, cap['owner'])):
        _fail()
    if recovering:
        _runner_authority(client, paths, record)
        for owner in (record.owner, control['owner'], removal['owner'], restoration['owner']):
            recovery._assert_owner_dead(owner)
    _no_other_operations(paths, target, restoration['package'])
    grant, grant_digest, completion_digest = _grant(paths, record, restoration)
    from . import installer_data_security
    from .installer_transaction_bridge import _request_data
    request = _request_data(paths, restoration)
    installer_data_security.verify_preserved(paths, {**request,
        'session_id': restoration['session_id'], 'recovery': True})
    # An existing generic recovery owner is real authority too, never an idle
    # marker. Its immutable grant link and exact process death are required.
    owner_leaf = continuation._owner_receipt(paths, restoration)
    owner_digest = None
    if owner_leaf.exists():
        adopted, owner_digest = _read(owner_leaf)
        if (not isinstance(adopted, dict) or set(adopted) != {'schema_version', 'grant_sha256', 'owner'}
                or type(adopted['schema_version']) is not int or adopted['schema_version'] != 1
                or adopted['grant_sha256'] != _digest(grant)):
            _fail()
        state._owner(adopted['owner'])
        if recovering or adopted['owner'] != cap['owner']:
            recovery._assert_owner_dead(adopted['owner'])
    finished_leaf = continuation._grant_path(paths, target).with_name('native-continuation-finished.json')
    finished_digest = None
    if finished_leaf.exists():
        finished, finished_digest = _read(finished_leaf)
        if finished != {'schema_version': 1, 'grant_sha256': _digest(grant)}:
            _fail()
    if (paths.current_path.read_bytes() != record.binding.selected_before
            or (paths.previous_path.read_bytes() if paths.previous_path.exists() else None) != record.binding.previous_before):
        _fail()
    scope = continuation._selected_scope(paths, restoration)
    if scope != {'selected_sha256': _sha(record.binding.selected_before),
            'previous_sha256': _sha(record.binding.previous_before) if record.binding.previous_before is not None else None,
            'tree_sha256': record.binding.selected_tree_sha256_before}:
        _fail()
    rollback._verify_native_restore(paths, record, plan)
    rollback._verify_original_core(paths, record)
    rollback._verify_original_data(paths, record)
    services = _restored_services(paths, record)
    proof = {'parent_operation_id': record.binding.operation_id, 'parent_binding_sha256': rollback._binding_hash(record),
        'plan_sha256': plan_digest, 'roles_sha256': roles_digest, 'restoration_transaction_id': target,
        'control_capability_sha256': _digest(control),
        'grant_sha256': grant_digest, 'native_capability_sha256': _digest(restoration),
        'capture_sha256': grant['capture']['capture_sha256'], 'completion_sha256': completion_digest,
        'generic_owner_receipt_sha256': owner_digest, 'generic_finished_receipt_sha256': finished_digest,
        'final_selection': scope}
    return record, restoration, root, proof, services


def _validate_receipt(paths, saved, proof, services):
    from .installer_transaction_bridge import _read_capability
    if (not isinstance(saved, dict) or set(saved) != {'schema_version', 'kind', 'proof', 'authority', 'services'}
            or type(saved['schema_version']) is not int or saved['schema_version'] != 1
            or saved['kind'] != 'staged-restoration-continuation' or saved['proof'] != proof):
        _fail()
    authority = saved['authority']
    if (not isinstance(authority, dict) or set(authority) != {'owner', 'helper_sha256', 'package_sha256',
            'transaction_id', 'session_id', 'phase', 'capability_sha256'}
            or authority['phase'] not in {'verify-foundation-rollback', 'finalize-staged-restoration-continuation'}):
        _fail()
    state._owner(authority['owner'])
    cap = _read_capability(paths, authority['session_id'])
    if (authority['capability_sha256'] != _digest(cap) or authority['owner'] != cap['owner']
            or authority['helper_sha256'] != cap['helper_sha256']
            or authority['package_sha256'] != cap['package']['package_sha256']
            or authority['transaction_id'] != cap['transaction_id']):
        _fail()
    if authority['phase'] == 'verify-foundation-rollback':
        if authority['capability_sha256'] != proof['control_capability_sha256']:
            _fail()
    elif (cap.get('restoration_transaction_id') != proof['restoration_transaction_id']
            or cap['transaction_id'] == proof['restoration_transaction_id']):
        _fail()
    if not isinstance(saved['services'], dict) or saved['services'].keys() != services.keys():
        _fail()
    for name, current in services.items():
        previous = saved['services'][name]
        if (not isinstance(previous, dict) or set(previous) != {'start_type', 'delayed_auto', 'state'}
                or previous['start_type'] != current['start_type'] or previous['delayed_auto'] != current['delayed_auto']
                or previous['state'] not in {'running', 'stopped'}):
            _fail()


def finalize_restoration_continuation(client, paths, operation_id):
    """Finalize exactly one role-bound old reservation after terminal rollback."""
    durable_state.installer_mutation_checkpoint(required=True)
    state._uuid(operation_id)
    client.checkpoint()
    record, restoration, root, proof, services = _proof(client, paths, operation_id)
    target = restoration['transaction_id']
    leaf = root / _RECEIPT
    hold = continuation.pending_continuation(paths)
    if leaf.exists():
        saved, _ = _read(leaf)
        _validate_receipt(paths, saved, proof, services)
        if saved['authority']['owner'] != client.capability['owner']:
            recovery._assert_owner_dead(saved['authority']['owner'])
    else:
        if hold != {'transaction_id': target, 'package': restoration['package']}:
            _fail()  # Arbitrary absence is not completion evidence.
        cap = client.capability
        saved = {'schema_version': 1, 'kind': 'staged-restoration-continuation', 'proof': proof,
            'authority': {'owner': cap['owner'], 'helper_sha256': cap['helper_sha256'],
                'package_sha256': cap['package']['package_sha256'], 'transaction_id': cap['transaction_id'],
                'session_id': cap['session_id'], 'phase': client.phase,
                'capability_sha256': _digest(cap)}, 'services': services}
        durable_state.write_json_atomic(leaf, saved, trusted_root=root, max_bytes=_LIMIT,
            protect=lambda path: fence.protect_state(path, secret=True))
    client.checkpoint()
    # Reprove everything after the only publication. No selector, native grant,
    # completion or old native-continuation-finished marker is ever rewritten.
    _, _, _, current, current_services = _proof(client, paths, operation_id)
    if current != proof or current_services != services or _read(leaf)[0] != saved:
        _fail()
    if hold is not None:
        continuation.finish_continuation_hold(paths, restoration)
    return {'result': 'staged-restoration-complete', 'operation_id': target,
        'parent_operation_id': record.binding.operation_id, 'receipt_sha256': _digest(saved)}
