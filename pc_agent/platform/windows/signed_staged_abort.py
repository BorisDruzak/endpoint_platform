"""Scope-bound recovery of a prepared compound switch before any MSI call."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from . import compound_upgrade_plan as compound, durable_state as durable
from . import installer_data_security, installer_fence as fence, msi_inventory
from . import installation_provenance as provenance, staged_boot_marker
from . import staged_candidate_payload as payload, staged_foundation_rollback as rollback
from . import staged_recovery, staged_update_state as state
from .authenticode_timestamp import has_verified_timestamp
from .installer_transaction_bridge import InstallerServices, NativeIdentity, _read_capability, _request_data
from .native_setup_continuation import pending_continuation
from .signed_native_recovery import _machine, _sha, _witness_msi_settlement
from .native_setup_observer import _PUBLISHER
from .update_paths import WindowsUpdatePaths
from .update_transaction import _windows_transaction


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _locate_file(root, archive, relative, digest):
    live, saved = root / relative, archive / relative
    _require(live.exists() != saved.exists(), 'ABORT_RECORD_LOCATION_INVALID')
    path = live if live.exists() else saved
    fence.reject_reparse_ancestors(path)
    _require(_sha(path) == digest, 'ABORT_RECORD_HASH_MISMATCH')
    return path


def _move_file(source, destination):
    import win32api

    durable.installer_mutation_checkpoint(required=True)
    digest = _sha(source)
    win32api.MoveFileEx(str(source), str(destination), 8)  # MOVEFILE_WRITE_THROUGH
    _require(_sha(destination) == digest, 'ABORT_ARCHIVE_HASH_MISMATCH')
    durable.flush_directory(source.parent)
    durable.flush_directory(destination.parent)


def _admit(paths, scope, archive):
    root = fence.state_root(paths)
    operation, upgrade = scope['operation'], scope['upgrade']
    record = state.read_staged_update(paths)
    _require(record is not None and record.binding.operation_id == operation and
             record.phase in {'switching', 'rolling-back'} and record.attempt_id is None,
             'ABORT_STAGE_INVALID')
    binding = record.binding
    _require(binding.old_release['version'] == '3.2.193' and binding.new_release['version'] == '3.2.202'
             and state._selector(binding.selected_before)['version'] == '3.2.201', 'ABORT_RELEASE_INVALID')
    if record.phase == 'switching':
        _require(_sha(root / 'staged-update.json') == scope['stage'], 'ABORT_STAGE_HASH_MISMATCH')
    else:
        _require(_sha(archive / 'staged-update.before.json') == scope['stage'], 'ABORT_RECEIPT_INVALID')
    inputs = staged_recovery._validate_recovery_inputs(paths, record)
    _require(inputs['files']['EndpointAgentSetup.exe'] == scope['setup'] and
             _sha(staged_recovery._root(paths, operation) / 'inputs.json') == scope['inputs'] and
             staged_boot_marker.present(operation, inputs['boot']) and
             staged_recovery._native_attempt(paths, record) is None and
             pending_continuation(paths) is None and not paths.pending_path.exists(), 'ABORT_NATIVE_ATTEMPT_PRESENT')
    staged_recovery._assert_owner_dead(record.owner)
    plan_path = root / 'upgrades' / upgrade / 'plan.json'
    _require(_sha(plan_path) == scope['plan'] and not (plan_path.parent / 'predecessor.json').exists(),
             'ABORT_COMPOUND_PLAN_MISMATCH')
    plan = compound._read(plan_path, secret=True)
    cap = _read_capability(paths, plan['new']['session_id'])
    compound.validate_bound_plan(plan, cap)
    _require(plan['phase'] == 'prepared' and plan['sequence'] == 0 and plan['owner'] == record.owner,
             'ABORT_COMPOUND_ALREADY_ENTERED')
    _require(cap['package'] == binding.new_release and plan['old']['package'] == binding.old_release,
             'ABORT_COMPOUND_RELEASE_MISMATCH')
    compound.read_prepared_source(paths, cap)

    native = msi_inventory.NativeMsi()
    _require(native.product(binding.old_release['product_code']) == 5 and
             native.product(binding.new_release['product_code']) == -1 and
             provenance.verified_foundation_release(paths) == binding.old_release,
             'ABORT_NATIVE_PRODUCTS_CHANGED')
    old_cap = _read_capability(paths, plan['old']['session_id'])
    old_media = _request_data(paths, old_cap)['package_path']
    old = msi_inventory.read_expected_package(old_media, binding.old_release)
    msi_inventory.verify_foundation(old.package, paths.install_root, expected=old)
    _require(paths.current_path.read_bytes() == binding.selected_before and
             paths.previous_path.read_bytes() == binding.previous_before, 'ABORT_SELECTORS_CHANGED')
    rollback._verify_original_core(paths, record)
    installer_data_security.before_native(paths, rollback._capture_request(paths, record))

    for name in ('transaction.json', f'children/{operation}/transaction.json'):
        leaf = _locate_file(root, archive, name, scope['records'][name])
        value = compound._read(leaf, maximum=16384)
        fence.validate_fence(value)
        _require(value['phase'] == 'msi-starting' and value['sequence'] == 1 and
                 not value['startup_restored'], 'ABORT_NATIVE_FENCE_ADVANCED')
    barrier = _locate_file(root, archive, 'upgrade.json', scope['records']['upgrade.json'])
    _require(compound._read(barrier, maximum=4096) == compound._barrier(plan), 'ABORT_BARRIER_MISMATCH')
    history = _locate_file(root, archive, f'upgrade-history/{upgrade}/barrier.json',
                           scope['records']['upgrade.json']).parent.parent
    _require({item.relative_to(history).as_posix() for item in history.rglob('*')} ==
             {upgrade, f'{upgrade}/barrier.json'}, 'ABORT_UNRELATED_HISTORY')

    candidate_root, source, target, archive_path = payload._paths(paths, record)
    expected = msi_inventory.read_expected_package(archive_path.with_name('EndpointAgent.msi'), binding.new_release)
    candidate_phase = payload._journal(candidate_root, record)
    _require(candidate_phase in ({'published'} if record.phase == 'switching' else {'published', 'cancelling', 'cancelled'})
             and source.exists() != target.exists(), 'ABORT_CANDIDATE_INVALID')
    payload._verify(target if target.exists() else source, expected)
    return record, plan, history, candidate_root, source, target, inputs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('check', 'apply'))
    mode = parser.parse_args().mode
    _require(getattr(sys, 'frozen', False) and has_verified_timestamp(Path(sys.executable), _PUBLISHER),
             'ABORT_SIGNED_IMAGE_REQUIRED')
    scope = json.loads((Path(sys._MEIPASS) / 'abort-scope.json').read_bytes())
    _require(_machine() == scope['machine'], 'ABORT_MACHINE_MISMATCH')
    paths = WindowsUpdatePaths.production()
    root = fence.state_root(paths)
    operation = scope['operation']
    archive = root / 'signed-pre-native-abort' / operation
    identity = NativeIdentity(os.getpid())
    try:
        _require(identity.value['sid'] == 'S-1-5-18', 'ABORT_SYSTEM_REQUIRED')
        with _windows_transaction(0), durable.installer_mutation_checkpoints(identity.assert_alive):
            record, plan, history, candidate_root, source, target, inputs = _admit(paths, scope, archive)
            _witness_msi_settlement()
            startup = {**plan['service_startup'], 'EndpointBrowserPolicy': plan['browser_startup']}
            with InstallerServices(paths, include_browser=True, checkpoint=identity.assert_alive) as services:
                actual = services.snapshot()
                _require(all(actual[name] in (value, {**value, 'start_type': 4})
                             for name, value in startup.items()), 'ABORT_SERVICE_CONFIG_CHANGED')
                if mode == 'check':
                    print('PRE_NATIVE_ABORT_SCOPE_VERIFIED', flush=True)
                    return 0
                provenance._archive_directory(provenance._archive_directory(root, archive.parent.name), archive.name)
                if record.phase == 'switching':
                    durable.write_bytes_atomic(archive / 'staged-update.before.json',
                        (root / 'staged-update.json').read_bytes(), trusted_root=archive,
                        max_bytes=65536, protect=lambda path: fence.protect_state(path, secret=True))
                    state.advance_staged_update(paths, operation, 'switching', 'rolling-back')
                services.restore_original(startup)
            if target.exists():
                payload._write(candidate_root, record, 'cancelling')
                durable.durable_rename_directory(target, source, trusted_root=paths.install_root.parent)
            payload._write(candidate_root, record, 'cancelled')
            for name, digest in scope['records'].items():
                leaf = _locate_file(root, archive, name, digest)
                if leaf == root / name:
                    dest = archive / name
                    if dest.parent != archive:
                        provenance._archive_directory(provenance._archive_directory(archive, 'children'), operation)
                    _move_file(leaf, dest)
            if history == root / 'upgrade-history':
                durable.durable_rename_directory(history, archive / history.name, trusted_root=root)
            _require(fence.read_fence(paths) is None and not compound.has_active_upgrade(paths), 'ABORT_NATIVE_GATE_REMAINS')
            state.advance_staged_update(paths, operation, 'rolling-back', 'rolled-back',
                                        safe_code='native_not_started_restored')
        import win32serviceutil
        for name in ('EndpointBrowserPolicy', 'EndpointAgent'):
            if inputs['service_states'][name] == 'Running':
                win32serviceutil.StartService(name)
                win32serviceutil.WaitForServiceStatus(name, 4, 45)
        print('PRE_NATIVE_ABORT_SOURCE_RUNNING', flush=True)
        return 0
    finally:
        identity.close()
