"""One-machine recovery for a settled, fresh native Setup transaction.

The scope, original public enrollment configuration and observer are sealed in
the signed executable. The original MSI, native grant and capture stay in place.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import sys
from uuid import uuid4

from . import durable_state, installer_data_security, installer_fence, msi_inventory
from . import native_setup_continuation as continuation
from . import staged_recovery, staged_update_state, update_transaction as transaction
from .authenticode_timestamp import has_verified_timestamp
from .installer_transaction_bridge import NativeIdentity, _read_capability, _request_data
from .native_setup_observer import _PUBLISHER, read_packaged_observer
from .update_paths import WindowsUpdatePaths


def _assert_scope(expected, actual):
    if expected != actual:
        raise ValueError('RECOVERY_SCOPE_MISMATCH')


def _sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _machine():
    import winreg

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Cryptography',
                       access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        guid = winreg.QueryValueEx(key, 'MachineGuid')[0]
    return hashlib.sha256(guid.lower().encode('ascii')).hexdigest()


def _witness_msi_settlement():
    import win32event
    import win32api

    msi = ctypes.WinDLL('msi.dll', winmode=0x800)
    begin = msi.MsiBeginTransactionW
    begin.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.UINT),
                      ctypes.POINTER(wintypes.HANDLE))
    begin.restype = wintypes.UINT
    end = msi.MsiEndTransaction
    end.argtypes = (wintypes.DWORD,)
    end.restype = wintypes.UINT
    close = msi.MsiCloseHandle
    close.argtypes = (wintypes.UINT,)
    close.restype = wintypes.UINT
    handle = wintypes.UINT()
    event = wintypes.HANDLE()
    opened = False
    try:
        opened = begin(f'EndpointRecoverySettlement-{uuid4()}', 0, ctypes.byref(handle),
                       ctypes.byref(event)) == 0
        if not opened or not handle.value or not event.value or end(0) != 0:
            raise ValueError('RECOVERY_MSI_BUSY')
        opened = False
        if win32event.WaitForSingleObject(event.value, 0) != win32event.WAIT_OBJECT_0:
            raise ValueError('RECOVERY_MSI_UNSETTLED')
    finally:
        if opened:
            end(0)
        if handle.value:
            close(handle)
        if event.value:
            win32api.CloseHandle(event.value)


class _RecoveryOwner:
    """In-process owner of a signed, scope-bound recovery. No pipe capabilities."""

    def __init__(self, capability, checkpoint):
        self.capability = capability
        self.checkpoint = checkpoint

    def request(self, phase, result):
        self.checkpoint()
        if (phase != 'complete' or set(result) != {'operation_id', 'observer', 'users'}
                or result['operation_id'] != self.capability['transaction_id']
                or result['observer'] != 'provisioned'
                or result['users'] not in {'running', 'not-required', 'session-unavailable'}):
            raise ValueError('RECOVERY_SCOPE_MISMATCH')


def _validate_original(paths, scope, identity, *, settled):
    operation = scope['transaction']
    root = installer_fence.state_root(paths)
    cache = root.parent / 'installer-cache' / f"msi-{scope['msi']}"
    grant_path = continuation._grant_path(paths, operation)
    completed = grant_path.with_name('completed.json')
    hold = root / 'native-continuation.json'
    media = cache / 'EndpointAgent.msi'
    original_setup = cache / 'EndpointAgentSetup.exe'
    original_helper = cache / 'endpoint-installer-host.exe'
    with ExitStack() as pins:
        for leaf in (grant_path, completed, media, original_setup, original_helper):
            pins.enter_context(durable_state._pinned_copy_source(leaf))
        if not settled:
            pins.enter_context(durable_state._pinned_copy_source(hold))
        _assert_scope(scope, {
            'machine': _machine(), 'transaction': operation, 'grant': _sha(grant_path),
            'completion': _sha(completed), 'msi': _sha(media), 'setup': _sha(original_setup),
            'helper': _sha(original_helper), 'hold': scope['hold'] if settled else _sha(hold),
        })
        grant = staged_recovery._read(grant_path)
        original = _read_capability(paths, grant['native_session_id'])
        if (continuation._digest(original) != grant['native_capability_sha256']
                or grant['owner'] != original['owner'] or grant['compound_plan_sha256'] is not None
                or original['transaction_id'] != operation or original['operation'] != 'install'
                or original['recovery'] or original['uninstall_finalization']
                or original['selected'] is not None or original['previous'] is not None
                or original['helper_sha256'] != scope['helper']
                or original['package']['package_sha256'] != scope['msi']
                or original['package']['version'] != '3.2.193'
                or grant['completion_relative'] != f'transactions/{operation}/completed.json'
                or grant['native_fence_relative'] != 'transaction.json'):
            raise ValueError('RECOVERY_ORIGINAL_AUTHORITY_INVALID')
        capability = {**original, 'owner': identity.value}
        continuation.read_continuation_grant(paths, capability)
        from .compound_upgrade_plan import _read, has_active_upgrade
        completion = _read(completed, maximum=16384)
        if (completion != grant['completion'] or has_active_upgrade(paths)
                or installer_fence.read_fence(paths) is not None
                or staged_update_state.read_staged_update(paths) is not None):
            raise ValueError('RECOVERY_NATIVE_NOT_SETTLED')
        request = {**_request_data(paths, capability), 'session_id': capability['session_id'], 'recovery': True}
        expected = msi_inventory.read_expected_package(media, capability['package'])
        if continuation.provenance.verified_foundation_release(paths) != capability['package']:
            raise ValueError('RECOVERY_FOUNDATION_MISMATCH')
        with msi_inventory.verified_foundation_bytes(expected, paths.install_root):
            if settled:
                finished = grant_path.with_name('native-continuation-finished.json')
                if (continuation.pending_continuation(paths) is not None
                        or staged_recovery._read(finished) != {
                            'schema_version': 1, 'grant_sha256': continuation._digest(grant)}):
                    raise ValueError('RECOVERY_FINISH_UNVERIFIED')
            else:
                if continuation.pending_continuation(paths) != {
                    key: capability[key] for key in ('transaction_id', 'package')
                }:
                    raise ValueError('RECOVERY_HOLD_MISMATCH')
                continuation._assert_recovery_owners_dead(paths, capability, grant)
                installer_data_security.verify_preserved(paths, request)
        return capability


def _enroll(paths, resources, args):
    from . import setup_entry

    data_root = paths.updates_root.parent
    if setup_entry._classify_installation_state(data_root) != 'clean':
        raise ValueError('RECOVERY_ENROLLMENT_STATE_CONFLICT')
    public = setup_entry._read_public_setup_config(resources / 'setup-config.json')
    if public['installer_version'] != '3.2.193':
        raise ValueError('RECOVERY_ENROLLMENT_RELEASE_MISMATCH')
    config = setup_entry.SetupConfig(endpoint_origin=public['endpoint_origin'],
        ca_file=resources / 'endpoint-ca.crt', installer_version=public['installer_version'],
        installer_release_id=public['installer_release_id'])
    config.validate()
    args.quiet = True
    return setup_entry._enroll_fresh_install(args, data_root, config, setup_entry._installed_provisioner())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('check', 'apply', 'enroll'))
    args = parser.parse_args()
    if not getattr(sys, 'frozen', False):
        raise ValueError('RECOVERY_SIGNED_EXE_REQUIRED')
    executable = Path(sys.executable)
    identity = NativeIdentity(os.getpid())
    try:
        if not has_verified_timestamp(executable, _PUBLISHER):
            raise ValueError('RECOVERY_SIGNATURE_INVALID')
        resources = Path(sys._MEIPASS)
        scope = json.loads((resources / 'recovery-scope.json').read_bytes())
        paths = WindowsUpdatePaths.production()
        settled = args.mode == 'enroll'
        with transaction._windows_transaction(0):
            capability = _validate_original(paths, scope, identity, settled=settled)
            if not settled:
                _witness_msi_settlement()
                asset, _, _ = read_packaged_observer(resources / 'setup-updater')
                if not has_verified_timestamp(asset, _PUBLISHER):
                    raise ValueError('RECOVERY_OBSERVER_SIGNATURE_INVALID')
            if args.mode == 'apply':
                owner = _RecoveryOwner(capability, identity.assert_alive)
                print(json.dumps(continuation.recover_native_continuation(owner, paths)), flush=True)
            elif args.mode == 'check':
                print('RECOVERY_SCOPE_VERIFIED', flush=True)
        return _enroll(paths, resources, args) if settled else 0
    finally:
        identity.close()
