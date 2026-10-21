"""Bounded local proof from the connected candidate; no network owner here."""
from __future__ import annotations

import hashlib
import json
import math
import os
import sys
import time
from uuid import uuid4, UUID

from . import durable_state, installer_fence, staged_update_state as state
from .update_transaction import _read_state
from .acl import PyWin32AclAdapter

_LIMIT = 8192
_REQUEST = 'staged-trial-request.json'
_PROOF = 'staged-trial-proof.json'


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _uuid(value):
    return isinstance(value, str) and str(UUID(value)) == value


def _request(paths):
    path = installer_fence.state_root(paths) / _REQUEST
    installer_fence.assert_state_security(path)
    value = _read_state(path, _LIMIT)
    record = state.read_staged_update(paths)
    if (not isinstance(value, dict) or set(value) != {'operation_id', 'attempt_id', 'binding_sha256', 'created_ns'}
            or not _uuid(value['attempt_id']) or type(value['created_ns']) is not int or value['created_ns'] <= 0
            or record is None or record.phase != 'trial' or value['operation_id'] != record.binding.operation_id
            or value['attempt_id'] != record.attempt_id
            or value['binding_sha256'] != _digest(state._binding_value(record.binding))):
        raise ValueError('UPDATE_STATE_INVALID')
    return value, record


def begin_staged_trial(paths, operation_id: str) -> str:
    """Verify settled native bytes and select only the exact signed candidate."""
    from . import installation_provenance as provenance
    from .compound_upgrade_plan import has_active_upgrade
    durable_state.installer_mutation_checkpoint(required=True)
    record = state.read_staged_update(paths)
    if (record is None or record.binding.operation_id != operation_id
            or record.phase not in {'switching', 'native-settled'}
            or installer_fence.read_fence(paths) is not None or has_active_upgrade(paths)):
        raise ValueError('UPDATE_STATE_INVALID')
    from .staged_recovery import reboot_pending
    if reboot_pending(paths, record):
        raise ValueError('UPDATE_STATE_INVALID')
    binding = record.binding
    if provenance.verified_foundation_release(paths) != binding.new_release:
        raise ValueError('PROVENANCE_CONFLICT')
    selector = {'schema_version': 1, 'version': binding.candidate_version,
                'source_revision': binding.candidate_source_revision}
    raw = json.dumps(selector, separators=(',', ':')).encode()
    core = provenance._inspect_core_value(paths, raw, selector, binding.new_release['version'])
    if (core.identity.version != binding.candidate_version
            or core.identity.source_revision != binding.candidate_source_revision
            or core.identity.tree_sha256 != binding.candidate_tree_sha256):
        raise ValueError('PROVENANCE_CONFLICT')
    observed = paths.current_path.read_bytes()
    if observed != binding.selected_before and state._selector(observed) != selector:
        raise ValueError('PROVENANCE_CONFLICT')
    if record.phase == 'switching':
        state.advance_staged_update(paths, operation_id, 'switching', 'native-settled')
    for path, data in ((paths.previous_path, binding.selected_before), (paths.current_path, raw)):
        durable_state.write_bytes_atomic(path, data, trusted_root=paths.install_root, max_bytes=4096,
                                        protect=installer_fence.protect_state)
    attempt = str(uuid4())
    request = {'operation_id': operation_id, 'attempt_id': attempt,
               'binding_sha256': _digest(state._binding_value(binding)), 'created_ns': time.monotonic_ns()}
    root = installer_fence.state_root(paths)
    durable_state.write_json_atomic(root / _REQUEST, request, trusted_root=root, max_bytes=_LIMIT,
                                    protect=installer_fence.protect_state)
    state.advance_staged_update(paths, operation_id, 'native-settled', 'trial', attempt_id=attempt)
    return attempt


def _running_candidate(paths, binding):
    from pc_agent.version import AGENT_VERSION
    from pathlib import Path
    return (getattr(sys, 'frozen', False) and AGENT_VERSION == binding.candidate_version
            and os.path.normcase(str(Path(sys.executable).absolute())) ==
            os.path.normcase(str((paths.versions_root / binding.candidate_version / 'pc_agent.exe').absolute())))


def _write_proof(paths, value):
    durable_state.write_json_atomic(paths.updates_root / _PROOF, value, trusted_root=paths.updates_root,
                                    max_bytes=_LIMIT, protect=PyWin32AclAdapter().protect_update_path)


class StagedTrialProofWriter:
    """One runtime lifetime, with a new nonce and empty observations per connect."""
    def __init__(self, paths):
        self.paths = paths
        self.proof = None

    def _record(self, action, ack=None):
        try:
            request, record = _request(self.paths)
            if not _running_candidate(self.paths, record.binding):
                return False
            now = time.monotonic_ns()
            if now < request['created_ns']:
                return False
            if action == 'handshake':
                self.proof = {'operation_id': request['operation_id'], 'attempt_id': request['attempt_id'],
                    'request_sha256': _digest(request), 'connection_nonce': str(uuid4()), 'pid': os.getpid(),
                    'handshake_ns': now, 'heartbeat_ns': None, 'policy_ack': False, 'connected': True,
                    'sequence': 0, 'last_event_ns': now}
            elif (self.proof is None or self.proof['request_sha256'] != _digest(request)
                    or now < self.proof['last_event_ns']):
                return False
            elif action == 'disconnected':
                self.proof['connected'] = False
            elif not self.proof['connected']:
                return False
            elif action == 'heartbeat':
                self.proof['heartbeat_ns'] = now
            elif action == 'policy':
                self.proof['policy_ack'] = ack.status == 'APPLIED'
            self.proof['sequence'] += 1
            self.proof['last_event_ns'] = now
            _write_proof(self.paths, self.proof)
            return True
        except Exception:
            # A failed publication causes withheld acceptance, never WSS failure.
            self.proof = None
            return False

    def record_handshake(self): return self._record('handshake')
    def record_heartbeat(self): return self._record('heartbeat')
    def record_policy_ack(self, ack): return self._record('policy', ack)
    def record_disconnected(self): return self._record('disconnected')


def read_staged_trial_proof(paths):
    request, _ = _request(paths)
    value = _read_state(paths.updates_root / _PROOF, _LIMIT)
    if value is None:
        return None
    fields = {'operation_id', 'attempt_id', 'request_sha256', 'connection_nonce', 'pid', 'handshake_ns',
              'heartbeat_ns', 'policy_ack', 'connected', 'sequence', 'last_event_ns'}
    if (not isinstance(value, dict) or set(value) != fields
            or value['operation_id'] != request['operation_id'] or value['attempt_id'] != request['attempt_id']
            or value['request_sha256'] != _digest(request) or not _uuid(value['connection_nonce'])
            or any(type(value[key]) is not int or value[key] <= 0 for key in ('pid', 'sequence', 'handshake_ns', 'last_event_ns'))
            or type(value['policy_ack']) is not bool or type(value['connected']) is not bool
            or not request['created_ns'] <= value['handshake_ns'] <= value['last_event_ns'] <= time.monotonic_ns()
            or (value['heartbeat_ns'] is not None and (type(value['heartbeat_ns']) is not int
                or not value['handshake_ns'] <= value['heartbeat_ns'] <= value['last_event_ns']))):
        raise ValueError('UPDATE_STATE_INVALID')
    return value


def staged_trial_decision(paths, operation_id, attempt_id, *, elapsed_seconds, stable_seconds):
    try:
        if (any(type(value) not in (int, float) or not math.isfinite(value) or value < 0
                for value in (elapsed_seconds, stable_seconds)) or stable_seconds > elapsed_seconds):
            return 'rollback'
        request, _ = _request(paths)
        if request['operation_id'] != operation_id or request['attempt_id'] != attempt_id:
            return 'rollback'
        if elapsed_seconds >= 180:
            return 'rollback'
        proof = read_staged_trial_proof(paths)
        now = time.monotonic_ns()
        if proof is None or not proof['connected'] or proof['heartbeat_ns'] is None or not proof['policy_ack']:
            return 'waiting'
        observed_stable = (now - proof['handshake_ns']) / 1e9
        if (stable_seconds >= 60 and observed_stable >= 60
                and 0 <= (now - proof['heartbeat_ns']) / 1e9 <= 45):
            return 'accept'
        return 'waiting'
    except Exception:
        return 'rollback'


def accept_staged_trial(paths, operation_id, attempt_id, *, elapsed_seconds, stable_seconds):
    durable_state.installer_mutation_checkpoint(required=True)
    if staged_trial_decision(paths, operation_id, attempt_id,
            elapsed_seconds=elapsed_seconds, stable_seconds=stable_seconds) != 'accept':
        raise ValueError('UPDATE_STATE_INVALID')
    return state.advance_staged_update(paths, operation_id, 'trial', 'accepted')
