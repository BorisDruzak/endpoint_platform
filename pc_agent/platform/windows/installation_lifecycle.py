"""Privileged native facts and a retained, credential-free causal outbox.

The owner calls ``record_native_finish`` only after known native0 and verified
postconditions. Setup may deliver these facts; it cannot invent native work.
Callers serialize access using the existing installer/update transaction lock.
No sender thread, service, retry timer, or copied device credential is created.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import re
import stat
import sys
from uuid import UUID, uuid4, uuid5

from endpoint_contracts.runtime_payload import read_json, reject_reparse_ancestors
from . import durable_state, installer_fence

_MAX_BYTES = 4 * 1024 * 1024
_EVENT_NAMESPACE = UUID('847e53a8-25cd-47b4-832c-34b203231aed')


def _assert_private(path):
    installer_fence.assert_state_security(path, secret=True)


def _protect_private(path):
    installer_fence.protect_state(path, secret=True)


def _uuid(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError('INSTALLATION_STATE_INVALID')
    return value


def _fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names.split()):
        raise ValueError('INSTALLATION_STATE_INVALID')
    return dict(value)


def _aware_time(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError('INSTALLATION_STATE_INVALID')
    return value.isoformat().replace('+00:00', 'Z')


def _native(value):
    """Strict canonical wire subset, without the network-capable model stack.

    These local persisted facts must also pass the shared provider models at
    notification ingress. Contract parity tests bind both validation boundaries.
    """
    result = _fields(value, 'version product_code source_revision msi_sha256 exit_code')
    for name, pattern in (
        ('version', r'(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})'),
        ('product_code', r'\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}'),
        ('source_revision', r'[0-9a-f]{40}'), ('msi_sha256', r'[0-9a-f]{64}'),
    ):
        if not isinstance(result[name], str) or re.fullmatch(pattern, result[name]) is None:
            raise ValueError('INSTALLATION_STATE_INVALID')
    if type(result['exit_code']) is not int or result['exit_code'] != 0:
        raise ValueError('INSTALLATION_STATE_INVALID')
    return result


def _cleanup(value):
    result = _fields(value, 'support browser')
    if result['support'] not in ('complete', 'incomplete', 'not_applicable') or result['browser'] not in (
            'complete', 'external_preserved', 'conflict', 'failed', 'not_applicable'):
        raise ValueError('INSTALLATION_STATE_INVALID')
    return result


def _wire(value, *, acknowledgement=False):
    fields = 'schema_version device_id event_id generation_id sequence '
    fields += 'state received_at' if acknowledgement else 'previous_event_id action occurred_at native cleanup'
    result = _fields(value, fields)
    schema = 'endpoint_installation_event_ack_v1' if acknowledgement else 'endpoint_installation_event_v1'
    if result['schema_version'] != schema or type(result['sequence']) is not int or not 1 <= result['sequence'] <= 2147483647:
        raise ValueError('INSTALLATION_STATE_INVALID')
    for name in ('device_id', 'event_id', 'generation_id'):
        _uuid(result[name])
    if result['state' if acknowledgement else 'action'] not in ('installed', 'removed'):
        raise ValueError('INSTALLATION_STATE_INVALID')
    timestamp = 'received_at' if acknowledgement else 'occurred_at'
    result[timestamp] = _aware_time(result[timestamp])
    if not acknowledgement:
        previous = result['previous_event_id']
        if (result['sequence'] == 1) != (previous is None) or previous == result['event_id']:
            raise ValueError('INSTALLATION_STATE_INVALID')
        if previous is not None:
            _uuid(previous)
        result['native'] = _native(result['native'])
        result['cleanup'] = _cleanup(result['cleanup'])
    return result


def _read(path):
    _assert_private(path)
    reject_reparse_ancestors(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > _MAX_BYTES:
        raise ValueError('INSTALLATION_STATE_INVALID')
    return read_json(path.read_bytes(), _MAX_BYTES)


class NativeLifecycleOutbox:
    """Atomic journal with immutable transaction IDs and independently checked ack.

    All facts are retained, including delivered ones: deletion of a cursor cannot
    restart the server stream. An existing directory with missing/corrupt files
    fails closed. A full administrative wipe cannot be repaired from a hostname.
    """
    def __init__(self, root: Path):
        self.root = root

    def _write(self, name, value):
        _assert_private(self.root)
        durable_state.write_json_atomic(self.root/name, value, trusted_root=self.root,
            max_bytes=_MAX_BYTES, protect=_protect_private)

    def _load(self, *, create=False):
        reject_reparse_ancestors(self.root.parent)
        sentinel = self.root.parent/'installation-events-anchor.json'
        if not self.root.exists():
            if sentinel.exists():
                raise ValueError('INSTALLATION_STATE_INVALID')
            if not create:
                return None
            # Parent is installer-state, already established by native prepare.
            installer_fence.assert_state_security(self.root.parent)
            self.root.mkdir()
            _protect_private(self.root)
            anchor = {'schema_version':1, 'anchor_id':str(uuid4())}
            durable_state.write_json_atomic(sentinel, anchor, trusted_root=self.root.parent,
                max_bytes=4096, protect=_protect_private)
            self._write('anchor.json', anchor)
            self._write('journal.json', {'schema_version':1, 'facts':[]})
            durable_state.flush_directory(self.root.parent)
        reject_reparse_ancestors(self.root)
        _assert_private(self.root)
        try:
            anchor, state = _read(self.root/'anchor.json'), _read(self.root/'journal.json')
            if _read(sentinel) != anchor:
                raise ValueError()
            if set(anchor) != {'schema_version','anchor_id'} or anchor['schema_version'] != 1:
                raise ValueError()
            _uuid(anchor['anchor_id'])
            if set(state) != {'schema_version','facts'} or state['schema_version'] != 1 or not isinstance(state['facts'], list) or len(state['facts']) > 4096:
                raise ValueError()
            streams, transactions = {}, set()
            for fact in state['facts']:
                if set(fact) != {'transaction_id','action','occurred_at','native','cleanup','device_id','event','ack','delivery'}:
                    raise ValueError()
                tx = _uuid(fact['transaction_id'])
                if tx in transactions or fact['action'] not in {'installed','removed'}:
                    raise ValueError()
                transactions.add(tx)
                _native(fact['native'])
                _cleanup(fact['cleanup'])
                stamp = datetime.fromisoformat(fact['occurred_at'])
                if stamp.utcoffset() is None:
                    raise ValueError()
                if fact['device_id'] is None:
                    if fact['event'] is not None or fact['ack'] is not None or fact['delivery'] != ('awaiting_enrollment' if fact['action']=='installed' else 'undeliverable'):
                        raise ValueError()
                    continue
                device = _uuid(fact['device_id'])
                previous = streams.get(device)
                expected = self._event(anchor, fact, previous)
                if _wire(fact['event']) != expected:
                    raise ValueError()
                if fact['ack'] is not None:
                    self._check_ack(expected, fact['ack'])
                    if fact['delivery'] != 'delivered' or (previous is not None and previous['ack'] is None):
                        raise ValueError()
                elif fact['delivery'] != 'pending':
                    raise ValueError()
                streams[device] = fact
            return anchor, state
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
            raise ValueError('INSTALLATION_STATE_INVALID') from error

    @staticmethod
    def _event(anchor, fact, previous):
        return _wire(dict(
            schema_version='endpoint_installation_event_v1', device_id=fact['device_id'],
            event_id=str(uuid5(_EVENT_NAMESPACE, fact['transaction_id']+':'+fact['action'])),
            generation_id=str(uuid5(UUID(anchor['anchor_id']), fact['device_id'])),
            sequence=1 if previous is None else previous['event']['sequence']+1,
            previous_event_id=None if previous is None else previous['event']['event_id'],
            action=fact['action'], occurred_at=fact['occurred_at'],
            native=fact['native'], cleanup=fact['cleanup']))

    @staticmethod
    def _check_ack(event, payload):
        ack = _wire(payload, acknowledgement=True)
        if any(ack[k] != event[k] for k in ('device_id','event_id','generation_id','sequence')) or ack['state'] != event['action']:
            raise ValueError('INSTALLATION_ACK_MISMATCH')
        return ack

    def record(self, *, transaction_id, action, device_id, native, cleanup, occurred_at):
        anchor, state = self._load(create=True)
        _uuid(transaction_id)
        if device_id is not None:
            _uuid(device_id)
        native = _native(native)
        cleanup = _cleanup(cleanup)
        if action not in {'installed','removed'} or occurred_at.utcoffset() is None:
            raise ValueError('INSTALLATION_STATE_INVALID')
        for fact in state['facts']:
            if fact['transaction_id'] == transaction_id:
                if any(fact[k] != value for k,value in (('action',action),('native',native),('device_id',device_id))):
                    raise ValueError('INSTALLATION_NATIVE_CONFLICT')
                return fact['event']
        if len(state['facts']) >= 4096:
            raise ValueError('INSTALLATION_STATE_FULL')
        fact = dict(transaction_id=transaction_id, action=action, device_id=device_id,
            native=native, cleanup=cleanup, occurred_at=occurred_at.isoformat(), event=None, ack=None,
            delivery='pending' if device_id else 'awaiting_enrollment' if action=='installed' else 'undeliverable')
        if device_id:
            previous = next((f for f in reversed(state['facts']) if f['device_id']==device_id), None)
            fact['event'] = self._event(anchor, fact, previous)
        state['facts'].append(fact)
        self._write('journal.json', state)
        return fact['event']

    def bind_installation(self, transaction_id, device_id):
        anchor, state = self._load()
        _uuid(device_id)
        fact = next((f for f in state['facts'] if f['transaction_id']==transaction_id), None)
        if fact is None or fact['action'] != 'installed' or fact['device_id'] not in (None, device_id):
            raise ValueError('INSTALLATION_NATIVE_CONFLICT')
        if fact['device_id'] is not None:
            return
        # Binding an earlier fact after later device facts would reorder history.
        index = state['facts'].index(fact)
        if any(f['device_id']==device_id for f in state['facts'][index+1:]):
            raise ValueError('INSTALLATION_NATIVE_CONFLICT')
        previous = next((f for f in reversed(state['facts'][:index]) if f['device_id']==device_id), None)
        fact['device_id'], fact['delivery'] = device_id, 'pending'
        fact['event'] = self._event(anchor, fact, previous)
        self._write('journal.json', state)

    def pending(self, device_id):
        loaded = self._load()
        return [] if loaded is None else [f['event'] for f in loaded[1]['facts'] if f['device_id']==device_id and f['ack'] is None]

    def deliver(self, device_id, sender, *, maximum=8):
        loaded = self._load()
        if loaded is None:
            return 'not_applicable'
        _, state = loaded
        count = 0
        for fact in state['facts']:
            if fact['device_id'] != device_id or fact['ack'] is not None:
                continue
            if count >= maximum:
                return 'pending'
            try:
                received = self._check_ack(fact['event'], sender(fact['event']))
                fact['ack'], fact['delivery'] = received, 'delivered'
                self._write('journal.json', state)
            except Exception:
                return 'pending'
            count += 1
        return 'delivered'


def native_action(capability):
    # A recovery/finalization or replacement child cannot claim ordinary removal.
    if capability.get('recovery') or capability.get('uninstall_finalization') or any(
            name in capability for name in ('staged_rollback','recovery_parent')):
        return None
    if 'compound' in capability and capability['operation'] != 'install':
        return None
    return {'install':'installed','uninstall':'removed'}.get(capability['operation'])


def packaged_extension_id():
    root = Path(sys._MEIPASS) if getattr(sys,'frozen',False) else Path(__file__).resolve().parents[3]
    value = (root/'browser_sensor'/'extension-id.txt').read_text(encoding='ascii').strip()
    if not re.fullmatch('[a-p]{32}', value):
        raise ValueError('INVALID_BROWSER_IDENTITY')
    return value


def relinquish_browser_policy(*, registry=None, extension_id=None):
    from .browser_policy import (APPROVED_UPDATE_URL, MARKER_PATH, BrowserPolicyApplicator,
                                BrowserPolicyConflict, WindowsPolicyRegistry)
    families = {}
    try:
        registry = registry if registry is not None else WindowsPolicyRegistry()
        app = BrowserPolicyApplicator(registry, extension_id=extension_id or packaged_extension_id(), update_url=APPROVED_UPDATE_URL)
    except Exception:
        return {'browser':'failed','families':{'chrome':'failed','yandex':'failed'}}
    for family in ('chrome','yandex'):
        try:
            marker = registry.read(MARKER_PATH, family)
            app.relinquish(family)
            families[family] = 'complete' if marker is not None else 'external_preserved'
        except BrowserPolicyConflict:
            families[family] = 'conflict'
        except Exception:
            families[family] = 'failed'
    result = next((state for state in ('failed','conflict','external_preserved') if state in families.values()), 'complete')
    return {'browser':result,'families':families}


def _identity(data_root):
    from .support_bootstrap import assert_bootstrap_file
    from pc_agent.enrollment_identity import read_enrollment_device_id
    path = data_root/'enrollment-identity.json'
    assert_bootstrap_file(path)
    return str(read_enrollment_device_id(path))


def outbox_for(paths):
    return NativeLifecycleOutbox(installer_fence.state_root(paths)/'installation-events')


def record_native_finish(paths, capability, expected, *, support_cleanup=None):
    """Only called inside authenticated known-native0 finish, before fence unlink."""
    action = native_action(capability)
    if action is None:
        return None
    durable_state.installer_mutation_checkpoint(required=True)
    box = outbox_for(paths)
    # Retries preserve the original cleanup facts and occurrence timestamp.
    loaded = box._load()
    if loaded:
        prior = next((f for f in loaded[1]['facts'] if f['transaction_id']==capability['transaction_id']),None)
        if prior:
            if prior['action'] != action or prior['native']['msi_sha256'] != expected.package.sha256:
                raise ValueError('INSTALLATION_NATIVE_CONFLICT')
            return prior
    browser = relinquish_browser_policy() if action=='removed' else {'browser':'not_applicable','families':{}}
    try:
        device = _identity(paths.pending_path.parents[1])
    except Exception:
        data_root = paths.pending_path.parents[1]
        if any((data_root/name).exists() or (data_root/name).is_symlink()
               for name in ('enrollment-identity.json','device-credential')):
            raise ValueError('INSTALLATION_AUTHORITY_UNAVAILABLE') from None
        device = None
    package = expected.package
    box.record(transaction_id=capability['transaction_id'], action=action, device_id=device,
        native=dict(version=package.version, product_code=package.product_code,
                    source_revision=expected.identity.source_revision, msi_sha256=package.sha256, exit_code=0),
        cleanup={'support':support_cleanup or 'not_applicable','browser':browser['browser']},
        occurred_at=datetime.now(UTC))
    return {'browser_cleanup':browser, 'notification':'pending' if device else 'awaiting_enrollment' if action=='installed' else 'undeliverable'}
