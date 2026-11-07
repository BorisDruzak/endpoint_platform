"""Root-private native receipts and credential-free causal outbox.

The caller holds one installation flock across every mutation. A scriptlet can
only record intent. No recovery path infers an exit status from package presence.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from uuid import uuid4

from endpoint_contracts.linux_installation_lifecycle import LinuxNativeSource, LinuxInstallationEventV1
from pc_agent.platform.linux.support_access_native import PrivateStore, SupportPaths, _directory

INSTALLATION_ROOT = Path('/var/lib/endpoint-agent-installation')


class InstallationPending(RuntimeError):
    pass


class InstallationStore(PrivateStore):
    def __init__(self, root=INSTALLATION_ROOT):
        super().__init__(SupportPaths(private=Path(root), public=Path(root)))

    def prepare(self):
        _directory(self.paths.private, 0o700, create=True)

    def invalidate_ready(self):
        # Caller owns the installation lock. Validate the node before unlinking.
        if self.read('runtime-ready', missing=True) is not None:
            (self.paths.private/'runtime-ready').unlink()
            descriptor = os.open(self.paths.private, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


class LifecycleJournal:
    def __init__(self, store):
        self.store = store

    def state(self):
        return self.store.json('state.json', missing=True) or {'operation': None,
            'sequence': 0, 'previous_event_id': None, 'generation_id': None,
            'acknowledged': 0, 'device_id': None}

    def _save(self, state):
        self.store.write('state.json', json.dumps(state, separators=(',', ':'), allow_nan=False).encode())

    def begin(self, action, source, *, execution=None):
        state = self.state()
        if action not in ('install', 'upgrade', 'remove'):
            raise InstallationPending('invalid_native_action')
        prior = state['operation']
        if prior and not prior.get('settled') and prior.get('phase') != 'not_started_recovered':
            raise InstallationPending('exclusive_native_recovery_required')
        if state['sequence'] - state['acknowledged'] >= 128:
            raise InstallationPending('outbox_delivery_required')
        source = LinuxNativeSource.model_validate(source).model_dump(mode='json')
        operation = {'id': str(uuid4()), 'action': action, 'source': source,
            'exit_code': None, 'phase': 'preparing', 'settled': False, 'event': None, 'bootstrap': 'pending' if action != 'remove' else 'not_applicable',
            'execution': execution, 'cleanup': {'support': 'not_applicable', 'browser': 'not_applicable'}}
        from pc_agent.platform.linux.enrollment_origin import configured_endpoint_origin
        configured_endpoint_origin()  # Validate explicit staging markers before native work.
        operation['environment'] = {name:os.environ[name] for name in
            ('ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT','CANARY_ENVIRONMENT','CANARY_APPROVED') if name in os.environ}
        operation['owner_pid'] = os.getpid()
        if os.name == 'posix':
            operation['owner_starttime'] = Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]
            operation['owner_boot_id'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        state['operation'] = operation
        self._save(state)
        return operation

    def preflight_refused(self, action, source):
        self.store.write('refused-' + str(uuid4()) + '.json', json.dumps({
            'action': action, 'source': source, 'phase': 'preflight_refused',
            'occurred_at': datetime.now(timezone.utc).isoformat()}).encode())

    def invocation_started(self):
        state = self.state()
        if not state['operation'] or state['operation'].get('phase') != 'preparing':
            raise InstallationPending('native_preparation_not_owned')
        # Must be durable BEFORE calling RPM, including the subprocess spawn.
        state['operation']['phase'] = 'invocation_possible'
        self._save(state)

    def preparation_recovered(self):
        state = self.state()
        operation = state['operation']
        if not operation or operation.get('phase') != 'preparing' or operation.get('exit_code') is not None:
            raise InstallationPending('preparation_not_recoverable')
        operation.update(phase='not_started_recovered', bootstrap='not_applicable')
        self.store.write('receipt-' + operation['id'] + '.json', json.dumps(operation).encode())
        self._save(state)

    def native_result(self, code):
        state = self.state()
        operation = state['operation']
        if type(code) is not int or not operation or operation.get('exit_code') is not None or operation.get('unmanaged'):
            raise InstallationPending('native_result_not_owned')
        operation['exit_code'] = code
        self._save(state)

    def cleanup_result(self, cleanup):
        state = self.state()
        if not state['operation'] or type(state['operation'].get('exit_code')) is not int or state['operation']['exit_code'] != 0:
            raise InstallationPending('known_native_zero_required')
        state['operation']['cleanup'] = cleanup
        self._save(state)

    def scriptlet_intent(self, action, *, invocation=None):
        # CLI-owned hooks never enter this method while the parent's flock is held.
        self.store.invalidate_ready()
        state = self.state()
        if (state['operation'] and state['operation'].get('unmanaged') and state['operation']['action'] == action
            and invocation is not None and state['operation'].get('invocation') == invocation):
            return  # The same pre/post pair retains one unknown receipt.
        if state['operation'] and not state['operation'].get('settled'):
            raise InstallationPending('exclusive_native_recovery_required')
        state['operation'] = {'id': str(uuid4()), 'action': action, 'exit_code': None,
            'settled': False, 'unmanaged': True, 'bootstrap': 'blocked', 'invocation':invocation}
        self._save(state)

    def settle(self, *, exact_native_state, device_id):
        state = self.state()
        operation = state['operation']
        if (not operation or operation.get('unmanaged') or type(operation.get('exit_code')) is not int
            or operation['exit_code'] != 0 or exact_native_state is not True):
            raise InstallationPending('known_native_zero_and_exact_state_required')
        if state['device_id'] not in (None, device_id):
            raise InstallationPending('canonical_identity_changed')
        if operation['settled']:
            return operation['event']
        action = 'removed' if operation['action'] == 'remove' else 'installed'
        # Upgrade remains in the same generation; reinstall follows removal.
        prior = self.store.json(f"event-{state['sequence']}.json", missing=True) if state['sequence'] else None
        generation = state['generation_id']
        if generation is None or (action == 'installed' and prior and prior['action'] == 'removed'):
            generation = str(uuid4())
        event = LinuxInstallationEventV1(schema_version='endpoint_linux_installation_event_v1',
            device_id=device_id, event_id=operation['id'], generation_id=generation,
            sequence=state['sequence']+1, previous_event_id=state['previous_event_id'], action=action,
            occurred_at=datetime.now(timezone.utc), native={**operation['source'], 'exit_code': 0},
            cleanup=operation['cleanup']).model_dump(mode='json')
        # Event and index are recoverable: same operation id, no duplicate generation.
        existing = self.store.json(f"event-{event['sequence']}.json", missing=True)
        if existing is not None:
            if existing['event_id'] != operation['id']:
                raise InstallationPending('causal_queue_conflict')
            event = LinuxInstallationEventV1.model_validate(existing).model_dump(mode='json')
        self.store.write(f"event-{event['sequence']}.json", json.dumps(event, separators=(',', ':')).encode())
        operation.update(settled=True, event=event)
        state.update(sequence=event['sequence'], previous_event_id=event['event_id'], generation_id=event['generation_id'], device_id=device_id)
        self.store.write('receipt-' + operation['id'] + '.json', json.dumps(operation, separators=(',', ':')).encode())
        self._save(state)
        return event

    def pending_events(self):
        state = self.state()
        return [LinuxInstallationEventV1.model_validate(self.store.json(f'event-{number}.json')).model_dump(mode='json')
            for number in range(state['acknowledged'] + 1, state['sequence'] + 1)]

    def acknowledge(self, ack):
        state = self.state()
        event = self.store.json(f"event-{state['acknowledged']+1}.json", missing=True)
        if not event or any(ack.get(key) != event[key] for key in ('device_id', 'event_id', 'generation_id', 'sequence')):
            raise InstallationPending('causal_ack_mismatch')
        state['acknowledged'] += 1
        self._save(state)

    def bootstrap_pending(self):
        operation = self.state()['operation']
        return bool(operation and operation.get('settled') and operation.get('bootstrap') == 'pending')

    def request_bootstrap(self):
        if not self.bootstrap_pending():
            raise InstallationPending('no_pending_native_bootstrap')

    def complete_bootstrap(self):
        self.request_bootstrap()
        state = self.state()
        state['operation']['bootstrap'] = 'complete'
        self._save(state)

    def registration_complete(self):
        self.request_bootstrap()
        state = self.state()
        state['operation']['registration'] = 'complete'
        self._save(state)
