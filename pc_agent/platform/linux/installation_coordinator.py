"""Canonical root-only Linux native owner. Reconcile never invokes RPM."""
import argparse
import asyncio
import errno
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
from uuid import UUID, uuid4

from pc_agent.platform.linux.installation_lifecycle import (
    InstallationPending, InstallationStore, LifecycleJournal)
from pc_agent.platform.linux.installation_durability import NativeDurability
from pc_agent.platform.linux.support_access_native import _sync_directory
from tools.release.linux_native_verifier import (
    NativeRPMVerifier, snapshot, run, ENV, LEGACY_SOURCE, LEGACY_MANIFEST, LEGACY_RPMS, PUBLISHER)
from pc_agent.platform.linux.installation_configuration import (
    configuration_file, STAGING_DROPIN, STAGING_ENVIRONMENT, STAGING_BYTES)
from pc_agent.version import AGENT_VERSION

KEY = Path('/usr/share/endpoint-agent/endpoint-rpm-release.asc')
NATIVE_UNITS = ('endpoint-agent.service', 'endpoint-agent-update.path', 'endpoint-agent-update.service',
    'endpoint-support-access.service', 'endpoint-agent-setup-retry.timer')


REPAIR_UNITS = NATIVE_UNITS + ('endpoint-agent-browser-policy.service',
    'endpoint-agent-update-rearm.timer', 'endpoint-agent-update-rearm.service')


def public_unit_state(properties):
    """Keep cached configuration identity without retaining arbitrary environment."""
    result = properties.copy()
    raw = result.pop('Environment', '')
    result['environment_sha256'] = hashlib.sha256(raw.encode()).hexdigest()
    try:
        cached = shlex.split(raw)
    except ValueError:
        cached = []
    result['staging_authority'] = {name: [item for item in cached
        if item.partition('=')[0] == name] == [name + '=' + value]
        for name, value in STAGING_ENVIRONMENT.items()}
    return result


class NativeCoordinator:
    def __init__(self, journal, backend, *, durability=None):
        self.journal, self.backend = journal, backend
        self.durability = durability

    def operate(self, action, source, inputs, *, device_id):
        prior = self.journal.state()['operation']
        if action != 'repair' and prior and prior.get('phase') == 'preparing' and prior.get('exit_code') is None:
            self.reconcile(device_id=None)
        try:
            identity = None
            if self.durability is not None and action != 'remove':
                identity = self.durability.identity_proof()
            if action == 'repair':
                state = self.journal.state()
                prior = state['operation']
                if (not prior or prior.get('unmanaged') or prior.get('source') != source
                    or not source.get('user_sensor_nevra') or len(inputs) != 2
                    or device_id is None or state['device_id'] != device_id
                    or not state['generation_id'] or not state['previous_event_id']
                    or not ((prior.get('action') in ('install', 'upgrade', 'repair')
                             and prior.get('settled') and prior.get('bootstrap') == 'complete'
                             and type(prior.get('exit_code')) is int and prior['exit_code'] == 0)
                            or (prior.get('action') == 'repair' and prior.get('phase') == 'not_started_recovered'))):
                    raise InstallationPending('repair_requires_exact_installed_pair')
                self.backend.check_repair_inputs(source)
            self.backend.preflight(action, source)
        except Exception:
            self.journal.preflight_refused(action, source)
            raise
        self.journal.begin(action, source, execution=self.journal.store.json('executor.json', missing=True),
                           durability_identity=identity)
        self.backend.prepare(action, source)
        self.journal.invocation_started()
        try:
            code = self.backend.execute(action, inputs)
        except Exception:
            raise InstallationPending('native_result_unknown_no_replay') from None
        self.journal.native_result(code)
        return self.reconcile(device_id=device_id)

    def reconcile(self, *, device_id):
        operation = self.journal.state()['operation']
        if operation and operation.get('phase') == 'preparing' and operation.get('exit_code') is None:
            self.backend.recover_preparation()
            self.journal.preparation_recovered()
            return 'preparation_recovered'
        if operation and operation.get('phase') == 'not_started_recovered':
            return 'preparation_recovered'
        if (not operation or operation.get('unmanaged') or type(operation.get('exit_code')) is not int
            or operation['exit_code'] != 0):
            raise InstallationPending('native_result_unknown_or_failed_no_replay')
        action, source = operation['action'], operation['source']
        self.require_native_state(operation)
        if action == 'repair':
            if device_id != self.journal.state()['device_id'] or device_id is None:
                raise InstallationPending('canonical_identity_changed')
            self.backend.check_repair_selector(source)
            self.backend.restore_repair()
            self.journal.complete_repair()
            return 'repair_complete'
        if action != 'remove':
            self.backend.arm_retry()
        if device_id is None:
            return 'enrollment_pending'
        if action == 'remove' and not operation.get('settled'):
            self.journal.cleanup_result(self.backend.cleanup(action))
        self.journal.settle(exact_native_state=True, device_id=device_id)
        return 'notification_pending'

    def require_native_state(self, operation):
        action, source = operation['action'], operation['source']
        if (self.durability is None or action == 'remove'
                or (operation['settled'] and 'durability' not in operation)):
            if not self.backend.matches(action, source):
                raise InstallationPending('native_final_state_mismatch')
            return
        proof = operation.get('durability')
        if not isinstance(proof, dict) or set(proof) != {'attempt', 'complete', 'identity'}:
            raise InstallationPending('native_durability_origin_unproved')
        self.durability.assert_owner(operation)
        if proof['complete'] is True:
            if not operation['settled'] and not self.durability.completed_identity_matches(operation, proof['identity']):
                raise InstallationPending('canonical_identity_changed')
            if not self.backend.matches(action, source):
                raise InstallationPending('native_final_state_mismatch')
            return
        if operation['settled'] or proof['complete'] is not False or not isinstance(proof['identity'], dict):
            raise InstallationPending('native_durability_origin_unproved')
        prior = proof['attempt']
        boot = self.durability.boot_id()
        if prior is not None and (not isinstance(prior, dict) or set(prior) != {'boot', 'id'}
                or prior['boot'] == boot or not self.durability.orderly_reboot_proved(operation, prior['boot'])):
            raise InstallationPending('native_durability_reboot_required')
        if self.durability.identity_proof() != proof['identity']:
            raise InstallationPending('canonical_identity_changed')
        attempt = {'boot': boot, 'id': str(uuid4())}
        self.journal.update_durability(operation['id'], attempt=attempt)
        try:
            if not self.backend.matches(action, source):
                raise InstallationPending('native_final_state_mismatch')
            self.durability.flush(action, source)
            if self.durability.identity_proof() != proof['identity'] or not self.backend.matches(action, source):
                raise InstallationPending('native_durability_final_state_changed')
        except Exception:
            self.backend.arm_retry()
            raise InstallationPending('native_durability_hold') from None
        self.journal.update_durability(operation['id'], attempt=attempt, complete=True)


def verify_pair(core, sensor, verifier):
    """Return the native source and its Core proof for Setup binding."""
    left = verifier(core)
    right = verifier(sensor) if sensor else None
    if left.package != 'endpoint-agent' or (right and (right.package != 'endpoint-agent-user-sensor'
        or (left.version, left.source_revision, left.frozen_manifest_sha256) !=
           (right.version, right.source_revision, right.frozen_manifest_sha256))):
        raise InstallationPending('native_pair_source_mismatch')
    source = {'version': left.version, 'source_revision': left.source_revision,
        'core_nevra': left.nevra, 'core_rpm_sha256': left.sha256,
        'user_sensor_nevra': right.nevra if right else None,
        'user_sensor_rpm_sha256': right.sha256 if right else None}
    return source, left


def assert_executor_binding(source, proof, execution):
    """Only the immutable historical156 source predates signed Setup closure."""
    if (proof.package != 'endpoint-agent' or source.get('version') != proof.version
        or source.get('source_revision') != proof.source_revision
        or source.get('core_nevra') != proof.nevra or source.get('core_rpm_sha256') != proof.sha256):
        raise InstallationPending('coordinator_source_proof_mismatch')
    legacy = {'version': '3.2.156', 'source_revision': LEGACY_SOURCE,
        'core_nevra': 'endpoint-agent-3.2.156-alt5.x86_64',
        'core_rpm_sha256': LEGACY_RPMS['endpoint-agent'],
        'user_sensor_nevra': None, 'user_sensor_rpm_sha256': None}
    sensor = {'user_sensor_nevra': 'endpoint-agent-user-sensor-3.2.156-alt5.x86_64',
        'user_sensor_rpm_sha256': LEGACY_RPMS['endpoint-agent-user-sensor']}
    if (source in (legacy, legacy | sensor) and proof.package == 'endpoint-agent'
        and proof.version == legacy['version'] and proof.nevra == legacy['core_nevra']
        and proof.sha256 == legacy['core_rpm_sha256'] and proof.source_revision == LEGACY_SOURCE
        and proof.frozen_manifest_sha256 == LEGACY_MANIFEST and proof.signer_fingerprint == PUBLISHER):
        return
    if (not isinstance(execution, dict) or not proof.setup_sha256
        or proof.setup_sha256 != execution.get('sha256')
        or proof.source_revision != execution.get('source_revision')
        or proof.version != execution.get('version')):
        raise InstallationPending('coordinator_not_bound_by_signed_source')


def native_state_matches(action, source, returncode, output, errors=''):
    expected = set() if action == 'remove' else {source['core_nevra']} | ({source['user_sensor_nevra']} if source['user_sensor_nevra'] else set())
    rows, actual, missing = output.splitlines() + errors.splitlines(), set(), 0
    if len(rows) != 2:
        return False
    for package in ('endpoint-agent','endpoint-agent-user-sensor'):
        absent = f'package {package} is not installed'
        expected_row = source.get('user_sensor_nevra' if package.endswith('user-sensor') else 'core_nevra')
        if rows.count(absent) == 1:
            missing += 1
        elif expected_row in expected and rows.count(expected_row) == 1:
            actual.add(expected_row)
        else:
            return False
    # ALT RPM4.13 reports the number of missing queried packages, on stderr.
    return actual == expected and returncode == missing


class RPMBackend:
    """Fixed production units/paths; no user-selectable root/database/scripts."""
    def __init__(self, store):
        self.store = store

    def _systemctl(self, *args):
        return run(['/usr/bin/systemctl', *args], timeout=25)

    def preflight(self, action, source):
        for name in ('pending_alt_update.json', 'rollback-request.json'):
            path = Path('/var/lib/endpoint-agent/updates')/name
            if path.exists() or path.is_symlink():
                raise InstallationPending('core_update_ownership_pending')
    def _unit_state(self, unit):
        names = ('LoadState,FragmentPath,DropInPaths,NeedDaemonReload,Environment,'
            'UnitFileState,ActiveState,Job,MainPID,ControlPID,InactiveEnterTimestampMonotonic,ActiveEnterTimestampMonotonic')
        operation = LifecycleJournal(self.store).state()['operation']
        if operation and operation.get('action') == 'repair':
            names += ',SubState'
        raw = self._systemctl('show', unit, '--property=' + names).decode()
        return public_unit_state(dict(row.split('=', 1) for row in raw.splitlines() if '=' in row))

    def _configuration_file(self, path):
        return configuration_file(path)

    def _configuration(self, unit, environment, properties=None):
        properties = self._unit_state(unit) if properties is None else properties
        if properties.get('NeedDaemonReload') != 'no':
            raise InstallationPending('native_configuration_reload_pending')
        result = {key: properties.get(key, '') for key in
            ('LoadState', 'FragmentPath', 'DropInPaths', 'UnitFileState', 'NeedDaemonReload',
             'environment_sha256', 'staging_authority')}
        if properties.get('LoadState') == 'not-found':
            if properties.get('FragmentPath') or properties.get('DropInPaths'):
                raise InstallationPending('foreign_native_unit_preserved')
            return result
        if (properties.get('LoadState') != 'loaded'
            or properties.get('FragmentPath') != '/usr/lib/systemd/system/' + unit):
            raise InstallationPending('foreign_native_unit_preserved')
        dropin = properties.get('DropInPaths')
        if dropin:
            if (unit != 'endpoint-agent.service' or dropin != STAGING_DROPIN
                or any(environment.get(name) != value for name, value in STAGING_ENVIRONMENT.items())):
                raise InstallationPending('foreign_native_unit_preserved')
            if properties.get('staging_authority') != dict.fromkeys(STAGING_ENVIRONMENT, True):
                raise InstallationPending('native_staging_cache_mismatch')
            proof = self._configuration_file(dropin)
            if proof['bytes'] != STAGING_BYTES or proof['identity'][2] != (stat.S_IFREG | 0o644):
                raise InstallationPending('foreign_native_staging_preserved')
            result['staging'] = proof
        fragment = self._configuration_file(properties['FragmentPath'])
        fragment['sha256'] = hashlib.sha256(fragment.pop('bytes').encode()).hexdigest()
        result['fragment'] = fragment
        return result

    def _assert_configuration(self, proof, *, repaired=False):
        if set(proof.get('configuration', {})) != set(REPAIR_UNITS if 'repair' in proof else NATIVE_UNITS):
            raise InstallationPending('native_configuration_proof_required')
        environment = LifecycleJournal(self.store).state()['operation']['environment']
        for unit, expected in proof['configuration'].items():
            actual = self._configuration(unit, environment)
            if repaired and 'fragment' in expected and 'fragment' in actual:
                # The signed RPM may replace the unit inode. Preserve all other
                # ownership, mode, fragment bytes, drop-ins and enablement proof.
                expected, actual = (
                    {**item, 'fragment': {**item['fragment'], 'identity': item['fragment']['identity'][2:5]}}
                    for item in (expected, actual)
                )
            if actual != expected:
                raise InstallationPending('native_configuration_changed_preserved')

    def _assert_prepared(self):
        proof = self.store.json(self._preparation_name())
        self._assert_configuration(proof)
        environment = LifecycleJournal(self.store).state()['operation']['environment']
        for unit in proof['configuration']:
            final = self._unit_state(unit)
            if self._configuration(unit, environment, final) != proof['configuration'][unit]:
                raise InstallationPending('native_configuration_changed_preserved')
            if final.get('LoadState') != 'not-found' and not self._quiescent(final):
                raise InstallationPending('native_unit_not_quiescent')
        return proof

    @staticmethod
    def _quiescent(properties):
        return (properties.get('ActiveState') in ('inactive','failed')
            and all(properties.get(key) in (None,'','0') for key in ('Job','MainPID','ControlPID')))

    def _preparation_name(self):
        return 'preparation-' + LifecycleJournal(self.store).state()['operation']['id'] + '.json'

    def prepare(self, action, source):
        self.preflight(action, source)  # Recheck before the first owned mutation.
        ready = self.store.read('runtime-ready', missing=True)
        operation = LifecycleJournal(self.store).state()['operation']
        environment = operation['environment']
        unit_names = REPAIR_UNITS if action == 'repair' else NATIVE_UNITS
        proof = {'ready': ready.decode() if ready else None, 'units': [],
            'configuration': {unit: self._configuration(unit, environment) for unit in unit_names}}
        if operation.get('previous_pending_bootstrap'):
            proof['partial_ready'] = {}
            for marker in ('support-pending', 'core-ready'):
                value = self.store.read(marker, missing=True)
                proof['partial_ready'][marker] = value.decode() if value is not None else None
        if action == 'repair':
            proof['repair'] = {'private': self._repair_private_inputs(),
                'original_units': {unit: self._unit_state(unit) for unit in unit_names},
                'sensors': self._repair_sensor_units()}
        name = self._preparation_name()
        self.store.save(name, proof)
        self._assert_configuration(proof)
        if operation.get('previous_pending_bootstrap'):
            # The original signed payload still owns boot readiness until dispatch.
            self.store.invalidate_ready(preserve_partial=True)
        else:
            self.store.invalidate_ready()
        # Stop only owned units. A missing unit is allowed only when not loaded.
        for unit in unit_names:
            self._assert_configuration(proof)
            before = self._unit_state(unit)
            if action == 'repair' and before != proof['repair']['original_units'][unit]:
                raise InstallationPending('repair_unit_activity_changed')
            if before.get('LoadState') == 'not-found':
                continue
            if self._configuration(unit, environment, before) != proof['configuration'][unit]:
                raise InstallationPending('native_configuration_changed_preserved')
            if before.get('ActiveState') != 'active':
                if self._quiescent(before):
                    continue
                raise InstallationPending('native_unit_transition_pending')
            if before.get('Job') not in (None,'','0'):
                raise InstallationPending('native_unit_job_pending')
            item = {'unit':unit, 'before':before, 'after':None, 'restored':False}
            proof['units'].append(item)
            self.store.save(name, proof)
            self._assert_configuration(proof)
            if self._unit_state(unit) != before:
                raise InstallationPending('preparation_unit_changed_before_stop')
            self._systemctl('stop', unit)
            item['after'] = self._unit_state(unit)
            if (not self._quiescent(item['after'])
                or self._configuration(unit, environment, item['after']) != proof['configuration'][unit]):
                raise InstallationPending('preparation_unit_changed_during_stop')
            self.store.save(name, proof)
        if action == 'remove':
            self._assert_configuration(proof)
            self._capture_native_selector(source)
            if source['user_sensor_nevra']:
                from pc_agent.platform.linux.installation_user_sessions import handoff_active_sensors
                self._assert_configuration(proof)
                handoff_active_sensors(stop=True, store=self.store)
            helper = Path('/usr/lib/endpoint-agent/browser-policy-helper')
            if helper.exists():
                # Failure aborts before RPM can delete ownership metadata.
                self._assert_configuration(proof)
                run([str(helper), '--relinquish'], timeout=25)
            self.store.write('browser-cleanup.json', json.dumps({'browser':'complete' if helper.exists() else 'not_applicable'}).encode())
        # Obsolete units disappear on rollback; never mutate enablement in preparation.
        self._assert_prepared()

    @staticmethod
    def _repair_private_inputs():
        from pwd import getpwnam
        from pc_agent.platform.linux.installation_notification import CA, CONFIG, DATA, read_secret
        account = getpwnam('endpoint-agent')
        proof = {}
        for path, uid, gid in ((CONFIG, 0, 0), (CA, 0, 0),
            (DATA/'device-credential', account.pw_uid, account.pw_gid),
            (DATA/'enrollment-identity.json', account.pw_uid, account.pw_gid)):
            before = path.lstat()
            contents = read_secret(path, uid=uid, gid=gid)
            try:
                acl = os.getxattr(path, 'system.posix_acl_access', follow_symlinks=False)
            except OSError as error:
                if error.errno not in (errno.ENODATA, errno.ENOTSUP):
                    raise
                acl = b''
            after = path.lstat()
            identity = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            if any(getattr(before, name) != getattr(after, name) for name in identity):
                raise InstallationPending('repair_private_inputs_changed')
            proof[path.name] = [after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid,
                hashlib.sha256(contents).hexdigest(), hashlib.sha256(acl).hexdigest()]
        return proof

    @staticmethod
    def _repair_sensor_units():
        from pc_agent.platform.linux.installation_user_sessions import session_ids, session_context, unit_properties
        result = {}
        for session in session_ids():
            context = session_context(session)
            if context is not None:
                result[session] = {'session': context, 'unit': unit_properties(context)}
        return result

    def _assert_repaired_inputs(self, proof):
        if self._repair_private_inputs() != proof['repair']['private']:
            raise InstallationPending('repair_private_inputs_changed')
        if self._repair_sensor_units() != proof['repair']['sensors']:
            raise InstallationPending('repair_sensor_session_changed')

    @staticmethod
    def _active_repair_unit(before, after):
        return (after.get('ActiveState') == 'active' and after.get('SubState') == before.get('SubState')
            and all(after.get(key) in (None, '', '0') for key in ('Job', 'ControlPID'))
            and (before.get('MainPID') in (None, '', '0') or after.get('MainPID') not in (None, '', '0')))

    def _assert_repair_units(self, proof):
        for unit, before in proof['repair']['original_units'].items():
            current = self._unit_state(unit)
            if before.get('ActiveState') == 'active':
                valid = self._active_repair_unit(before, current)
            else:
                valid = current == before
            if not valid:
                raise InstallationPending('repair_unit_activity_not_restored')

    def restore_repair(self):
        operation = LifecycleJournal(self.store).state()['operation']
        for component in ('core', 'sensor'):
            if self.store.json(f"repair-{operation['id']}-{component}.json", missing=True) != {
                'operation_id': operation['id'], 'component': component,
            }:
                raise InstallationPending('repair_scriptlets_incomplete')
        self.recover_preparation(repaired=True)

    def _refresh_repair_boot_proof(self, name, proof):
        operation = LifecycleJournal(self.store).state()['operation']
        if operation.get('action') != 'repair' or type(operation.get('exit_code')) is not int or operation['exit_code'] != 0:
            return
        repair = proof['repair']
        previous = repair.get('unit_state_boot_id', operation.get('owner_boot_id'))
        if not isinstance(previous, str):
            return
        try:
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            old_id, new_id = UUID(previous), UUID(boot)
            if not old_id.int or not new_id.int or str(old_id) != previous or str(new_id) != boot or boot == previous:
                return
        except (OSError, ValueError):
            return  # Without a proven new boot, keep the original strict comparisons.

        original_units = repair['original_units']
        stopped = {item['unit']: item for item in proof['units']}
        if (set(original_units) != set(REPAIR_UNITS) or len(stopped) != len(proof['units'])
                or set(stopped) != {unit for unit, state in original_units.items() if state.get('ActiveState') == 'active'}):
            raise InstallationPending('native_configuration_proof_required')
        for unit, original in original_units.items():
            current = self._unit_state(unit)
            item = stopped.get(unit)
            if item is None:
                if not self._same_unit_across_boot(original, current):
                    raise InstallationPending('repair_unit_activity_not_restored')
                original_units[unit] = current
                continue
            if item['before'] != original or not item['after'] or not self._quiescent(item['after']):
                raise InstallationPending('preparation_stop_outcome_pending')
            if not item['restored'] and self._same_unit_across_boot(item['after'], current):
                item['after'] = current
                continue
            # Support is independently enabled. It may already have regained
            # its original running state through the new boot's normal target.
            support_started = (
                unit == 'endpoint-support-access.service' and original.get('UnitFileState') == 'enabled'
                and original.get('SubState') == 'running' and original.get('MainPID', '0') != '0'
            )
            if (not (support_started or item['restored'])
                    or not self._matches_restored_unit(original, current)):
                raise InstallationPending('preparation_unit_changed_preserved')
            item['restored'] = True
            item['restored_unit_state'] = current
        # Record all observations together, before any marker or service action.
        # Further retries in this boot must honor the new timestamps.
        repair['unit_state_boot_id'] = boot
        self.store.save(name, proof)

    @staticmethod
    def _same_unit_across_boot(expected, current):
        timestamps = {'ActiveEnterTimestampMonotonic', 'InactiveEnterTimestampMonotonic'}
        return (expected.keys() == current.keys()
                and all(expected[key] == current[key] for key in expected.keys() - timestamps))

    def _matches_restored_unit(self, original, current):
        if not self._active_repair_unit(original, current):
            return False
        if 'MainPID' not in original:
            return (original.get('FragmentPath', '').endswith(('.path', '.timer'))
                    and self._same_unit_across_boot(original, current))
        old_pid, new_pid = original.get('MainPID', ''), current.get('MainPID', '')
        if not (old_pid.isdecimal() and new_pid.isdecimal()) or (int(old_pid) > 0) != (int(new_pid) > 0):
            return False
        return self._same_unit_across_boot(dict(original, MainPID=new_pid), current)

    def _check_rebased_repair(self, proof):
        if 'unit_state_boot_id' not in proof['repair']:
            return
        self._assert_repaired_inputs(proof)
        expected = dict(proof['repair']['original_units'])
        for item in proof['units']:
            expected[item['unit']] = item['restored_unit_state'] if item['restored'] else item['after']
        if any(self._unit_state(unit) != state for unit, state in expected.items()):
            raise InstallationPending('preparation_unit_changed_preserved')

    def recover_preparation(self, *, repaired=False):
        name = self._preparation_name()
        proof = self.store.json(name, missing=True)
        if proof is None:
            if repaired:
                raise InstallationPending('native_configuration_proof_required')
            return  # Interrupted before the first durable preparation/mutation.
        self._assert_configuration(proof, repaired=repaired)
        if repaired:
            self._assert_repaired_inputs(proof)
            self._refresh_repair_boot_proof(name, proof)
            self._check_rebased_repair(proof)
        for item in proof['units']:
            current = self._unit_state(item['unit'])
            if item['restored']:
                if repaired and not self._active_repair_unit(item['before'], current):
                    raise InstallationPending('repair_unit_activity_not_restored')
                continue
            if item['after'] is None:
                if current != item['before']:
                    raise InstallationPending('preparation_stop_outcome_pending')
                item['restored'] = True  # Stop demonstrably never changed state.
                self.store.save(name, proof)
            elif current != item['after']:
                if (repaired and 'unit_state_boot_id' not in proof['repair'] and item.get('restart_requested')
                        and self._active_repair_unit(item['before'], current)):
                    item['restored'] = True
                    self.store.save(name, proof)
                else:
                    raise InstallationPending('preparation_unit_changed_preserved')
        from pc_agent.platform.linux.installation_user_sessions import assert_preparation_handoffs, handoff_active_sensors
        if not repaired:
            assert_preparation_handoffs(self.store)
        markers = dict(proof.get('partial_ready', {}))
        markers['runtime-ready'] = proof['ready']
        for marker in ('support-pending', 'core-ready', 'runtime-ready'):
            if marker not in markers:
                continue
            current = self.store.read(marker, missing=True)
            original = markers[marker].encode() if markers[marker] is not None else None
            if current is not None and current != original:
                raise InstallationPending('preparation_ready_changed_preserved')
            if original is not None and current is None:
                self._assert_configuration(proof, repaired=repaired)
                if repaired:
                    self._check_rebased_repair(proof)
                self.store.write(marker, original)
        for item in reversed(proof['units']):
            if not item['restored']:
                # Never enable units or restore an externally changed unit.
                self._assert_configuration(proof, repaired=repaired)
                if self._unit_state(item['unit']) != item['after']:
                    raise InstallationPending('preparation_unit_changed_preserved')
                if repaired:
                    self._check_rebased_repair(proof)
                    item['restart_requested'] = True
                    self.store.save(name, proof)
                self._systemctl('start', item['unit'])
                if repaired:
                    current = self._unit_state(item['unit'])
                    if not self._active_repair_unit(item['before'], current):
                        raise InstallationPending('repair_unit_activity_not_restored')
                    if 'unit_state_boot_id' in proof['repair']:
                        if not self._matches_restored_unit(item['before'], current):
                            raise InstallationPending('repair_unit_activity_not_restored')
                        item['restored_unit_state'] = current
                item['restored'] = True
                self.store.save(name, proof)
        self._assert_configuration(proof, repaired=repaired)
        if repaired:
            self._check_rebased_repair(proof)
            self._assert_repair_units(proof)
            self._assert_repaired_inputs(proof)
        else:
            handoff_active_sensors(store=self.store, retained_only=True)

    def execute(self, action, inputs):
        # Final boundary after the durable invocation marker; refusal never runs RPM.
        proof = self._assert_prepared()
        if 'partial_ready' in proof:
            # No RPM may consume readiness granted to the previous payload.
            self.store.invalidate_ready()
        if action == 'remove':
            arguments = ['/usr/bin/rpm', '-e', 'endpoint-agent-user-sensor', 'endpoint-agent'] if len(inputs) == 2 else ['/usr/bin/rpm', '-e', 'endpoint-agent']
        elif action == 'repair':
            arguments = ['/usr/bin/rpm', '-U', '--replacepkgs', *map(str, inputs)]
        else:
            arguments = ['/usr/bin/rpm', '-U', '--oldpackage', *map(str, inputs)]
        # Unknown timeout/interrupt is retained, never translated into native0.
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=180, env=ENV)
        return result.returncode

    def matches(self, action, source):
        if not self.installed_packages_match(action, source):
            return False
        if action == 'remove':
            return True
        # RPM can return zero even when %post did not create the runtime selector.
        check = subprocess.run(
            ['/usr/lib/endpoint-agent/check-start-prerequisites', '--allow-unconfigured'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, env=ENV)
        return check.returncode == 0

    def check_repair_selector(self, source):
        with snapshot(Path('/opt/endpoint-agent/current.json')) as (frozen, _):
            if json.loads(frozen.read_bytes()) != {'schema_version': 1,
                'source_revision': source['source_revision'], 'version': source['version']}:
                raise InstallationPending('repair_requires_exact_native_selector')

    def check_repair_inputs(self, source):
        if not self.installed_packages_match('repair', source, verify_files=False):
            raise InstallationPending('repair_requires_exact_installed_pair')
        self.check_repair_selector(source)
        event_id = LifecycleJournal(self.store).state()['previous_event_id']
        if self.store.json('runtime-ready', missing=True) != {
            'operation_id': event_id, 'source_revision': source['source_revision']
        }:
            raise InstallationPending('repair_requires_completed_native_runtime')

    def installed_packages_match(self, action, source, *, verify_files=True):
        result = subprocess.run(['/usr/bin/rpm', '-q', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n',
            'endpoint-agent', 'endpoint-agent-user-sensor'], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        if len(result.stdout) + len(result.stderr) > 4096:
            return False
        if not native_state_matches(action, source, result.returncode, result.stdout.decode('ascii'), result.stderr.decode('ascii')):
            return False
        if verify_files and action != 'remove':
            # Verify selected native source payload, including setup/support closure.
            args = ['/usr/bin/rpm', '-V', 'endpoint-agent']
            if source['user_sensor_nevra']:
                args.append('endpoint-agent-user-sensor')
            check = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, env=ENV)
            if check.returncode or check.stdout:
                return False
        return True

    def arm_retry(self):
        if Path('/usr/lib/systemd/system/endpoint-agent-setup-retry.timer').is_file():
            self._systemctl('daemon-reload')
            self._systemctl('enable', '--now', 'endpoint-agent-setup-retry.timer')

    def cleanup(self, action):
        from pc_agent.platform.linux.support_access_service import finalize_removal
        from pc_agent.platform.linux.support_access_native import SupportPaths
        # Unit files are already absent after native erase; preun stopped them.
        paths = SupportPaths()
        if paths.private.exists():
            operation_id = LifecycleJournal(self.store).state()['operation']['id']
            previous = self.store.json('support-removal.json', missing=True)
            if previous and previous.get('operation_id') == operation_id:
                from pc_agent.platform.linux.support_access_native import PrivateStore, _directory
                support_store = PrivateStore(paths)
                with support_store.locked():
                    _directory(paths.public, 0o755)
                    if any(p.name != '.lock' for p in paths.private.iterdir()) or any(paths.public.iterdir()):
                        raise InstallationPending('support_state_changed_after_removal')
                result = previous['result']
            else:
                result = finalize_removal(known_native_exit_code=0)
                self.store.write('support-removal.json', json.dumps({'operation_id':operation_id, 'result':result}).encode())
            support = 'incomplete' if result['pending'] else 'complete'
        else:
            support = 'not_applicable'
        browser = self.store.json('browser-cleanup.json', missing=True)
        self._remove_captured_selector()
        return {'support': support, 'browser': browser['browser'] if browser else 'not_applicable'}

    def _capture_native_selector(self, source):
        selector = Path('/opt/endpoint-agent/current.json')
        self.store.write('native-selector.json', b'{"sha256":null,"value":null}')
        if not selector.exists():
            return
        with snapshot(selector) as (frozen, digest):
            raw = frozen.read_bytes()
        value = json.loads(raw)
        if value != {'schema_version': 1, 'source_revision': source['source_revision'], 'version': source['version']}:
            return  # Foreign OTA selection is never rewritten or deleted.
        self.store.write('native-selector.json', json.dumps({'sha256':digest,'value':value}).encode())

    def _remove_captured_selector(self):
        proof = self.store.json('native-selector.json', missing=True)
        path = Path('/opt/endpoint-agent/current.json')
        if proof is None or proof.get('sha256') is None or not path.exists():
            return
        with snapshot(path) as (_, digest):
            if digest != proof['sha256']:
                raise InstallationPending('selector_changed_preserved')
        path.unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _retain_verified_copy(source, destination, digest, *, mode, conflict):
    """Publish a durable, digest-named copy while holding the installation lock."""
    if os.path.lexists(destination):
        with snapshot(destination) as (_, existing):
            if existing != digest:
                raise InstallationPending(conflict)
    else:
        temporary = destination.parent / ('.retain-' + uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as target, source.open('rb') as original:
                while chunk := original.read(1024 * 1024):
                    target.write(chunk)
                target.flush()
                os.chmod(temporary, mode)
                os.fsync(target.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    _sync_directory(destination.parent)


def retain_inputs(paths, store, verifier):
    """Keep exact signed native inputs outside removed/OTA-owned payload."""
    result = []
    for original in paths:
        with snapshot(original) as (private, digest):
            verifier(private)
            destination = store.paths.private / (digest + '.rpm')
            _retain_verified_copy(private, destination, digest, mode=0o400,
                                  conflict='retained_archive_conflict')
            result.append(destination)
    return result


def retain_executor(store):
    """Onefile image is copied before RPM can remove it. No deferred onedir imports."""
    if not getattr(sys, 'frozen', False):
        raise InstallationPending('frozen_native_setup_required')
    executable = Path(sys.executable)
    with snapshot(executable) as (retained, digest):
        target = store.paths.private / ('setup-' + digest)
        if executable == target:
            from pc_agent.platform.linux.native_build_identity import build_identity
            identity = build_identity()
            if identity.get('component') != 'setup' or identity.get('version') != AGENT_VERSION:
                raise InstallationPending('executor_build_identity')
            with store.locked():
                register_retained_executor(store, {'path':str(target),'sha256':digest,
                    'source_revision':identity['source_revision'],'version':identity['version']})
            return
        with store.locked():
            _retain_verified_copy(retained, target, digest, mode=0o500,
                                  conflict='executor_conflict')
    # A successful exec never unwinds Python contexts. Validate the source again
    # and remove every temporary verification copy before handing off.
    os.execv(str(target), [str(target), *sys.argv[1:]])


def register_retained_executor(store, execution):
    pending = LifecycleJournal(store).state()['operation']
    if (pending and not pending.get('settled') and pending.get('execution') is not None
            and pending['execution'] != execution):
        raise InstallationPending('native_executor_pending_owner')
    store.write('executor.json', json.dumps(execution).encode())


def rpm_scriptlet_invocation():
    parent = os.getppid()
    for _ in range(16):
        if parent <= 1:
            break
        fields = Path(f'/proc/{parent}/stat').read_text().rsplit(')',1)[1].split()
        if Path(f'/proc/{parent}/exe').resolve() == Path('/usr/bin/rpm').resolve():
            return {'pid':parent,'start':fields[19],
                'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
        parent = int(fields[1])
    raise InstallationPending('scriptlet_native_ancestor_required')


def owns_native_scriptlet(pending):
    if not pending or pending.get('exit_code') is not None or pending.get('settled'):
        return False
    owner = pending.get('owner_pid')
    if pending.get('phase') != 'invocation_possible':
        return False
    parent = os.getppid()
    for _ in range(16):
        if parent <= 1:
            break
        fields = Path(f'/proc/{parent}/stat').read_text().rsplit(')', 1)[1].split()
        if parent == owner:
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            return fields[19] == pending.get('owner_starttime') and boot == pending.get('owner_boot_id')
        parent = int(fields[1])
    return False


def main(argv=None):
    if (sys.argv[1:] if argv is None else argv) == ['--build-info']:
        from pc_agent.platform.linux.native_build_identity import build_identity
        print(json.dumps(build_identity(),sort_keys=True))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'upgrade', 'remove', 'repair', 'reconcile',
                                          'notify', 'scriptlet', 'mark-orderly-reboot'))
    parser.add_argument('--core-rpm', type=Path)
    parser.add_argument('--user-sensor-rpm', type=Path)
    parser.add_argument('--public-key', type=Path, default=KEY)
    parser.add_argument('--intent', choices=('install', 'upgrade', 'remove', 'repair-check', 'repair-core-done', 'repair-sensor-done'))
    parser.add_argument('--legacy-kit-manifest', type=Path)
    parser.add_argument('--legacy-kit-signature', type=Path)
    args = parser.parse_args(argv)
    try:
        if os.name != 'posix' or os.geteuid() != 0:
            raise InstallationPending('native_root_required')
        store = InstallationStore()
        if args.action == 'mark-orderly-reboot':
            if not store.paths.private.exists():
                return 0
            jobs = run(['/usr/bin/systemctl', 'list-jobs', '--no-pager', '--no-legend', 'reboot.target'], timeout=5)
            if not any(row.split()[1:3] == [b'reboot.target', b'start'] for row in jobs.splitlines()):
                raise InstallationPending('native_durability_orderly_reboot_unproved')
            with store.locked():
                pending = LifecycleJournal(store).state()['operation']
                proof = pending.get('durability') if pending else None
                if (proof and proof.get('attempt') and proof.get('complete') is False
                        and type(pending.get('exit_code')) is int and pending['exit_code'] == 0
                        and not pending.get('settled') and not pending.get('unmanaged')):
                    durability = NativeDurability(store)
                    durability.assert_hook_owner(pending)
                    durability.mark_orderly_reboot(pending)
            return 0
        store.prepare()
        if args.action in ('notify', 'reconcile'):
            state = LifecycleJournal(store).state()
            environment = (state.get('operation') or {}).get('environment', {})
            from pc_agent.platform.linux.enrollment_origin import configured_endpoint_origin
            configured_endpoint_origin(environment)
            for name in ('ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT','CANARY_ENVIRONMENT','CANARY_APPROVED','ENDPOINT_AGENT_ORIGIN'):
                if name in environment:
                    os.environ[name] = environment[name]
                else:
                    os.environ.pop(name, None)
        if args.action == 'scriptlet':
            if args.intent in ('repair-check', 'repair-core-done', 'repair-sensor-done'):
                pending = LifecycleJournal(store).state()['operation']
                if not (pending and pending.get('action') == 'repair'
                        and pending.get('phase') == 'invocation_possible' and pending.get('exit_code') is None):
                    return 1
                if not owns_native_scriptlet(pending):
                    return 21
                if args.intent != 'repair-check':
                    component = args.intent.split('-')[1]
                    store.save(f"repair-{pending['id']}-{component}.json",
                        {'operation_id': pending['id'], 'component': component})
                return 0
            # A locked CLI owner is the only path in which hooks skip new intent.
            try:
                with store.locked():
                    LifecycleJournal(store).scriptlet_intent(args.intent, invocation=rpm_scriptlet_invocation())
            except Exception:
                # Confirm a real ancestor coordinator owns the pending receipt;
                # arbitrary lock contention/unsafe state is never permission.
                pending = LifecycleJournal(store).state()['operation']
                owned = owns_native_scriptlet(pending)
                return 0 if owned else 21
            return 0
        retain_executor(store)
        if args.action == 'notify':
            from pc_agent.platform.linux.installation_notification import notify
            asyncio.run(notify(store))
            return 0
        journal, backend = LifecycleJournal(store), RPMBackend(store)
        with store.locked():
            from pc_agent.platform.linux.installation_notification import canonical_identity
            # Reconcile resumes partial canonical delivery inside the notifier;
            # it must not block that SAME delivery before its recovery owner runs.
            operation = journal.state()['operation']
            repair = args.action == 'repair' or bool(args.action == 'reconcile' and operation and operation['action'] == 'repair')
            device = None if args.action == 'reconcile' and not repair else canonical_identity()[0]
            coordinator = NativeCoordinator(journal, backend, durability=NativeDurability(store))
            if args.action == 'reconcile':
                if operation and operation.get('bootstrap') == 'complete':
                    return 0
                if repair and operation.get('execution') != store.json('executor.json'):
                    raise InstallationPending('repair_executor_changed')
                result = coordinator.reconcile(device_id=device)
                if result == 'repair_complete' or (result == 'preparation_recovered' and not journal.bootstrap_pending()):
                    return 0
            else:
                if args.core_rpm is None:
                    raise InstallationPending('exact_native_input_required')
                verifier = NativeRPMVerifier(args.public_key, legacy_manifest=args.legacy_kit_manifest,
                    legacy_signature=args.legacy_kit_signature, legacy_core=args.core_rpm)
                paths = retain_inputs([args.core_rpm] + ([args.user_sensor_rpm] if args.user_sensor_rpm else []), store, verifier)
                source, core_proof = verify_pair(paths[0], paths[1] if len(paths) == 2 else None, verifier)
                assert_executor_binding(source, core_proof, store.json('executor.json'))
                if args.action == 'remove' and not backend.installed_packages_match('install', source):
                    raise InstallationPending('remove_source_not_installed')
                if coordinator.operate(args.action, source, paths, device_id=device) == 'repair_complete':
                    return 0
        # Native owner/flock has exited before the bounded notification child.
        result = subprocess.run([sys.executable, 'notify'], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, env=ENV)
        return result.returncode
    except Exception:
        print('Endpoint native operation pending; retained receipt requires reconciliation.', file=sys.stderr)
        return 21


if __name__ == '__main__':
    raise SystemExit(main())
