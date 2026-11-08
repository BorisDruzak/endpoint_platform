"""Canonical root-only Linux native owner. Reconcile never invokes RPM."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys

from pc_agent.platform.linux.installation_lifecycle import (
    InstallationPending, InstallationStore, LifecycleJournal)
from tools.release.linux_native_verifier import (
    NativeRPMVerifier, snapshot, run, ENV, LEGACY_SOURCE, LEGACY_MANIFEST, LEGACY_RPMS, PUBLISHER)
from pc_agent.platform.linux.installation_configuration import (
    configuration_file, STAGING_DROPIN, STAGING_ENVIRONMENT, STAGING_BYTES)

KEY = Path('/usr/share/endpoint-agent/endpoint-rpm-release.asc')
NATIVE_UNITS = ('endpoint-agent.service', 'endpoint-agent-update.path', 'endpoint-agent-update.service',
    'endpoint-support-access.service', 'endpoint-agent-setup-retry.timer')


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
    def __init__(self, journal, backend):
        self.journal, self.backend = journal, backend

    def operate(self, action, source, inputs, *, device_id):
        prior = self.journal.state()['operation']
        if prior and prior.get('phase') == 'preparing' and prior.get('exit_code') is None:
            self.reconcile(device_id=None)
        try:
            self.backend.preflight(action, source)
        except Exception:
            self.journal.preflight_refused(action, source)
            raise
        self.journal.begin(action, source, execution=self.journal.store.json('executor.json', missing=True))
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
        if not self.backend.matches(action, source):
            raise InstallationPending('native_final_state_mismatch')
        if action != 'remove':
            self.backend.arm_retry()
        if device_id is None:
            return 'enrollment_pending'
        if action == 'remove' and not operation.get('settled'):
            self.journal.cleanup_result(self.backend.cleanup(action))
        self.journal.settle(exact_native_state=True, device_id=device_id)
        return 'notification_pending'


def verify_pair(core, sensor, verifier):
    left = verifier(core)
    right = verifier(sensor) if sensor else None
    if left.package != 'endpoint-agent' or (right and (right.package != 'endpoint-agent-user-sensor'
        or (left.version, left.source_revision, left.frozen_manifest_sha256) !=
           (right.version, right.source_revision, right.frozen_manifest_sha256))):
        raise InstallationPending('native_pair_source_mismatch')
    return {'version': left.version, 'source_revision': left.source_revision,
        'core_nevra': left.nevra, 'core_rpm_sha256': left.sha256,
        'user_sensor_nevra': right.nevra if right else None,
        'user_sensor_rpm_sha256': right.sha256 if right else None}


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
        raw = self._systemctl('show', unit, '--property=LoadState,FragmentPath,DropInPaths,NeedDaemonReload,Environment,UnitFileState,ActiveState,Job,MainPID,ControlPID,InactiveEnterTimestampMonotonic,ActiveEnterTimestampMonotonic').decode()
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

    def _assert_configuration(self, proof):
        if set(proof.get('configuration', {})) != set(NATIVE_UNITS):
            raise InstallationPending('native_configuration_proof_required')
        environment = LifecycleJournal(self.store).state()['operation']['environment']
        for unit, expected in proof['configuration'].items():
            if self._configuration(unit, environment) != expected:
                raise InstallationPending('native_configuration_changed_preserved')

    def _assert_prepared(self):
        proof = self.store.json(self._preparation_name())
        self._assert_configuration(proof)
        environment = LifecycleJournal(self.store).state()['operation']['environment']
        for unit in NATIVE_UNITS:
            final = self._unit_state(unit)
            if self._configuration(unit, environment, final) != proof['configuration'][unit]:
                raise InstallationPending('native_configuration_changed_preserved')
            if final.get('LoadState') != 'not-found' and not self._quiescent(final):
                raise InstallationPending('native_unit_not_quiescent')

    @staticmethod
    def _quiescent(properties):
        return (properties.get('ActiveState') in ('inactive','failed')
            and all(properties.get(key) in (None,'','0') for key in ('Job','MainPID','ControlPID')))

    def _preparation_name(self):
        return 'preparation-' + LifecycleJournal(self.store).state()['operation']['id'] + '.json'

    def prepare(self, action, source):
        self.preflight(action, source)  # Recheck before the first owned mutation.
        ready = self.store.read('runtime-ready', missing=True)
        environment = LifecycleJournal(self.store).state()['operation']['environment']
        proof = {'ready': ready.decode() if ready else None, 'units': [],
            'configuration': {unit: self._configuration(unit, environment) for unit in NATIVE_UNITS}}
        name = self._preparation_name()
        self.store.save(name, proof)
        self._assert_configuration(proof)
        self.store.invalidate_ready()
        # Stop only owned units. A missing unit is allowed only when not loaded.
        for unit in NATIVE_UNITS:
            self._assert_configuration(proof)
            before = self._unit_state(unit)
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

    def recover_preparation(self):
        name = self._preparation_name()
        proof = self.store.json(name, missing=True)
        if proof is None:
            return  # Interrupted before the first durable preparation/mutation.
        self._assert_configuration(proof)
        for item in proof['units']:
            if item['restored']:
                continue
            current = self._unit_state(item['unit'])
            if item['after'] is None:
                if current != item['before']:
                    raise InstallationPending('preparation_stop_outcome_pending')
                item['restored'] = True  # Stop demonstrably never changed state.
                self.store.save(name, proof)
            elif current != item['after']:
                raise InstallationPending('preparation_unit_changed_preserved')
        from pc_agent.platform.linux.installation_user_sessions import assert_preparation_handoffs, handoff_active_sensors
        assert_preparation_handoffs(self.store)
        ready = self.store.read('runtime-ready', missing=True)
        original = proof['ready'].encode() if proof['ready'] else None
        if ready is not None and ready != original:
            raise InstallationPending('preparation_ready_changed_preserved')
        if original is not None and ready is None:
            self._assert_configuration(proof)
            self.store.write('runtime-ready', original)
        for item in reversed(proof['units']):
            if not item['restored']:
                # Never enable units or restore an externally changed unit.
                self._assert_configuration(proof)
                if self._unit_state(item['unit']) != item['after']:
                    raise InstallationPending('preparation_unit_changed_preserved')
                self._systemctl('start', item['unit'])
                item['restored'] = True
                self.store.save(name, proof)
        self._assert_configuration(proof)
        handoff_active_sensors(store=self.store, retained_only=True)

    def execute(self, action, inputs):
        # Final boundary after the durable invocation marker; refusal never runs RPM.
        self._assert_prepared()
        if action == 'remove':
            arguments = ['/usr/bin/rpm', '-e', 'endpoint-agent-user-sensor', 'endpoint-agent'] if len(inputs) == 2 else ['/usr/bin/rpm', '-e', 'endpoint-agent']
        else:
            arguments = ['/usr/bin/rpm', '-U', '--oldpackage', *map(str, inputs)]
        # Unknown timeout/interrupt is retained, never translated into native0.
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=180, env=ENV)
        return result.returncode

    def matches(self, action, source):
        result = subprocess.run(['/usr/bin/rpm', '-q', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n',
            'endpoint-agent', 'endpoint-agent-user-sensor'], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        if len(result.stdout) + len(result.stderr) > 4096:
            return False
        if not native_state_matches(action, source, result.returncode, result.stdout.decode('ascii'), result.stderr.decode('ascii')):
            return False
        if action != 'remove':
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


def retain_inputs(paths, store, verifier):
    """Keep exact signed native inputs outside removed/OTA-owned payload."""
    result = []
    for original in paths:
        with snapshot(original) as (private, digest):
            verifier(private)
            destination = store.paths.private / (digest + '.rpm')
            if destination.exists():
                with snapshot(destination) as (_, existing):
                    if existing != digest:
                        raise InstallationPending('retained_archive_conflict')
            else:
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
                with os.fdopen(fd, 'wb') as target, private.open('rb') as source:
                    while chunk := source.read(1024 * 1024):
                        target.write(chunk)
                    target.flush()
                    os.fsync(target.fileno())
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
            if identity.get('component') != 'setup' or identity.get('version') != '3.2.179':
                raise InstallationPending('executor_build_identity')
            with store.locked():
                store.write('executor.json', json.dumps({'path':str(target),'sha256':digest,
                    'source_revision':identity['source_revision'],'version':identity['version']}).encode())
            return
        if target.exists():
            with snapshot(target) as (_, existing):
                if existing != digest:
                    raise InstallationPending('executor_conflict')
        else:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
            with os.fdopen(fd, 'wb') as output, retained.open('rb') as source:
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
        os.execv(str(target), [str(target), *sys.argv[1:]])


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


def main(argv=None):
    if (sys.argv[1:] if argv is None else argv) == ['--build-info']:
        from pc_agent.platform.linux.native_build_identity import build_identity
        print(json.dumps(build_identity(),sort_keys=True))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'upgrade', 'remove', 'reconcile', 'notify', 'scriptlet'))
    parser.add_argument('--core-rpm', type=Path)
    parser.add_argument('--user-sensor-rpm', type=Path)
    parser.add_argument('--public-key', type=Path, default=KEY)
    parser.add_argument('--intent', choices=('install', 'upgrade', 'remove'))
    parser.add_argument('--legacy-kit-manifest', type=Path)
    parser.add_argument('--legacy-kit-signature', type=Path)
    args = parser.parse_args(argv)
    try:
        if os.name != 'posix' or os.geteuid() != 0:
            raise InstallationPending('native_root_required')
        store = InstallationStore()
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
            # A locked CLI owner is the only path in which hooks skip new intent.
            try:
                with store.locked():
                    LifecycleJournal(store).scriptlet_intent(args.intent, invocation=rpm_scriptlet_invocation())
            except Exception:
                # Confirm a real ancestor coordinator owns the pending receipt;
                # arbitrary lock contention/unsafe state is never permission.
                pending = LifecycleJournal(store).state()['operation']
                owner = pending.get('owner_pid') if pending else None
                parent = os.getppid()
                for _ in range(16):
                    if (parent == owner and pending.get('exit_code') is None and not pending.get('settled')
                        and pending.get('phase') == 'invocation_possible'):
                        start = Path(f'/proc/{parent}/stat').read_text().rsplit(')',1)[1].split()[19]
                        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
                        return 0 if start == pending.get('owner_starttime') and boot == pending.get('owner_boot_id') else 21
                    if parent <= 1:
                        break
                    fields = Path(f'/proc/{parent}/stat').read_text().rsplit(')',1)[1].split()
                    parent = int(fields[1])
                return 21
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
            device = None if args.action == 'reconcile' else canonical_identity()[0]
            coordinator = NativeCoordinator(journal, backend)
            if args.action == 'reconcile':
                if journal.state()['operation'] and journal.state()['operation'].get('bootstrap') == 'complete':
                    return 0
                if coordinator.reconcile(device_id=device) == 'preparation_recovered':
                    return 0
            else:
                if args.core_rpm is None:
                    raise InstallationPending('exact_native_input_required')
                verifier = NativeRPMVerifier(args.public_key, legacy_manifest=args.legacy_kit_manifest,
                    legacy_signature=args.legacy_kit_signature, legacy_core=args.core_rpm)
                paths = retain_inputs([args.core_rpm] + ([args.user_sensor_rpm] if args.user_sensor_rpm else []), store, verifier)
                source = verify_pair(paths[0], paths[1] if len(paths) == 2 else None, verifier)
                assert_executor_binding(source, verifier(paths[0]), store.json('executor.json'))
                if args.action == 'remove' and not backend.matches('install', source):
                    raise InstallationPending('remove_source_not_installed')
                coordinator.operate(args.action, source, paths, device_id=device)
        # Native owner/flock has exited before the bounded notification child.
        result = subprocess.run([sys.executable, 'notify'], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, env=ENV)
        return result.returncode
    except Exception:
        print('Endpoint native operation pending; retained receipt requires reconciliation.', file=sys.stderr)
        return 21


if __name__ == '__main__':
    raise SystemExit(main())
