"""Opt-in isolated root/RPMdb harness; never touches installed Endpoint state."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import hashlib
import io
import tarfile
import sys
import textwrap

import pytest

pytestmark = pytest.mark.skipif(os.name != 'posix' or not os.environ.get('ENDPOINT_NATIVE_HARNESS_ROOT'),
    reason='requires explicitly owned isolated Linux native harness')


@pytest.fixture
def root():
    base = Path(os.environ['ENDPOINT_NATIVE_HARNESS_ROOT'])
    assert base.parent == Path('/var/tmp') and base.name.startswith('endpoint-linux178-install-harness-')
    assert base.resolve() == base and base.stat().st_uid == 0 and base.stat().st_mode & 0o777 == 0o700
    assert json.loads((base/'owner.json').read_text()) == {'purpose':'task4-isolated-native-harness'}
    path = Path(tempfile.mkdtemp(dir=base, prefix='case-'))
    return path


def test_native_flock_concurrency_symlink_hardlink_and_mode_refusal(root):
    from pc_agent.platform.linux.installation_lifecycle import InstallationStore
    from pc_agent.platform.linux.support_access import SupportError
    store = InstallationStore(root/'state')
    store.prepare()
    with store.locked():
        with pytest.raises(SupportError):
            with InstallationStore(root/'state').locked():
                pass
        outside = root/'outside'
        outside.write_text('preserved')
        outside.chmod(0o600)
        (root/'state/link').symlink_to(outside)
        with pytest.raises(SupportError):
            store.write('link', b'changed')
        assert outside.read_text() == 'preserved'
        os.link(outside, root/'state/hardlink')
        with pytest.raises(SupportError):
            store.read('hardlink')
        unsafe = root/'state/unsafe'
        unsafe.write_bytes(b'unchanged')
        unsafe.chmod(0o666)
        with pytest.raises(SupportError):
            store.write('unsafe', b'changed')


def test_native_snapshot_detects_mutation_replacement_and_symlink(root):
    from tools.release.linux_native_verifier import snapshot, VerificationError
    original = root/'input.rpm'
    original.write_bytes(b'original')
    original.chmod(0o600)
    with pytest.raises(VerificationError):
        with snapshot(original) as (copy, digest):
            assert copy.read_bytes() == b'original'
            original.write_bytes(b'changed')
    link = root/'symlink'
    link.symlink_to(original)
    with pytest.raises((OSError, VerificationError)):
        with snapshot(link):
            pass


@pytest.mark.parametrize('existing_target', [False, True])
def test_native_executor_successful_real_exec_leaves_no_verification_snapshots(root, existing_target):
    snapshots = root/'snapshots'
    snapshots.mkdir(mode=0o700)
    executable = root/'vendor-setup'
    payload = ('#!'+sys.executable+'\n'+textwrap.dedent('''\
        import hashlib, json, os, stat, sys
        from pathlib import Path
        target = Path(sys.argv[0])
        info = target.stat()
        print(json.dumps({'path':str(target), 'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
            'mode':stat.S_IMODE(info.st_mode), 'uid':info.st_uid, 'nlink':info.st_nlink,
            'snapshots':[p.name for p in Path(sys.argv[1]).iterdir()]}))
    ''')).encode()
    executable.write_bytes(payload)
    executable.chmod(0o500)
    digest = hashlib.sha256(payload).hexdigest()
    state = root/'state'
    state.mkdir(mode=0o700)
    target = state/('setup-'+digest)
    if existing_target:
        target.write_bytes(payload)
        target.chmod(0o500)
    runner = '''\
import sys, tempfile
from pc_agent.platform.linux import installation_coordinator as c
from pc_agent.platform.linux.installation_lifecycle import InstallationStore
store = InstallationStore(sys.argv[2])
store.prepare()
tempfile.tempdir = sys.argv[3]
sys.frozen = True
sys.executable = sys.argv[1]
sys.argv = [sys.executable, sys.argv[3]]
c.retain_executor(store)
raise RuntimeError('exec handoff returned')
'''
    result = subprocess.run([sys.executable, '-c', runner, str(executable), str(state), str(snapshots)],
        capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {'path':str(target), 'sha256':digest,
        'mode':0o500, 'uid':0, 'nlink':1, 'snapshots':[]}
    assert list(snapshots.iterdir()) == []
    assert target.read_bytes() == executable.read_bytes() == payload


def test_real_rpm_install_upgrade_rollback_failure_remove_in_isolated_database(root):
    from pc_agent.platform.linux.installation_coordinator import NativeCoordinator
    from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationStore, InstallationPending
    build = root/'build'
    for name in ('BUILD','BUILDROOT','RPMS','SOURCES','SPECS','SRPMS'):
        (build/name).mkdir(parents=True,mode=0o700)
    packages = []
    for version in ('1','2'):
        spec = build/'SPECS/fixture.spec'
        spec.write_text(f'''Name: endpoint-task4-fixture
Version: {version}
Release: alt1
Summary: Isolated native fixture
License: MIT
Group: Development/Other
BuildArch: noarch
AutoReqProv: no
%description
Not an Endpoint package; no service or scriptlets.
%install
mkdir -p %buildroot/opt/task4-fixture
echo {version} > %buildroot/opt/task4-fixture/value
%files
/opt/task4-fixture/value
''')
        result = subprocess.run(['/usr/bin/rpmbuild','-bb','--define','_allow_root_build 1',
            '--define',f'_topdir {build}',str(spec)],capture_output=True,timeout=45)
        assert result.returncode == 0, result.stderr.decode()[-400:]
        packages.append(next((build/'RPMS').rglob(f'endpoint-task4-fixture-{version}-*.rpm')))
    native = root/'native'
    native.mkdir(mode=0o700)
    prefix = ['/usr/bin/rpm','--root',str(native),'--dbpath','/rpmdb']
    assert subprocess.run([*prefix,'--initdb'],capture_output=True).returncode == 0
    class Backend:
        version = '1'
        cleanup_count = 0
        def preflight(self, action, source): pass
        def recover_preparation(self): pass
        def prepare(self, action, source): pass
        def execute(self, action, inputs):
            args = ['-e','--noscripts','--nodeps','endpoint-task4-fixture'] if action == 'remove' else ['-U','--noscripts','--nodeps','--oldpackage',str(inputs[0])]
            return subprocess.run([*prefix,*args],capture_output=True,timeout=30).returncode
        def matches(self, action, source):
            result = subprocess.run([*prefix,'-q','--qf','%{VERSION}','endpoint-task4-fixture'],capture_output=True,timeout=10)
            return result.returncode == 1 if action == 'remove' else result.returncode == 0 and result.stdout.decode() == self.version
        def cleanup(self, action):
            self.cleanup_count += 1
            return {'support':'not_applicable','browser':'not_applicable'}
        def arm_retry(self): pass
    backend = Backend()
    state = InstallationStore(root/'state')
    state.prepare()
    source = {'version':'3.2.183','source_revision':'a'*40,'core_nevra':'endpoint-agent-3.2.183-alt6.x86_64','core_rpm_sha256':'b'*64}
    with state.locked():
        journal = LifecycleJournal(state)
        coordinator = NativeCoordinator(journal,backend)
        for action, version, package in [('install','1',packages[0]),('upgrade','2',packages[1]),('upgrade','1',packages[0]),('remove','1',packages[0])]:
            backend.version = version
            coordinator.operate(action,source,[package],device_id='29a8bed4-2894-40f7-89fb-07b3c7f633fe')
        assert backend.cleanup_count == 1
        assert [x['action'] for x in journal.pending_events()] == ['installed','installed','installed','removed']
        with pytest.raises(InstallationPending):
            coordinator.operate('install',source,[root/'missing.rpm'],device_id='29a8bed4-2894-40f7-89fb-07b3c7f633fe')
        assert journal.state()['operation']['exit_code'] != 0
        with pytest.raises(InstallationPending):
            coordinator.reconcile(device_id='29a8bed4-2894-40f7-89fb-07b3c7f633fe')
        assert backend.cleanup_count == 1
    assert not (native/'opt/task4-fixture/value').exists()
    from pc_agent.platform.linux.installation_coordinator import native_state_matches
    absent = subprocess.run([*prefix,'-q','--qf','%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n',
        'endpoint-agent','endpoint-agent-user-sensor'],capture_output=True,text=True,env={**os.environ,'LC_ALL':'C'})
    assert native_state_matches('remove', source, absent.returncode, absent.stdout, absent.stderr)


def test_actual_spec_builds_two_packages_with_identical_complete_source_closure(root):
    from tools.release.linux_native_verifier import run, read_cpio, inspect_source, NATIVE_PATHS
    repository = Path(__file__).resolve().parents[2]
    build = root/'build'
    for name in ('BUILD','BUILDROOT','RPMS','SOURCES','SPECS','SRPMS'):
        (build/name).mkdir(parents=True,mode=0o700)
    sources = build/'SOURCES'
    native = repository/'packaging/alt/SOURCES'
    for path in native.iterdir():
        if path.is_file():
            (sources/path.name).write_bytes(path.read_bytes())
    for destination, relative in {
        'README.md':'packaging/alt/README.md', 'endpoint-agent-update.service':'deploy/agent/alt/endpoint-agent-update.service',
        'endpoint-agent-update.path':'deploy/agent/alt/endpoint-agent-update.path',
        'apply-pending-alt-update.sh':'deploy/agent/alt/apply-pending-alt-update.sh',
        'build_linux_native_manifest.py':'tools/build_linux_native_manifest.py',
        'endpoint-rpm-release.asc':'packaging/alt/pilot/endpoint-rpm-release.asc',
        'browser_policy_protocol.py':'pc_agent/browser_policy_protocol.py',
        'browser_policy.py':'pc_agent/platform/linux/browser_policy.py',
        'seqpacket.py':'pc_agent/platform/linux/seqpacket.py',
        'browser_policy_helper.py':'pc_agent/platform/linux/browser_policy_helper.py',
    }.items():
        (sources/destination).write_bytes((repository/relative).read_bytes())
    dummy = b'#!/bin/sh\nexit 0\n'
    for name in ('launcher','endpoint-kde-probe','endpoint-agent-setup.bin'):
        (sources/name).write_bytes(dummy)
    (sources/'foreground.js').write_text('// native fixture\n')
    (sources/'extension-id.txt').write_text('a'*32)
    (sources/'browser-native-host.json').write_text('{}')
    manifest = json.dumps({'schema_version':1,'version':'3.2.183','source_revision':'a'*40,'files':[]}).encode()
    def archive(path, entries):
        with tarfile.open(path,'w:gz') as target:
            for name, raw in entries.items():
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                info.mode = 0o755 if name.endswith(('endpoint-agent','endpoint-support-access')) else 0o644
                target.addfile(info,io.BytesIO(raw))
    archive(sources/'endpoint-agent-linux_amd64-3.2.183.tar.gz', {'manifest.json':manifest,
        'endpoint-agent/endpoint-agent':dummy,'endpoint-agent/_internal/fixture':b'fixture'})
    (sources/'endpoint-agent-linux_amd64-3.2.183.manifest.json').write_text('{}')
    archive(sources/'endpoint-support-access.tar.gz',{'endpoint-support-access':dummy,'_internal/fixture':b'support'})
    spec = build/'SPECS/endpoint-agent.spec'
    spec.write_bytes((repository/'packaging/alt/endpoint-agent.spec').read_bytes())
    result = subprocess.run(['/usr/bin/rpmbuild','-bb','--nodeps','--with','user_sensor','--with','native_setup',
        '--define','_allow_root_build 1','--define',f'_topdir {build}','--define','agent_version 3.2.183',
        '--define','source_revision '+'a'*40,str(spec)],capture_output=True,timeout=60)
    assert result.returncode == 0, result.stderr.decode()[-4000:]
    rpms = list((build/'RPMS').rglob('*.rpm'))
    assert len(rpms) == 2
    common = []
    for rpm in rpms:
        package = run(['/usr/bin/rpm','-qp','--qf','%{NAME}',str(rpm)]).decode()
        with tempfile.TemporaryFile(dir=root) as payload:
            run(['/usr/bin/rpm2cpio',str(rpm)],output_file=payload,limit=10*1024*1024)
            files, selected = read_cpio(payload)
        raw = selected[NATIVE_PATHS[package]]
        files.pop(NATIVE_PATHS[package])
        common.append(inspect_source(raw,package,'3.2.183',files,
            core_manifest_digest=hashlib.sha256(manifest).hexdigest() if package == 'endpoint-agent' else None))
    assert common[0] == common[1]


def test_actual_immutable_156_signatures_source_pair_and_tamper_refusal(root):
    from tools.release.linux_native_verifier import NativeRPMVerifier, VerificationError, LEGACY_SOURCE, LEGACY_MANIFEST
    kit = Path('/root/endpoint-unified156-linux-20261026/kit')
    original = kit/'extracted/endpoint-alt-pilot-3.2.156-1'
    core = original/'endpoint-agent-3.2.156-alt5.x86_64.rpm'
    sensor = original/'endpoint-agent-user-sensor-3.2.156-alt5.x86_64.rpm'
    verifier = NativeRPMVerifier(original/'endpoint-rpm-release.asc',
        legacy_manifest=kit/'public/endpoint-alt-pilot-3.2.156-1.manifest.json',
        legacy_signature=kit/'public/endpoint-alt-pilot-3.2.156-1.manifest.sig', legacy_core=core)
    values = [verifier(core),verifier(sensor)]
    assert all(x.source_revision == LEGACY_SOURCE and x.frozen_manifest_sha256 == LEGACY_MANIFEST for x in values)
    corrupted = root/'tampered.rpm'
    raw = bytearray(sensor.read_bytes())
    raw[-1] ^= 1
    corrupted.write_bytes(raw)
    corrupted.chmod(0o600)
    with pytest.raises(VerificationError):
        verifier(corrupted)
    with pytest.raises(VerificationError):
        NativeRPMVerifier(original/'endpoint-rpm-release.asc')(sensor)
    wrong = root/'untrusted.asc'
    wrong.write_bytes(b'not the pinned publisher')
    with pytest.raises(VerificationError):
        NativeRPMVerifier(wrong)(sensor)


def test_completed_local_removal_receipt_is_not_replaced_by_missing_token_retry(root, monkeypatch):
    from pc_agent.platform.linux.installation_lifecycle import InstallationStore, LifecycleJournal, InstallationPending
    from pc_agent.platform.linux.installation_coordinator import RPMBackend
    from pc_agent.platform.linux import support_access_native as native, support_access_service as service
    paths = native.SupportPaths(private=root/'support-private',public=root/'support-public')
    native.PrivateStore(paths).prepare()
    monkeypatch.setattr(native,'SupportPaths',lambda: paths)
    calls = []
    def final(**kwargs):
        calls.append(kwargs)
        return {'unregistered':True,'pending':False,'private_state_removed':True}
    monkeypatch.setattr(service,'finalize_removal',final)
    store = InstallationStore(root/'state')
    store.prepare()
    with store.locked():
        journal = LifecycleJournal(store)
        journal.begin('remove',{'version':'3.2.183','source_revision':'a'*40,
            'core_nevra':'endpoint-agent-3.2.183-alt6.x86_64','core_rpm_sha256':'b'*64})
        journal.native_result(0)
        backend = RPMBackend(store)
        assert backend.cleanup('remove')['support'] == 'complete'
        assert backend.cleanup('remove')['support'] == 'complete'
        assert len(calls) == 1
        unexpected = paths.private/'config.json'
        unexpected.write_bytes(b'preserve-new-unknown-state')
        unexpected.chmod(0o600)
        with pytest.raises(InstallationPending):
            backend.cleanup('remove')
        assert unexpected.read_bytes() == b'preserve-new-unknown-state'


def test_native_prepare_closes_boot_gate_before_any_native_operation(root, monkeypatch):
    from pc_agent.platform.linux.installation_lifecycle import InstallationStore, LifecycleJournal
    from pc_agent.platform.linux.installation_coordinator import RPMBackend
    store = InstallationStore(root/'state')
    store.prepare()
    with store.locked():
        store.write('runtime-ready',b'previous-known-bootstrap')
        LifecycleJournal(store).begin('upgrade',{'version':'3.2.183','source_revision':'a'*40,
            'core_nevra':'endpoint-agent-3.2.183-alt6.x86_64','core_rpm_sha256':'b'*64})
        backend = RPMBackend(store)
        monkeypatch.setattr(backend,'_systemctl',lambda *_: b'LoadState=not-found\nNeedDaemonReload=no\n')
        backend.prepare('upgrade',{'version':'3.2.183'})
        assert not (store.paths.private/'runtime-ready').exists()


def test_native_preparation_recovery_restores_only_exact_owned_stopped_unit(root, monkeypatch):
    from pc_agent.platform.linux.installation_lifecycle import InstallationStore, LifecycleJournal, InstallationPending
    from pc_agent.platform.linux.installation_coordinator import RPMBackend, NativeCoordinator
    from pc_agent.platform.linux import installation_user_sessions as sensors
    store = InstallationStore(root/'state')
    store.prepare()
    unit = 'endpoint-agent.service'
    current = {'LoadState':'loaded','FragmentPath':'/usr/lib/systemd/system/'+unit,
        'DropInPaths':'','NeedDaemonReload':'no','UnitFileState':'enabled','ActiveState':'active','InactiveEnterTimestampMonotonic':'10'}
    backend = RPMBackend(store)
    commands = []
    def systemctl(*args):
        commands.append(args)
        if args[0] == 'show':
            return ('\n'.join(k+'='+v for k,v in current.items()) if args[1] == unit else 'LoadState=not-found\nNeedDaemonReload=no').encode()
        if args[0] == 'stop': current.update(ActiveState='inactive',InactiveEnterTimestampMonotonic='20')
        if args[0] == 'start': current.update(ActiveState='active')
        return b''
    monkeypatch.setattr(backend,'_systemctl',systemctl)
    monkeypatch.setattr(backend,'_configuration_file',lambda _: {'identity':[1,2],'bytes':'[Service]\n'})
    monkeypatch.setattr(sensors,'session_ids',lambda: [])
    with store.locked():
        journal = LifecycleJournal(store)
        journal.begin('upgrade',{'version':'3.2.183','source_revision':'a'*40,
            'core_nevra':'endpoint-agent-3.2.183-alt6.x86_64','core_rpm_sha256':'b'*64})
        store.write('runtime-ready',b'old-proof')
        backend.prepare('upgrade',{'version':'3.2.183'})
        assert current['ActiveState'] == 'inactive'
        coordinator = NativeCoordinator(journal,backend)
        # An explicit state change defeats restoration until original proof is
        # available; no service action or gate restoration is inferred.
        current['UnitFileState'] = 'masked'
        with pytest.raises(InstallationPending): coordinator.reconcile(device_id=None)
        assert store.read('runtime-ready',missing=True) is None
        current['UnitFileState'] = 'enabled'
        assert coordinator.reconcile(device_id=None) == 'preparation_recovered'
        assert current['ActiveState'] == 'active'
        assert store.read('runtime-ready') == b'old-proof'
        assert ('start',unit) in commands and not any('enable' in x for x in commands)
        assert store.json('receipt-'+journal.state()['operation']['id']+'.json')['exit_code'] is None


def test_native_scriptlet_invalidates_existing_gate_without_native_success(root):
    from pc_agent.platform.linux.installation_lifecycle import InstallationStore, LifecycleJournal, InstallationPending
    store = InstallationStore(root/'state')
    store.prepare()
    with store.locked():
        store.write('runtime-ready',b'old-proof')
        journal = LifecycleJournal(store)
        journal.scriptlet_intent('install')
        assert not (store.paths.private/'runtime-ready').exists()
        assert journal.state()['operation']['unmanaged']
        with pytest.raises(InstallationPending): journal.native_result(0)


def test_native_optional_graphical_environment_absence_race_and_unsafe_nodes(root, monkeypatch):
    from pc_agent.platform.linux import installation_user_sessions as sensors
    from pc_agent.platform.linux.installation_lifecycle import InstallationPending
    from tools.release.linux_native_verifier import VerificationError
    runtime = root/'run/user/1000'
    runtime.mkdir(parents=True,mode=0o700)
    os.chown(runtime,1000,1000)
    actual_path = Path
    monkeypatch.setattr(sensors,'Path',lambda value: root/'run/user' if value == '/run/user' else actual_path(value))
    def missing_environment(argv, **kwargs):
        if 'list-sessions' in argv: return b'6 1000 fixture seat0\n'
        return b'Active=yes\nRemote=no\nClass=user\nType=x11\nUser=1000\nState=active\nTimestampMonotonic=123\nLeader=456\n'
    monkeypatch.setattr(sensors,'run',missing_environment)
    assert sensors.handoff_active_sensors() == [{'session':'6','status':'session_prerequisite_absent'}]
    environment = runtime/'endpoint-user-sensor.env'
    environment.write_text('DISPLAY=":0"\n')
    environment.chmod(0o600)
    os.chown(environment,1000,1000)
    assert sensors.read_session_environment(runtime,1000)['digest']
    environment.chmod(0o666)
    with pytest.raises(InstallationPending): sensors.read_session_environment(runtime,1000)
    environment.unlink()
    environment.symlink_to(root/'missing')
    with pytest.raises(OSError): sensors.read_session_environment(runtime,1000)
    calls = []
    def vanished(argv, **kwargs):
        calls.append(argv)
        if 'show-session' in argv: raise VerificationError('native_tool_failed')
        return b'6 1000 fixture seat0\n' if len(calls) == 1 else b''
    monkeypatch.setattr(sensors,'run',vanished)
    assert sensors.handoff_active_sensors() == [{'session':'6','status':'session_prerequisite_absent'}]
