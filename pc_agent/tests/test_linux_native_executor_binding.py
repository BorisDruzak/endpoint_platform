"""The Setup/source binding applies to every source except the immutable156 pair."""
from dataclasses import replace

import pytest

from pc_agent.platform.linux.installation_lifecycle import InstallationPending
from pc_agent.version import AGENT_VERSION
from tools.release.linux_native_verifier import (VerifiedNativeRPM, PUBLISHER, LEGACY_SOURCE,
    LEGACY_MANIFEST, LEGACY_RPMS)


def proof(version='3.2.179'):
    return VerifiedNativeRPM('endpoint-agent-'+version+'-alt6.x86_64',PUBLISHER,'a'*40,'b'*64,
        'c'*64,version,'endpoint-agent','d'*64)


def binding(native, sensor=False):
    return {'version':native.version,'source_revision':native.source_revision,'core_nevra':native.nevra,
        'core_rpm_sha256':native.sha256,'user_sensor_nevra':'endpoint-agent-user-sensor-3.2.156-alt5.x86_64' if sensor else None,
        'user_sensor_rpm_sha256':LEGACY_RPMS['endpoint-agent-user-sensor'] if sensor else None}


def test_corrected179_setup_can_execute_only_its_signed_source():
    from pc_agent.platform.linux.installation_coordinator import assert_executor_binding
    native = proof()
    executor = {'sha256':'d'*64,'source_revision':'a'*40,'version':'3.2.179'}
    assert_executor_binding(binding(native), native, executor)
    for wrong in ({'sha256':'e'*64}, {'source_revision':'f'*40}, {'version':'3.2.178'}):
        with pytest.raises(InstallationPending): assert_executor_binding(binding(native),native,executor | wrong)


@pytest.mark.parametrize('version', ['3.2.178','3.2.180','3.2.156'])
def test_other_modern_sources_cannot_skip_setup_binding_by_version(version):
    from pc_agent.platform.linux.installation_coordinator import assert_executor_binding
    native = proof(version)
    with pytest.raises(InstallationPending):
        assert_executor_binding(binding(native),native,{'sha256':'d'*64,'source_revision':'a'*40,'version':'3.2.179'})
    with pytest.raises(InstallationPending):
        assert_executor_binding(binding(native),replace(native,setup_sha256=None),{'sha256':None,'source_revision':'a'*40,'version':version})


@pytest.mark.parametrize('sensor', [True, False])
def test_only_exact_historical156_source_has_setup_exemption(sensor):
    from pc_agent.platform.linux.installation_coordinator import assert_executor_binding
    native = VerifiedNativeRPM('endpoint-agent-3.2.156-alt5.x86_64',PUBLISHER,LEGACY_SOURCE,
        LEGACY_MANIFEST,LEGACY_RPMS['endpoint-agent'],'3.2.156','endpoint-agent')
    assert_executor_binding(binding(native,sensor),native,{'version':'3.2.179'})
    for changed in ({'core_rpm_sha256':'1'*64},{'core_nevra':'endpoint-agent-3.2.156-alt6.x86_64'},
        {'source_revision':'2'*40},{'user_sensor_rpm_sha256':'3'*64},
        {'user_sensor_nevra':'endpoint-agent-user-sensor-3.2.156-alt6.x86_64'}):
        with pytest.raises(InstallationPending):
            assert_executor_binding(binding(native,sensor) | changed,native,{'version':'3.2.179'})

@pytest.mark.parametrize('version', ['3.2.179','3.2.180','3.2.156'])
def test_cli_refuses_mismatched_modern_source_before_any_native_work(monkeypatch, version):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from pc_agent.platform.linux import installation_coordinator as c, installation_notification as n
    from pc_agent.tests.test_linux_installation_lifecycle import MemoryStore
    store = MemoryStore()
    store.prepare = lambda: None
    store.locked = nullcontext
    store.data['executor.json'] = {'sha256':'e'*64,'source_revision':'a'*40,'version':'3.2.179'}
    monkeypatch.setattr(c,'os',SimpleNamespace(name='posix',geteuid=lambda:0))
    monkeypatch.setattr(c,'InstallationStore',lambda:store)
    monkeypatch.setattr(c,'retain_executor',lambda *_:None)
    monkeypatch.setattr(c,'retain_inputs',lambda paths,_store,verify:(paths, [verify(path) for path in paths]))
    monkeypatch.setattr(c,'NativeRPMVerifier',lambda *_args,**_kw:lambda _:proof(version))
    monkeypatch.setattr(n,'canonical_identity',lambda:(None,None))
    invoked = []
    monkeypatch.setattr(c.NativeCoordinator,'operate',lambda *_args,**_kw:invoked.append(True))
    monkeypatch.setattr(c.subprocess,'run',lambda *_args,**_kw:SimpleNamespace(returncode=0))
    assert c.main(['upgrade','--core-rpm','signed.rpm']) == 21
    assert not invoked


@pytest.mark.parametrize('with_sensor', [False, True])
def test_cli_verifies_each_captured_rpm_once_before_using_retained_pair(monkeypatch, with_sensor):
    from contextlib import contextmanager, nullcontext
    from pathlib import Path
    from types import SimpleNamespace
    from pc_agent.platform.linux import installation_coordinator as c, installation_notification as n
    from pc_agent.tests.test_linux_installation_lifecycle import MemoryStore

    store = MemoryStore()
    store.prepare = lambda: None
    store.locked = nullcontext
    store.data['executor.json'] = {'sha256': 'd' * 64, 'source_revision': 'a' * 40, 'version': '3.2.179'}
    core = proof()
    sensor = replace(core, package='endpoint-agent-user-sensor',
                     nevra='endpoint-agent-user-sensor-3.2.179-alt6.x86_64', sha256='e' * 64)
    verified = []
    operated = []
    paths = [Path('core.rpm')] + ([Path('sensor.rpm')] if with_sensor else [])
    proofs = dict(zip(paths, [core, sensor]))
    store.paths = SimpleNamespace(private=Path("protected"))
    retained_paths = [store.paths.private / (proofs[path].sha256 + ".rpm") for path in paths]
    arguments = ['upgrade', '--core-rpm', str(paths[0])]
    if with_sensor:
        arguments.extend(['--user-sensor-rpm', str(paths[1])])

    def verify(path):
        verified.append(path)
        return proofs[path]

    @contextmanager
    def capture(path):
        yield path, proofs[path].sha256

    def operate(_self, action, source, retained, *, device_id):
        operated.append((action, source, retained, device_id))
        return 'notification_pending'

    monkeypatch.setattr(c, 'os', SimpleNamespace(name='posix', geteuid=lambda: 0))
    monkeypatch.setattr(c, 'InstallationStore', lambda: store)
    monkeypatch.setattr(c, 'retain_executor', lambda *_: None)
    monkeypatch.setattr(c, 'snapshot', capture)
    monkeypatch.setattr(c, '_retain_verified_copy', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(c, 'NativeRPMVerifier', lambda *_args, **_kwargs: verify)
    monkeypatch.setattr(n, 'canonical_identity', lambda: (None, None))
    monkeypatch.setattr(c.NativeCoordinator, 'operate', operate)
    monkeypatch.setattr(c.subprocess, 'run', lambda *_args, **_kwargs: SimpleNamespace(returncode=0))
    assert c.main(arguments) == 0
    assert operated == [('upgrade', binding(core) | {
        'user_sensor_nevra': sensor.nevra if with_sensor else None,
        'user_sensor_rpm_sha256': sensor.sha256 if with_sensor else None}, retained_paths, None)]
    assert verified == paths


@pytest.mark.parametrize('field,value',[('version','3.2.180'),('source_revision','f'*40),
    ('core_nevra','endpoint-agent-3.2.179-alt7.x86_64'),('core_rpm_sha256','e'*64)])
def test_executor_binding_also_binds_source_record_to_verified_core(field,value):
    from pc_agent.platform.linux.installation_coordinator import assert_executor_binding
    native = proof()
    with pytest.raises(InstallationPending):
        assert_executor_binding(binding(native) | {field:value},native,
            {'sha256':'d'*64,'source_revision':'a'*40,'version':'3.2.179'})

@pytest.mark.parametrize('component,version,accepted',[
    ('setup', AGENT_VERSION, True),
    ('setup', '3.2.179', False),
    ('setup', '3.2.178', False),
    ('core', AGENT_VERSION, False),
    ('support', AGENT_VERSION, False),
])
def test_retained_executor_accepts_only_current_frozen_setup_identity(tmp_path,monkeypatch,component,version,accepted):
    from contextlib import contextmanager, nullcontext
    from types import SimpleNamespace
    from pc_agent.platform.linux import installation_coordinator as c, native_build_identity as identity
    from pc_agent.tests.test_linux_installation_lifecycle import MemoryStore
    store = MemoryStore()
    store.paths = SimpleNamespace(private=tmp_path)
    store.locked = nullcontext
    executable = tmp_path/('setup-'+'d'*64)
    monkeypatch.setattr(c.sys,'frozen',True,raising=False)
    monkeypatch.setattr(c.sys,'executable',str(executable))
    @contextmanager
    def snapshot(_): yield executable,'d'*64
    monkeypatch.setattr(c,'snapshot',snapshot)
    monkeypatch.setattr(identity,'build_identity',lambda:{'schema_version':'endpoint_linux_native_build_v1',
        'component':component,'version':version,'source_revision':'a'*40,'source_files':{}})
    if accepted:
        c.retain_executor(store)
        assert store.json('executor.json') == {'path':str(executable),'sha256':'d'*64,'source_revision':'a'*40,'version':version}
    else:
        with pytest.raises(InstallationPending,match='executor_build_identity'): c.retain_executor(store)
        assert store.json('executor.json',missing=True) is None


@pytest.mark.parametrize('existing_target', [False, True])
def test_executor_releases_all_snapshots_before_exec_handoff(tmp_path, monkeypatch, existing_target):
    from contextlib import contextmanager, nullcontext
    import hashlib
    from pathlib import Path
    from types import SimpleNamespace
    from pc_agent.platform.linux import installation_coordinator as c
    payload = b'exact frozen setup bytes'
    digest = hashlib.sha256(payload).hexdigest()
    executable = tmp_path/'vendor-setup'
    executable.write_bytes(payload)
    private = tmp_path/'private'
    private.mkdir()
    target = private/('setup-'+digest)
    if existing_target:
        target.write_bytes(payload)
    copies = []
    @contextmanager
    def snapshot(path):
        copy = tmp_path/('snapshot-'+str(len(copies)))
        copy.write_bytes(Path(path).read_bytes())
        copies.append(copy)
        try:
            yield copy, hashlib.sha256(copy.read_bytes()).hexdigest()
        finally:
            copy.unlink()
    class Handoff(BaseException):
        pass
    def execv(path, arguments):
        # Inspect at entry, before exception unwinding can hide the leak.
        assert copies and not any(copy.exists() for copy in copies)
        assert path == str(target) and arguments == [str(target), 'upgrade']
        assert target.read_bytes() == payload
        raise Handoff
    monkeypatch.setattr(c.sys, 'frozen', True, raising=False)
    monkeypatch.setattr(c.sys, 'executable', str(executable))
    monkeypatch.setattr(c.sys, 'argv', [str(executable), 'upgrade'])
    # Windows lacks this POSIX flag; real node guards run in the native harness.
    if not hasattr(c.os, 'O_NOFOLLOW'):
        monkeypatch.setattr(c.os, 'O_NOFOLLOW', 0, raising=False)
        monkeypatch.setattr(c, '_sync_directory', lambda _path: None)
    monkeypatch.setattr(c, 'snapshot', snapshot)
    monkeypatch.setattr(c.os, 'execv', execv)
    with pytest.raises(Handoff):
        c.retain_executor(SimpleNamespace(paths=SimpleNamespace(private=private), locked=nullcontext))


def test_executor_preserves_conflicting_retained_target(tmp_path, monkeypatch):
    from contextlib import contextmanager, nullcontext
    import hashlib
    from types import SimpleNamespace
    from pc_agent.platform.linux import installation_coordinator as c
    payload = b'exact frozen setup bytes'
    digest = hashlib.sha256(payload).hexdigest()
    executable = tmp_path/'vendor-setup'
    executable.write_bytes(payload)
    target = tmp_path/('setup-'+digest)
    target.write_bytes(b'foreign retained bytes')
    @contextmanager
    def snapshot(path):
        yield path, hashlib.sha256(path.read_bytes()).hexdigest()
    def execv(*_):
        pytest.fail('conflicting retained executor reached exec')
    monkeypatch.setattr(c.sys, 'frozen', True, raising=False)
    monkeypatch.setattr(c.sys, 'executable', str(executable))
    monkeypatch.setattr(c, 'snapshot', snapshot)
    monkeypatch.setattr(c.os, 'execv', execv)
    with pytest.raises(InstallationPending, match='executor_conflict'):
        c.retain_executor(SimpleNamespace(paths=SimpleNamespace(private=tmp_path), locked=nullcontext))
    assert target.read_bytes() == b'foreign retained bytes'


@pytest.mark.parametrize("input_kind", ["rpm", "executor"])
def test_interrupted_retention_leaves_no_final_file_and_allows_retry(tmp_path, monkeypatch, input_kind):
    from contextlib import contextmanager, nullcontext
    import errno
    import hashlib
    import os
    from types import SimpleNamespace

    from pc_agent.platform.linux import installation_coordinator as coordinator

    original = tmp_path / "vendor-input"
    payload = b"verified and immutable vendor bytes"
    original.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    private = tmp_path / "private"
    private.mkdir()
    store = SimpleNamespace(paths=SimpleNamespace(private=private), locked=nullcontext)
    expected = private / (digest + ".rpm" if input_kind == "rpm" else "setup-" + digest)
    reached_exec = []

    @contextmanager
    def verified_snapshot(path):
        yield path, hashlib.sha256(path.read_bytes()).hexdigest()

    monkeypatch.setattr(coordinator, "snapshot", verified_snapshot)
    monkeypatch.setattr(os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0), raising=False)
    monkeypatch.setattr(coordinator.sys, "frozen", True, raising=False)
    monkeypatch.setattr(coordinator.sys, "executable", str(original))
    monkeypatch.setattr(os, "execv", lambda path, _argv: reached_exec.append(path))
    if os.name == "nt":
        monkeypatch.setattr(coordinator, "_sync_directory", lambda _path: None)

    def retain():
        if input_kind == "rpm":
            native = replace(proof(), sha256=digest)
            assert coordinator.retain_inputs([original], store, lambda _source: native) == ([expected], [native])
        else:
            coordinator.retain_executor(store)

    original_fdopen = os.fdopen

    @contextmanager
    def interrupted_stream(fd, mode):
        with original_fdopen(fd, mode) as stream:
            def partial_write(data):
                stream.write(data[:4])
                raise OSError(errno.ENOSPC, "fixture interrupted retained copy")

            yield SimpleNamespace(write=partial_write)

    with monkeypatch.context() as patch:
        patch.setattr(os, "fdopen", interrupted_stream)
        with pytest.raises(OSError, match="interrupted retained copy"):
            retain()

    assert list(private.iterdir()) == []
    assert reached_exec == []
    retain()
    assert expected.read_bytes() == payload
    assert reached_exec == ([str(expected)] if input_kind == "executor" else [])


def test_retention_refuses_written_bytes_that_differ_from_the_verified_input(tmp_path, monkeypatch):
    from contextlib import contextmanager
    import hashlib
    import os

    from pc_agent.platform.linux import installation_coordinator as coordinator

    original, destination = tmp_path / "original.rpm", tmp_path / "retained.rpm"
    original.write_bytes(b"verified payload")
    digest = hashlib.sha256(original.read_bytes()).hexdigest()
    fdopen = os.fdopen

    class CorruptCopy:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, data):
            return self.stream.write(b"x" * len(data))

    @contextmanager
    def corrupt_stream(fd, mode):
        with fdopen(fd, mode) as stream:
            yield CorruptCopy(stream)

    monkeypatch.setattr(os, "fdopen", corrupt_stream)
    monkeypatch.setattr(os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0), raising=False)
    monkeypatch.setattr(coordinator, "_sync_directory", lambda _path: None)
    with pytest.raises(InstallationPending, match="retained_archive_conflict"):
        coordinator._retain_verified_copy(original, destination, digest, mode=0o400,
                                          conflict="retained_archive_conflict")
    assert list(tmp_path.iterdir()) == [original]


def test_retention_requires_proof_for_the_captured_rpm_digest(tmp_path, monkeypatch):
    from contextlib import contextmanager

    from pc_agent.platform.linux import installation_coordinator as coordinator

    @contextmanager
    def snapshot(path):
        yield path, "f" * 64

    monkeypatch.setattr(coordinator, "snapshot", snapshot)
    monkeypatch.setattr(coordinator, "_retain_verified_copy", lambda *_args, **_kwargs:
                        pytest.fail("a mismatched proof reached the retained archive"))
    with pytest.raises(InstallationPending, match="native_input_proof_mismatch"):
        coordinator.retain_inputs([tmp_path / "vendor.rpm"], None, lambda _: proof())
