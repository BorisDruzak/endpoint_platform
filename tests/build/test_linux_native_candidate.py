"""Current candidate builders must seal corrected181, with independent Support1.0.0."""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tarfile

import pytest

from tools.release.linux_native_verifier import VerifiedNativeRPM, PUBLISHER


@pytest.mark.parametrize('component,version', [('setup','3.2.181'),('support','1.0.0')])
def test_native_freezer_seals_candidate_source_identity(tmp_path, monkeypatch, component, version):
    from tools.release import freeze_linux_native_identity as f
    def git(argv, **kwargs):
        return 'a'*40+'\n' if 'rev-parse' in argv else ''
    monkeypatch.setattr(f.subprocess,'check_output',git)
    stage = tmp_path/'frozen'
    stage.mkdir()
    monkeypatch.setattr(f.tempfile,'mkdtemp',lambda **kw:str(stage))
    result = Path(f.freeze_identity(tmp_path,component))
    value = json.loads(result.read_text())
    assert value['component'] == component and value['version'] == version
    assert value['source_revision'] == 'a'*40


def kit_inputs(tmp_path, monkeypatch, version='3.2.181'):
    from tools import build_alt_native_kit as k
    paths = [tmp_path/name for name in ('core.rpm','sensor.rpm','setup','key.asc')]
    for path in paths: path.write_bytes(path.name.encode())
    digest = hashlib.sha256(b'setup').hexdigest()
    core = VerifiedNativeRPM('endpoint-agent-'+version+'-alt6.x86_64',PUBLISHER,'a'*40,'b'*64,'c'*64,version,'endpoint-agent',digest)
    sensor = replace(core,package='endpoint-agent-user-sensor')
    monkeypatch.setattr(k,'NativeRPMVerifier',lambda _:lambda path:core if Path(path).name == 'core.rpm' else sensor)
    @contextmanager
    def snapshot(path):
        yield path, hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(k,'snapshot',snapshot)
    return k, paths


def test_native_kit_builds181_with_signed_setup_source_binding(tmp_path, monkeypatch):
    k, paths = kit_inputs(tmp_path,monkeypatch)
    target, metadata = k.build(*paths,tmp_path/'output')
    value = json.loads(metadata.read_text())
    assert target.name == 'endpoint-alt-pilot-3.2.181-1.tar.gz'
    assert value['agent_version'] == '3.2.181' and value['agent_source_revision'] == 'a'*40
    with tarfile.open(target) as archive:
        assert archive.extractfile('endpoint-alt-pilot-3.2.181-1/endpoint-agent-setup').read() == b'setup'
    paths[2].write_bytes(b'wrong-setup')
    with pytest.raises(ValueError): k.build(*paths,tmp_path/'wrong')
    assert not (tmp_path/'wrong').exists()


@pytest.mark.parametrize('version',['3.2.180','3.2.179','3.2.178','3.2.156'])
def test_current_native_kit_refuses_older_candidate_pair(tmp_path,monkeypatch,version):
    k, paths = kit_inputs(tmp_path,monkeypatch,version)
    with pytest.raises(ValueError): k.build(*paths,tmp_path/'output')
    assert not (tmp_path/'output').exists()


def test_native181_dispatches_to_current_builder_without_legacy_pilot_flow(monkeypatch):
    import sys
    from tools import build_alt_pilot_kit as dispatcher, build_alt_native_kit as native
    received = []
    monkeypatch.setattr(sys,'argv',['kit','native181','--core','fixed.rpm'])
    monkeypatch.setattr(native,'main',lambda argv:received.append(argv))
    assert dispatcher.main() == 0
    assert received == [['--core','fixed.rpm']]
