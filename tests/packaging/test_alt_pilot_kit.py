"""Pilot packaging must preserve reviewed bytes and reject ambiguous inputs."""
from pathlib import Path
import hashlib
import json
import subprocess
import tarfile

import pytest

from tools import build_alt_pilot_kit as kit


def inputs(tmp_path, monkeypatch):
    root = tmp_path / 'inputs'
    root.mkdir()
    for name in kit.PACKAGES:
        (root / name).write_bytes(('reviewed:' + name).encode())
    archive = root / kit.RUNTIME
    archive.write_bytes(b'reviewed immutable runtime')
    (root / kit.RUNTIME_MANIFEST).write_text(json.dumps({
        'schema_version': 'endpoint_linux_agent_artifact_v1', 'platform': 'linux_amd64',
        'version': kit.VERSION, 'source_revision': 'a' * 40, 'artifact_name': kit.RUNTIME,
        'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'size': archive.stat().st_size,
    }))
    monkeypatch.setattr(kit, 'query_rpm', lambda path: kit.PACKAGES[path.name])
    monkeypatch.setattr(kit, 'AGENT_REVISION', 'a' * 40, raising=False)
    monkeypatch.setattr(kit, 'QUALIFIED_INPUTS', {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}, raising=False)
    monkeypatch.setattr(kit.subprocess, 'run', lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, 'Header V4 RSA/SHA256 Signature, key ID 48370631: OK\nV4 RSA/SHA256 Signature, key ID 48370631: OK\n', ''))
    return root


def unpack(archive, destination):
    with tarfile.open(archive) as stream:
        stream.extractall(destination, filter='data')
    return destination / kit.KIT_NAME


def test_build_is_deterministic_and_all_files_are_covered(tmp_path, monkeypatch):
    source = inputs(tmp_path, monkeypatch)
    first, digest = kit.build(source, tmp_path / 'one')
    second, _ = kit.build(source, tmp_path / 'two')
    assert first.read_bytes() == second.read_bytes()
    assert digest.read_text().split()[0] == hashlib.sha256(first.read_bytes()).hexdigest()
    root = unpack(first, tmp_path / 'unpacked')
    manifest_hash = hashlib.sha256((root / 'pilot-manifest.json').read_bytes()).hexdigest()
    manifest = kit.verify(root, manifest_hash)
    assert manifest['endpoint_origin'] == 'https://endpoint.sosnadmin.local'
    assert manifest['agent_source_revision'] == 'a' * 40
    assert set(manifest['files']) == {p.name for p in root.iterdir()} - {'pilot-manifest.json'}


@pytest.mark.parametrize('extra', ['device-credential', 'ca.crt', 'config.yaml', 'unexpected.rpm'])
def test_unreviewed_inputs_are_rejected(tmp_path, monkeypatch, extra):
    source = inputs(tmp_path, monkeypatch)
    (source / extra).write_text('must not enter distributable')
    with pytest.raises(ValueError, match='INPUT_SET'):
        kit.build(source, tmp_path / 'out')


def test_wrong_rpm_identity_is_rejected_before_publication(tmp_path, monkeypatch):
    source = inputs(tmp_path, monkeypatch)
    monkeypatch.setattr(kit, 'query_rpm', lambda path: ('unrelated', '1', '1', 'x86_64'))
    with pytest.raises(ValueError, match='RPM_IDENTITY'):
        kit.build(source, tmp_path / 'out')
    assert not (tmp_path / 'out' / (kit.KIT_NAME + '.tar.gz')).exists()


def test_runtime_sidecar_must_match_bytes(tmp_path, monkeypatch):
    source = inputs(tmp_path, monkeypatch)
    (source / kit.RUNTIME).write_bytes(b'tampered')
    with pytest.raises(ValueError, match='RUNTIME_DIGEST'):
        kit.build(source, tmp_path / 'out')


def test_manifest_trust_and_payload_tampering_are_independent(tmp_path, monkeypatch):
    source = inputs(tmp_path, monkeypatch)
    archive, _ = kit.build(source, tmp_path / 'out')
    root = unpack(archive, tmp_path / 'unpacked')
    digest = hashlib.sha256((root / 'pilot-manifest.json').read_bytes()).hexdigest()
    with pytest.raises(ValueError, match='MANIFEST_DIGEST'):
        kit.verify(root, '0' * 64)
    (root / next(iter(kit.PACKAGES))).write_bytes(b'changed')
    with pytest.raises(ValueError, match='FILE_DIGEST'):
        kit.verify(root, digest)


def test_no_immutable_archive_overwrite(tmp_path, monkeypatch):
    source = inputs(tmp_path, monkeypatch)
    archive, _ = kit.build(source, tmp_path / 'out')
    archive.write_bytes(b'existing different operator artifact')
    with pytest.raises(ValueError, match='IMMUTABLE_OUTPUT'):
        kit.build(source, tmp_path / 'out')
    assert archive.read_bytes() == b'existing different operator artifact'


def test_manifest_cannot_choose_path_outside_kit(tmp_path, monkeypatch):
    source = inputs(tmp_path, monkeypatch)
    archive, _ = kit.build(source, tmp_path / 'out')
    root = unpack(archive, tmp_path / 'unpacked')
    path = root / 'pilot-manifest.json'
    manifest = json.loads(path.read_text())
    manifest['files']['../escape'] = next(iter(manifest['files'].values()))
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='FILE_SET'):
        kit.verify(root, hashlib.sha256(path.read_bytes()).hexdigest())


def test_same_version_repacked_rpm_is_not_a_qualified_input(tmp_path, monkeypatch):
    source = inputs(tmp_path, monkeypatch)
    (source / next(iter(kit.PACKAGES))).write_bytes(b'same name and version, different executable')
    with pytest.raises(ValueError, match='QUALIFIED_DIGEST'):
        kit.build(source, tmp_path / 'out')


@pytest.mark.parametrize('changes,expected', [
    ({'hostname': 'other'}, 'HOSTNAME'),
    ({'os_id': 'ubuntu'}, 'ALT11'),
    ({'os_version': '110'}, 'ALT11'),
    ({'arch': 'aarch64'}, 'ALT11'),
    ({'state_exists': True}, 'EXISTING_AGENT'),
    ({'agent_query_status': 0}, 'EXISTING_AGENT'),
    ({'agent_query_status': 2}, 'EXISTING_AGENT'),
    ({'cups': '2.1.1-alt2.x86_64'}, 'CUPS_VERSION'),
])
def test_machine_gate_does_not_replace_existing_or_unknown_state(changes, expected):
    facts = {'hostname':'test-alt','os_id':'altlinux','os_version':'11.4','arch':'x86_64',
        'state_exists':False,'agent_query_status':1,'cups':'2.1.1-alt1.x86_64'}
    with pytest.raises(ValueError, match=expected):
        kit.machine_install_packages({**facts, **changes}, 'test-alt')


def test_repaired_cups_is_not_reinstalled_and_absent_cups_is_explicit():
    facts = {'hostname':'test-alt','os_id':'altlinux','os_version':'11.4','arch':'x86_64',
        'state_exists':False,'agent_query_status':1,'cups':'2.1.1-alt1.endpoint2.x86_64'}
    assert kit.machine_install_packages(facts,'test-alt') == list(kit.INSTALL[:2])
    assert kit.machine_install_packages({**facts,'cups':None},'test-alt') == list(kit.INSTALL)


@pytest.mark.parametrize('relative', [
    'etc/systemd/system/endpoint-agent.service',
    'etc/systemd/system/endpoint-agent.service.d/old.conf',
    'etc/systemd/system/endpoint-agent-update.service.d/old.conf',
    'usr/lib/endpoint-agent/orphan-helper',
    'etc/systemd/user/endpoint-user-sensor.service.d/old.conf',
    'etc/xdg/autostart/endpoint-user-sensor.desktop',
])
def test_real_preflight_refuses_retained_unit_state_before_rpm_transaction(tmp_path, monkeypatch, relative):
    system_root = tmp_path / 'system'
    release = system_root / 'etc/os-release'
    release.parent.mkdir(parents=True)
    release.write_text('ID=altlinux\nVERSION_ID=11.4\n')
    retained = system_root / relative
    retained.parent.mkdir(parents=True, exist_ok=True)
    retained.write_text('retained installation state')
    monkeypatch.setattr(kit, 'SYSTEM_ROOT', system_root, raising=False)
    monkeypatch.setattr(kit.platform, 'node', lambda: 'test-alt')
    monkeypatch.setattr(kit.platform, 'machine', lambda: 'x86_64')
    original_read = Path.read_text
    monkeypatch.setattr(Path, 'read_text', lambda path, *a, **kw: original_read(release if path.as_posix() == '/etc/os-release' else path, *a, **kw))
    calls = []
    def run(command, **options):
        calls.append(command)
        if command == ['rpm','-q','endpoint-agent']:
            return subprocess.CompletedProcess(command,1,b'',b'')
        if command[:2] == ['rpm','-q']:
            return subprocess.CompletedProcess(command,0,'2.1.1-alt1.x86_64','')
        return subprocess.CompletedProcess(command,0,b'',b'')
    monkeypatch.setattr(kit.subprocess,'run',run)
    monkeypatch.setattr(kit,'query_rpm',lambda path: kit.PACKAGES[path.name])
    with pytest.raises(ValueError,match='EXISTING_AGENT'):
        kit.machine_preflight(tmp_path/'kit','test-alt')
    assert not any('--test' in call for call in calls)


def test_digest_only_rpm_success_is_not_a_publisher_signature(tmp_path, monkeypatch):
    source = inputs(tmp_path, monkeypatch)
    monkeypatch.setattr(kit.subprocess, 'run', lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, 'digests OK\n', ''))
    with pytest.raises(ValueError, match='RPM_SIGNATURE_REQUIRED'):
        kit.build(source, tmp_path / 'out')


@pytest.mark.parametrize('output,status', [
    ('Header V4 RSA/SHA256 Signature, key ID 48370631: OK\n',0),
    ('Header V4 RSA/SHA256 Signature, key ID 11111111: OK\nV4 RSA/SHA256 Signature, key ID 11111111: OK\n',0),
    ('Header V4 RSA/SHA256 Signature, key ID 48370631: BAD\nV4 RSA/SHA256 Signature, key ID 48370631: BAD\n',1),
])
def test_signature_verification_requires_both_signatures_and_expected_key(tmp_path,monkeypatch,output,status):
    inputs(tmp_path,monkeypatch)
    monkeypatch.setattr(kit.subprocess,'run',lambda cmd,**kw:subprocess.CompletedProcess(cmd,status,output,''))
    with pytest.raises((ValueError,subprocess.SubprocessError)):
        kit.verify_package_signatures(tmp_path,Path('packaging/alt/pilot/endpoint-rpm-release.asc'))


def test_public_key_substitution_is_refused(tmp_path):
    key=tmp_path/'publisher.asc';key.write_bytes(b'unrelated key')
    with pytest.raises(ValueError,match='PUBLISHER_KEY_DIGEST'):
        kit.verify_package_signatures(tmp_path,key)
