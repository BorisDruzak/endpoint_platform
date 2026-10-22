"""Candidate bytes are prepared online, then moved once before native adoption."""
from dataclasses import replace
import hashlib
import json
import os
from types import SimpleNamespace
import zipfile

import pytest

from endpoint_contracts.runtime_payload import verify_payload
from pc_agent.platform.windows import durable_state, installer_fence
from pc_agent.tests.windows.test_staged_update_state import staged, begin
from pc_agent.tests.windows.test_installer_fence import native_protected_root
from pc_agent.tests.windows.test_installation_provenance import payload


@pytest.fixture
def candidate(staged, tmp_path):
    from pc_agent.platform.windows import staged_candidate_payload as module
    state, paths, binding, owner = staged
    source = tmp_path / 'source'
    manifest = payload(source, version=binding.candidate_version,
                       minimum=binding.candidate_version, source='b' * 40)
    identity = verify_payload(source, manifest)
    binding = replace(binding, candidate_tree_sha256=identity.tree_sha256)
    staged = state, paths, binding, owner
    begin(staged)
    cache = paths.install_root.parent / 'installer-cache' / ('msi-' + binding.new_release['package_sha256'])
    cache.mkdir(parents=True)
    archive = cache / 'EndpointCore.zip'
    with zipfile.ZipFile(archive, 'w') as output:
        for item in source.rglob('*'):
            if item.is_file(): output.write(item, item.relative_to(source).as_posix())
        output.writestr('endpoint-update-manifest.json', json.dumps(manifest))
    for path in [paths.install_root, cache.parent, cache, archive]:
        installer_fence.protect_state(path)
    # The real PowerShell execution cache deliberately has no service readers.
    installer_fence.protect_state(archive, secret=True)
    expected = SimpleNamespace(identity=identity, manifest=manifest)
    return module, paths, state.read_staged_update(paths), expected, archive


def prepare(candidate):
    module, paths, record, expected, archive = candidate
    with durable_state.installer_mutation_checkpoints(lambda: None):
        return module.prepare_candidate_payload(paths, record, expected)


def test_online_preparation_never_selects_or_publishes_candidate(candidate):
    module, paths, record, expected, _ = candidate
    selected = paths.current_path.read_bytes()
    root = prepare(candidate)
    assert verify_payload(root, expected.manifest) == expected.identity
    assert paths.current_path.read_bytes() == selected
    assert not (paths.versions_root / expected.identity.version).exists()
    assert not (root / '.endpoint-msi-runtime.json').exists()


def test_archive_manifest_order_does_not_change_exact_msi_file_inventory(candidate):
    _, _, _, expected, archive = candidate
    with zipfile.ZipFile(archive) as bundle:
        members = {item.filename: bundle.read(item) for item in bundle.infolist()}
    manifest = json.loads(members['endpoint-update-manifest.json'])
    manifest['files'] = list(reversed(manifest['files']))
    members['endpoint-update-manifest.json'] = json.dumps(manifest).encode()
    with zipfile.ZipFile(archive, 'w') as output:
        for name, data in members.items(): output.writestr(name, data)
    assert verify_payload(prepare(candidate), expected.manifest) == expected.identity


def test_publish_moves_all_files_without_copy_and_cancel_moves_them_back(candidate, monkeypatch):
    module, paths, record, expected, _ = candidate
    source = prepare(candidate)
    before = {item.path: (source / item.path).stat().st_ino for item in expected.identity.files}
    paths.versions_root.mkdir()
    installer_fence.protect_state(paths.versions_root)
    original_write = durable_state.write_bytes_atomic
    def only_journal(path, *a, **k):
        assert path.name == 'storage.json', 'promotion copied payload bytes'
        return original_write(path, *a, **k)
    with monkeypatch.context() as patch:
        patch.setattr(durable_state, 'write_bytes_atomic', only_journal)
        with durable_state.installer_mutation_checkpoints(lambda: None):
            target = module.publish_candidate_payload(paths, record, expected)
            assert {item.path: (target / item.path).stat().st_ino for item in expected.identity.files} == before
            module.cancel_candidate_payload(paths, record, expected)
    assert not target.exists()
    assert {item.path: (source / item.path).stat().st_ino for item in expected.identity.files} == before


@pytest.mark.parametrize('defect', ['foreign-destination', 'payload-hash', 'source-revision', 'unexpected-file', 'archive-reparse'])
def test_conflict_is_rejected_without_selecting_candidate(candidate, defect):
    module, paths, record, expected, archive = candidate
    if defect == 'foreign-destination':
        target = paths.versions_root / expected.identity.version
        target.mkdir(parents=True)
        (target / 'foreign.txt').write_bytes(b'untouched')
        installer_fence.protect_state(target)
    elif defect == 'source-revision':
        expected.identity = replace(expected.identity, source_revision='c' * 40)
    elif defect == 'archive-reparse':
        original = archive.with_name('original.zip')
        archive.rename(original)
        archive.symlink_to(original)
    elif defect == 'payload-hash':
        with zipfile.ZipFile(archive) as bundle:
            members = {item.filename: bundle.read(item) for item in bundle.infolist()}
        members['pc_agent.exe'] = b'changed'
        with zipfile.ZipFile(archive, 'w') as output:
            for name, data in members.items(): output.writestr(name, data)
    else:
        with zipfile.ZipFile(archive, 'a') as output:
            output.writestr('foreign.txt', b'changed')
    before = paths.current_path.read_bytes()
    with pytest.raises(ValueError): prepare(candidate)
    assert paths.current_path.read_bytes() == before
    if defect == 'foreign-destination': assert (target / 'foreign.txt').read_bytes() == b'untouched'


def test_owner_loss_cannot_publish_partial_tree(candidate):
    module, paths, record, expected, _ = candidate
    count = 0
    def lost():
        nonlocal count
        count += 1
        if count == 8: raise ValueError('OWNER_AUTH_FAILED')
    with durable_state.installer_mutation_checkpoints(lost), pytest.raises(ValueError):
        module.prepare_candidate_payload(paths, record, expected)
    assert not (paths.versions_root / expected.identity.version).exists()


def test_absent_optional_archive_preserves_historical_wrapper_path(candidate):
    module, paths, record, expected, archive = candidate
    archive.unlink()
    with durable_state.installer_mutation_checkpoints(lambda: None):
        assert module.prepare_candidate_payload(paths, record, expected) is None
        assert module.publish_candidate_payload(paths, record, expected) is None
        assert module.cancel_candidate_payload(paths, record, expected) is None


def test_reset_after_rename_reuses_exact_tree(candidate, monkeypatch):
    module, paths, record, expected, _ = candidate
    source = prepare(candidate)
    before = source.stat().st_ino
    write = module._write
    def reset(root, value, phase):
        if phase == 'published': raise OSError('reset after rename')
        return write(root, value, phase)
    with monkeypatch.context() as patch:
        patch.setattr(module, '_write', reset)
        with durable_state.installer_mutation_checkpoints(lambda: None), pytest.raises(OSError):
            module.publish_candidate_payload(paths, record, expected)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        target = module.publish_candidate_payload(paths, record, expected)
    assert target.stat().st_ino == before and not source.exists()


def test_unscoped_writer_cannot_prepare_or_publish(candidate):
    module, paths, record, expected, _ = candidate
    for action in (module.prepare_candidate_payload, module.publish_candidate_payload, module.cancel_candidate_payload):
        with pytest.raises(ValueError, match='installer mutation scope is absent'):
            action(paths, record, expected)
