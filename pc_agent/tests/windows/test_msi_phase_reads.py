"""Repeated reads retain exact native file handles only within one helper phase."""
from copy import deepcopy
import hashlib
import os

import pytest

from pc_agent.platform.windows import msi_inventory as msi


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='native deny-write/delete pins')


@pytest.fixture
def media(tmp_path, monkeypatch):
    path = tmp_path / 'package.msi'
    path.write_bytes(b'exact immutable package fixture')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    calls = []
    def read(actual, expected):
        calls.append((actual, expected))
        if hashlib.sha256(actual.read_bytes()).hexdigest() != expected:
            raise msi.ProvenanceConflict()
        return {'digest': expected, 'nested': {'unchanged': True}}
    monkeypatch.setattr(msi, '_read_package', read, raising=False)
    return path, digest, calls


def test_one_phase_reads_once_and_prevents_write_delete_and_replacement(media):
    path, digest, calls = media
    with msi.package_read_scope():
        original = msi.read_package(path, digest)
        assert msi.read_package(path, digest) == original
        assert len(calls) == 1
        for mutate in (lambda: path.write_bytes(b'changed'), path.unlink,
                       lambda: path.rename(path.with_suffix('.replaced'))):
            with pytest.raises(OSError):
                mutate()
        assert msi.read_package(path, digest) == original
    path.write_bytes(b'pin released after phase')
    with pytest.raises(msi.ProvenanceConflict):
        with msi.package_read_scope():
            msi.read_package(path, digest)
    assert len(calls) == 2


def test_other_hash_and_other_path_are_never_satisfied_from_cached_media(media):
    path, digest, calls = media
    other = path.with_name('other.msi')
    other.write_bytes(path.read_bytes())
    with msi.package_read_scope():
        msi.read_package(path, digest)
        with pytest.raises(msi.ProvenanceConflict):
            msi.read_package(path, '0' * 64)
        msi.read_package(other, digest)
    assert len(calls) == 3


def test_returned_objects_cannot_poison_later_checks(media):
    path, digest, calls = media
    with msi.package_read_scope():
        value = msi.read_package(path, digest)
        expected = deepcopy(value)
        value['nested']['unchanged'] = False
        assert msi.read_package(path, digest) == expected
    assert len(calls) == 1


def test_scope_exception_releases_pins_and_never_reuses_previous_phase(media):
    path, digest, calls = media
    with pytest.raises(RuntimeError, match='owner lost'):
        with msi.package_read_scope():
            msi.read_package(path, digest)
            raise RuntimeError('owner lost')
    path.rename(path.with_suffix('.moved'))
    path.write_bytes(b'exact immutable package fixture')
    with msi.package_read_scope():
        msi.read_package(path, digest)
    assert len(calls) == 2


def test_preexisting_writer_prevents_cache_admission(media):
    import pywintypes
    path, digest, calls = media
    with path.open('r+b'):
        with pytest.raises(pywintypes.error):
            with msi.package_read_scope():
                msi.read_package(path, digest)
    assert calls == []


def test_outside_scope_keeps_fresh_reads(media):
    path, digest, calls = media
    msi.read_package(path, digest)
    msi.read_package(path, digest)
    assert len(calls) == 2


def test_expected_inventory_is_bound_to_the_entire_release_and_phase(media, monkeypatch):
    path, digest, _ = media
    calls = []
    def read(actual, release):
        calls.append((actual, deepcopy(release)))
        return {'release': deepcopy(release)}
    monkeypatch.setattr(msi, '_read_expected_package', read)
    release = {'package_sha256': digest, 'source_revision': 'a' * 40}
    with msi.package_read_scope():
        original = msi.read_expected_package(path, release)
        original['release']['source_revision'] = 'changed returned value'
        assert msi.read_expected_package(path, release)['release'] == release
        changed = {**release, 'source_revision': 'b' * 40}
        assert msi.read_expected_package(path, changed)['release'] == changed
    with msi.package_read_scope():
        msi.read_expected_package(path, release)
    assert len(calls) == 3


def test_hardlinked_media_is_rejected_before_any_cached_result(media):
    path, digest, calls = media
    os.link(path, path.with_suffix('.hardlink'))
    with pytest.raises(ValueError):
        with msi.package_read_scope():
            msi.read_package(path, digest)
    assert calls == []


def test_mutation_boundary_releases_reads_and_demands_fresh_validation(media):
    from pc_agent.platform.windows import durable_state
    path, digest, calls = media
    grants = []
    with msi.package_read_scope(), durable_state.installer_mutation_checkpoints(lambda: grants.append('live-owner')):
        msi.read_package(path, digest)
        durable_state.installer_mutation_checkpoint(required=True)
        path.write_bytes(b'changed only after the live owner checkpoint')
        with pytest.raises(msi.ProvenanceConflict):
            msi.read_package(path, digest)
    assert grants == ['live-owner'] and len(calls) == 2


def test_optional_cache_limits_fall_back_to_fresh_validation(media):
    path, digest, calls = media
    files = [path]
    for number in range(17):
        other = path.with_name(f'package-{number}.msi')
        other.write_bytes(path.read_bytes())
        files.append(other)
    with msi.package_read_scope():
        for file in files:
            assert msi.read_package(file, digest)['digest'] == digest
        assert msi.read_package(files[-1], digest)['digest'] == digest
    assert len(calls) == len(files) + 1


def test_exact_file_digest_reuse_retains_native_pins_and_invalidates(media, monkeypatch):
    from pc_agent.platform.windows import durable_state
    path, digest, _ = media
    calls = []
    def read(actual):
        calls.append(actual)
        return hashlib.sha256(actual.read_bytes()).hexdigest()
    monkeypatch.setattr(msi, '_hash_file', read, raising=False)
    with msi.package_read_scope(), durable_state.installer_mutation_checkpoints(lambda: None):
        assert msi._file_sha256(path) == digest
        assert msi._file_sha256(path) == digest
        with pytest.raises(OSError):
            path.write_bytes(b'cannot change while digest is reused')
        with pytest.raises(OSError):
            path.unlink()
        assert len(calls) == 1
        durable_state.installer_mutation_checkpoint(required=True)
        path.write_bytes(b'new bytes after original authenticated mutation boundary')
        changed = hashlib.sha256(path.read_bytes()).hexdigest()
        assert msi._file_sha256(path) == changed and changed != digest
        assert len(calls) == 2
    assert msi._file_sha256(path) == changed
    assert len(calls) == 3


def test_digest_without_phase_never_reuses_unpinned_bytes(media, monkeypatch):
    path, digest, _ = media
    calls = []
    def read(actual):
        calls.append(actual)
        return hashlib.sha256(actual.read_bytes()).hexdigest()
    monkeypatch.setattr(msi, '_hash_file', read, raising=False)
    assert msi._file_sha256(path) == digest
    path.write_bytes(b'different unpinned bytes')
    assert msi._file_sha256(path) != digest and len(calls) == 2


def test_database_semantics_reuses_only_pinned_file_bytes_and_returns_copy(media, monkeypatch):
    from pc_agent.platform.windows import durable_state
    path, _, _ = media
    native = msi.NativeMsi()
    calls = []
    def read(actual):
        calls.append(actual)
        return {'Table': hashlib.sha256(actual.read_bytes()).hexdigest()}
    monkeypatch.setattr(native, '_read_database_semantics', read, raising=False)
    with msi.package_read_scope(), durable_state.installer_mutation_checkpoints(lambda: None):
        first = native.database_semantics(path)
        first['Table'] = 'changed returned value'
        expected = hashlib.sha256(path.read_bytes()).hexdigest()
        assert native.database_semantics(path) == {'Table': expected}
        assert len(calls) == 1
        durable_state.installer_mutation_checkpoint(required=True)
        path.write_bytes(b'new physical media')
        assert native.database_semantics(path) != {'Table': expected}
        assert len(calls) == 2
    native.database_semantics(path)
    assert len(calls) == 3


def test_foundation_keeps_full_descriptor_checks_even_in_media_read_scope(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from pc_agent.platform.windows import update_transaction, durable_state
    monkeypatch.setattr(update_transaction, '_assert_state_security', lambda *_: None)
    rows = []
    for name, (file, component) in msi.FOUNDATION_EXECUTABLES.items():
        (tmp_path / name).write_bytes(b'exact foundation')
        rows.append({'path': name, 'file': file, 'component': component, 'size': 16,
                     'sha256': hashlib.sha256(b'exact foundation').hexdigest()})
    expected = SimpleNamespace(foundation_files=rows)
    calls = []
    verify = durable_state._verify_copy_bytes
    def read(descriptor, size, digest):
        calls.append(descriptor)
        return verify(descriptor, size, digest)
    monkeypatch.setattr(durable_state, '_verify_copy_bytes', read)
    monkeypatch.setattr(msi, '_hash_file', lambda *_: pytest.fail('Foundation bytes reused as MSI media'))
    with msi.package_read_scope(), durable_state.installer_mutation_checkpoints(lambda: None):
        with msi.verified_foundation_bytes(expected, tmp_path):
            pass
        with msi.verified_foundation_bytes(expected, tmp_path):
            pass
        assert len(calls) == 16
        durable_state.installer_mutation_checkpoint(required=True)
        (tmp_path / rows[0]['path']).write_bytes(b'changed')
        with pytest.raises(ValueError):
            with msi.verified_foundation_bytes(expected, tmp_path):
                pytest.fail('changed foundation admitted')


def test_explicit_immutable_msi_keeps_pins_across_unrelated_metadata_writes(media, tmp_path):
    from pc_agent.platform.windows import durable_state
    path, digest, calls = media
    grants = []
    with msi.package_read_scope(immutable_media_roots=(path.parent,)):
        with durable_state.installer_mutation_checkpoints(lambda: grants.append('owner')):
            msi.read_package(path, digest)
            durable_state.write_bytes_atomic(tmp_path / 'metadata.json', b'{}', trusted_root=tmp_path, max_bytes=10)
            assert msi.read_package(path, digest)['digest'] == digest
            with pytest.raises(OSError):
                path.write_bytes(b'cannot write pinned immutable media')
            with pytest.raises(OSError):
                path.unlink()
            assert len(calls) == 1 and grants
    path.write_bytes(b'handle released only after the phase')
    with pytest.raises(msi.ProvenanceConflict):
        with msi.package_read_scope(immutable_media_roots=(path.parent,)):
            msi.read_package(path, digest)


def test_immutable_media_scope_still_drops_other_paths_and_non_msi_files(media, tmp_path):
    from pc_agent.platform.windows import durable_state
    path, digest, calls = media
    root = tmp_path / 'immutable'
    root.mkdir()
    stable = root / 'input.msi'
    stable.write_bytes(path.read_bytes())
    metadata = root / 'mutable.json'
    metadata.write_bytes(b'initial')
    with msi.package_read_scope(immutable_media_roots=(root,)):
        with durable_state.installer_mutation_checkpoints(lambda: None):
            msi.read_package(stable, digest)
            msi.read_package(path, digest)
            old = msi._file_sha256(metadata)
            durable_state.installer_mutation_checkpoint(required=True)
            path.write_bytes(b'changed mutable media outside the fixed roots')
            metadata.write_bytes(b'changed metadata even inside the fixed roots')
            with pytest.raises(msi.ProvenanceConflict):
                msi.read_package(path, digest)
            assert msi._file_sha256(metadata) != old
            assert msi.read_package(stable, digest)['digest'] == digest
    assert sum(actual == stable for actual, _ in calls) == 1


def test_immutable_pin_validation_failure_releases_every_handle(media, monkeypatch):
    from pc_agent.platform.windows import durable_state
    path, digest, _ = media
    other = path.with_name('second.msi')
    other.write_bytes(path.read_bytes())
    with msi.package_read_scope(immutable_media_roots=(path.parent,)):
        msi.read_package(path, digest)
        msi.read_package(other, digest)
        scope = msi._PHASE_READS.get()
        def reject(_):
            raise msi.ProvenanceConflict()
        monkeypatch.setattr(scope, 'validate', reject)
        with durable_state.installer_mutation_checkpoints(lambda: None):
            with pytest.raises(msi.ProvenanceConflict):
                durable_state.installer_mutation_checkpoint(required=True)
        assert not scope.pins and not scope.pin_scopes and not scope.values
        path.write_bytes(b'all handles closed')
        other.unlink()


@pytest.mark.parametrize('phase,include_cache', [('prepare', True), ('compound-finalize', True), ('msi-enter', False)])
def test_immutable_media_roots_are_fixed_package_inputs_and_owned_native_cache(tmp_path, monkeypatch, phase, include_cache):
    import win32api
    from types import SimpleNamespace
    paths = SimpleNamespace(install_root=tmp_path/'Endpoint/Agent')
    monkeypatch.setattr(win32api, 'GetWindowsDirectory', lambda: str(tmp_path/'Windows'))
    cap = {'package': {'package_sha256': 'a'*64}, 'compound': {'old': {'package': {'package_sha256': 'b'*64}}}}
    roots = msi.immutable_installer_media_roots(paths, cap, phase)
    assert roots[:2] == (tmp_path/'Endpoint/installer-cache'/('msi-'+'a'*64),
                         tmp_path/'Endpoint/installer-cache'/('msi-'+'b'*64))
    assert (tmp_path/'Windows/Installer' in roots) is include_cache
    cap['package']['package_sha256'] = '../foreign'
    with pytest.raises(ValueError):
        msi.immutable_installer_media_roots(paths, cap, phase)
