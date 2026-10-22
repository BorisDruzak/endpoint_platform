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
