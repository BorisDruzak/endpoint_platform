"""Archive copies share the same durability boundary as small state writes."""
import hashlib
import os
from pathlib import Path
import pytest
from pc_agent.platform.windows import durable_state as durable


def test_windows_path_and_descriptor_creation_time_have_same_identity(monkeypatch):
    from types import SimpleNamespace
    import stat
    monkeypatch.setattr(durable, '_WINDOWS', True)
    fields = dict(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_dev=5, st_ino=6,
        st_size=7, st_mtime_ns=80, st_birthtime_ns=40)
    path = SimpleNamespace(**fields, st_ctime_ns=40)
    descriptor = SimpleNamespace(**fields, st_ctime_ns=90)
    assert durable._copy_identity(path) == durable._copy_identity(descriptor)
    for name in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_birthtime_ns'):
        changed = SimpleNamespace(**{**fields, name: fields[name] + 1}, st_ctime_ns=90)
        assert durable._copy_identity(path) != durable._copy_identity(changed)


def arguments(tmp_path):
    source_root, destination_root = tmp_path / 'source', tmp_path / 'archive'
    source_root.mkdir(); destination_root.mkdir()
    source = source_root / 'package.msi'
    source.write_bytes(b'bounded exact payload' * 70000)
    return source, destination_root / 'package.msi', dict(source_root=source_root,
        trusted_root=destination_root, max_bytes=2*1024*1024, expected_size=source.stat().st_size,
        expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), protect=lambda _path: None,
        validate=lambda _path: None)


@pytest.mark.parametrize('fault', ['size', 'hash', 'protect', 'fsync', 'replace'])
def test_failed_archive_copy_never_publishes(tmp_path, monkeypatch, fault):
    source, target, kwargs = arguments(tmp_path)
    if fault == 'size': kwargs['expected_size'] += 1
    elif fault == 'hash': kwargs['expected_sha256'] = '0'*64
    else:
        def fail(*_args, **_kwargs): raise OSError('injected boundary')
        if fault == 'protect': kwargs['protect'] = fail
        else: monkeypatch.setattr(durable.os, fault, fail)
    with pytest.raises((OSError, ValueError)):
        durable.durable_copy_file(source, target, **kwargs)
    assert not target.exists()
    assert list(target.parent.iterdir()) == []
    assert source.stat().st_size > 0


def test_existing_exact_archive_retries_directory_barrier(tmp_path, monkeypatch):
    source, target, kwargs = arguments(tmp_path)
    target.write_bytes(source.read_bytes())
    calls = []
    monkeypatch.setattr(durable, 'flush_directory', lambda path: calls.append(path))
    durable.durable_copy_file(source, target, **kwargs)
    assert calls == [target.parent]
    target.write_bytes(b'unrelated forensic evidence')
    with pytest.raises(ValueError): durable.durable_copy_file(source, target, **kwargs)
    assert target.read_bytes() == b'unrelated forensic evidence'


def test_directory_failure_remains_error_after_visible_copy(tmp_path, monkeypatch):
    source, target, kwargs = arguments(tmp_path)
    def fail(_path): raise OSError('directory barrier')
    monkeypatch.setattr(durable, 'flush_directory', fail)
    with pytest.raises(OSError, match='directory barrier'):
        durable.durable_copy_file(source, target, **kwargs)
    assert target.read_bytes() == source.read_bytes()


def test_copy_requires_explicit_archive_policy_on_existing_destination(tmp_path):
    source, target, kwargs = arguments(tmp_path)
    target.write_bytes(source.read_bytes())
    checked = []
    def validate(path):
        checked.append(path)
        raise ValueError('archive policy rejected')
    kwargs['validate'] = validate
    with pytest.raises(ValueError, match='archive policy rejected'):
        durable.durable_copy_file(source, target, **kwargs)
    assert checked == [target]
    assert target.read_bytes() == source.read_bytes()


def test_empty_inventoried_payload_file_is_preserved(tmp_path):
    source, target, kwargs = arguments(tmp_path)
    source.write_bytes(b'')
    kwargs.update(expected_size=0, expected_sha256=hashlib.sha256(b'').hexdigest())
    durable.durable_copy_file(source, target, **kwargs)
    assert target.read_bytes() == b''


@pytest.mark.skipif(os.name != 'nt', reason='native source sharing modes')
def test_native_source_is_pinned_against_write_and_delete(tmp_path):
    source, target, kwargs = arguments(tmp_path)
    protected = []
    def protect(temporary):
        assert temporary.stat().st_size == 0
        for action in (lambda: source.open('wb'), lambda: source.unlink()):
            with pytest.raises(PermissionError): action()
        protected.append(temporary)
    kwargs['protect'] = protect
    durable.durable_copy_file(source, target, **kwargs)
    assert protected and target.read_bytes() == source.read_bytes()
