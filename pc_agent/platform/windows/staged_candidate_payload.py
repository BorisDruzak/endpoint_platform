"""Prepare signed-MSI Core bytes online, without claiming native ownership.

The archive is an internal Setup transport. Its complete content is bound to
the inventory extracted from the authenticated MSI. Native MSI still installs
and verifies every feature/component and writes its own ownership metadata.
"""
from __future__ import annotations

import hashlib
import os
from contextlib import ExitStack
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import zipfile

from endpoint_contracts.runtime_payload import (
    BUNDLE_FILENAME, MAX_PAYLOAD_BYTES, read_json, verify_payload, verify_windows_archive,
)
from . import durable_state, installer_fence as fence
from . import installation_provenance as provenance, staged_update_state as state

_SCHEMA = 'endpoint_staged_candidate_payload_v1'
_LIMIT = 4096


def _fail():
    raise ValueError('PROVENANCE_CONFLICT')


def _present(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def _paths(paths, record):
    root = fence.state_root(paths) / 'candidate-payload' / record.binding.operation_id
    cache = fence.state_root(paths).parent / 'installer-cache'
    archive = cache / ('msi-' + record.binding.new_release['package_sha256']) / 'EndpointCore.zip'
    return root, root / 'payload', paths.versions_root / record.binding.candidate_version, archive


def _authorize(paths, record, expected):
    durable_state.installer_mutation_checkpoint(required=True)
    current = state.read_staged_update(paths)
    if (current is None or current.binding != record.binding
            or current.phase not in {'preparing', 'prepared'}
            or (expected.identity.version, expected.identity.source_revision, expected.identity.tree_sha256) !=
               (record.binding.candidate_version, record.binding.candidate_source_revision,
                record.binding.candidate_tree_sha256)):
        _fail()
    return _paths(paths, record)


def _binding(record):
    return hashlib.sha256(state._canonical(state._binding_value(record.binding))).hexdigest()


def _journal(root, record):
    path = root / 'storage.json'
    if not _present(path): return None
    fence.assert_state_security(root)
    fence.assert_state_security(path)
    value = read_json(provenance._read(path, _LIMIT), _LIMIT)
    if (set(value) != {'schema_version', 'binding_sha256', 'phase'}
            or value['schema_version'] != _SCHEMA or value['binding_sha256'] != _binding(record)
            or value['phase'] not in {'copying', 'prepared', 'publishing', 'published', 'cancelling', 'cancelled'}):
        _fail()
    return value['phase']


def _write(root, record, phase):
    durable_state.installer_mutation_checkpoint(required=True)
    durable_state.write_json_atomic(root / 'storage.json', {
        'schema_version': _SCHEMA, 'binding_sha256': _binding(record), 'phase': phase,
    }, trusted_root=root, max_bytes=_LIMIT, protect=fence.protect_state)


def _verify(root, expected):
    fence.assert_state_security(root)
    for leaf in root.rglob('*'):
        fence.assert_state_security(leaf)
    if verify_payload(root, expected.manifest) != expected.identity: _fail()


def prepare_candidate_payload(paths, record, expected):
    root, source, target, archive = _authorize(paths, record, expected)
    if not _present(archive): return None  # Historical standalone wrapper.
    if _present(target) or _present(root): _fail()  # Never take over another tree.
    fence.assert_state_security(archive, secret=True)
    # Keep one native deny-write/delete handle throughout validation/extraction.
    with durable_state._pinned_copy_source(archive) as descriptor:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1): _fail()
        with archive.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        identity = verify_windows_archive(archive, sha256=digest, size=before.st_size,
            version=expected.identity.version, minimum_launcher_version=expected.identity.minimum_launcher_version)
        if identity != expected.identity: _fail()
        with zipfile.ZipFile(archive) as bundle:
            manifest = read_json(bundle.read(BUNDLE_FILENAME), 4 * 1024 * 1024)
            # ZIP's PowerShell publisher and MSI's Python publisher order names
            # differently. Compare every record and all metadata canonically;
            # duplicate/path/type/content checks above remain unchanged.
            canonical = lambda value: {**value, 'files': sorted(value['files'], key=lambda item: item['path'])}
            if canonical(manifest) != canonical(expected.manifest): _fail()
            parent = provenance._archive_directory(fence.state_root(paths), 'candidate-payload')
            root = provenance._archive_directory(parent, record.binding.operation_id)
            _write(root, record, 'copying')
            source = provenance._archive_directory(root, 'payload')
            for item in expected.identity.files:
                parent = source
                for part in Path(item.path).parts[:-1]:
                    parent = provenance._archive_directory(parent, part)
                data = bundle.read(item.path)
                if len(data) != item.size or hashlib.sha256(data).hexdigest() != item.sha256: _fail()
                durable_state.write_bytes_atomic(source / item.path, data, trusted_root=source,
                    max_bytes=MAX_PAYLOAD_BYTES, protect=fence.protect_state)
        after = os.fstat(descriptor)
        if (durable_state._copy_identity(before) != durable_state._copy_identity(after)
                or before.st_ctime_ns != after.st_ctime_ns
                or durable_state._copy_identity(archive.lstat()) != durable_state._copy_identity(before)):
            _fail()
    _verify(source, expected)
    _write(root, record, 'prepared')
    return source


def publish_candidate_payload(paths, record, expected):
    root, source, target, _ = _authorize(paths, record, expected)
    if not _present(root): return None
    phase = _journal(root, record)
    if phase not in {'prepared', 'publishing', 'published'}: _fail()
    if _present(source) and not _present(target) and phase != 'published':
        _verify(source, expected)
        if not _present(paths.versions_root):
            provenance._archive_directory(paths.install_root, 'versions')
        fence.assert_namespace_security(paths.versions_root, include_self=True)
        _write(root, record, 'publishing')
        durable_state.durable_rename_directory(source, target, trusted_root=paths.install_root.parent)
    elif phase == 'prepared' or _present(source) or not _present(target):
        _fail()
    _verify(target, expected)
    _write(root, record, 'published')
    return target


def check_candidate_executable(paths, record, expected):
    """Check the frozen CLI online; this grants no native or trial authority."""
    root, _, target, _ = _authorize(paths, record, expected)
    if not _present(root):
        return None  # Historical standalone wrapper without a staged candidate.
    if (_journal(root, record) != 'published'
            or provenance._selector(paths.current_path)[0] != record.binding.selected_before):
        _fail()
    with ExitStack() as stack:
        identities = []
        # Hold every authenticated dependency, not just the executable. The
        # child may load DLLs lazily; no payload mutation is allowed meanwhile.
        for path in (target / item.path for item in expected.identity.files):
            before = durable_state._copy_identity(path.lstat())
            descriptor = stack.enter_context(durable_state._pinned_copy_source(path))
            opened = os.fstat(descriptor)
            if durable_state._copy_identity(opened) != before:
                _fail()
            identities.append((path, descriptor, before, opened.st_ctime_ns))
        _verify(target, expected)
        with tempfile.TemporaryFile(dir=root) as output:
            if isinstance(output.name, str):
                fence.protect_state(Path(output.name), secret=True)
            durable_state.installer_mutation_checkpoint(required=True)
            deadline = time.monotonic() + 60
            child = subprocess.Popen(
                [str(target / 'pc_agent.exe'), '--print-version'],
                cwd=str(target), stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT,
                shell=False, close_fds=True,
                creationflags=0x08000000 if os.name == 'nt' else 0,
            )
            try:
                while child.poll() is None:
                    durable_state.installer_mutation_checkpoint(required=True)
                    if os.fstat(output.fileno()).st_size > 4096 or time.monotonic() >= deadline:
                        _fail()
                    time.sleep(0.1)
                child.wait(timeout=5)
                durable_state.installer_mutation_checkpoint(required=True)
                if (child.returncode != 0 or time.monotonic() >= deadline
                        or os.fstat(output.fileno()).st_size > 4096):
                    _fail()
                output.seek(0)
                if output.read(4097).strip() != expected.identity.version.encode('ascii'):
                    _fail()
            finally:
                if child.poll() is None:
                    # Popen retains the exact native process handle. Never kill
                    # by image name, PID discovery or a different operation.
                    child.kill()
                    child.wait(timeout=5)
        _authorize(paths, record, expected)
        if provenance._selector(paths.current_path)[0] != record.binding.selected_before:
            _fail()
        _verify(target, expected)
        for path, descriptor, before, changed in identities:
            after = os.fstat(descriptor)
            if (durable_state._copy_identity(path.lstat()) != before
                    or durable_state._copy_identity(after) != before
                    or after.st_ctime_ns != changed):
                _fail()
    return True


def cancel_candidate_payload(paths, record, expected):
    """After original-state/native-settlement proof, undo only our publication.

    Partial private staging stays as protected evidence. No arbitrary payload
    is deleted, and no selected runtime or MSI-owned tree is moved.
    """
    root, source, target, _ = _authorize(paths, record, expected)
    if not _present(root): return None
    phase = _journal(root, record)
    if phase in {'copying', 'prepared', 'cancelled'}:
        if _present(target): _fail()
        return None
    if phase not in {'publishing', 'published', 'cancelling'}: _fail()
    if _present(target) and not _present(source):
        _verify(target, expected)
        _write(root, record, 'cancelling')
        durable_state.durable_rename_directory(target, source, trusted_root=paths.install_root.parent)
    elif _present(target) or not _present(source):
        _fail()
    _verify(source, expected)
    _write(root, record, 'cancelled')
    return source


def cancel_prepared_candidate(paths, record):
    """Historical operations without this journal require no extra media read."""
    durable_state.installer_mutation_checkpoint(required=True)
    root, _, _, archive = _paths(paths, record)
    if not _present(root): return None
    from .msi_inventory import read_expected_package
    expected = read_expected_package(archive.with_name('EndpointAgent.msi'), record.binding.new_release)
    return cancel_candidate_payload(paths, record, expected)
