"""One retained payload tree, with crash-recoverable, fixed-path publication.

Capture receipts remain immutable v1 evidence. The separate v2 storage journal
only describes where those exact bytes live; it is not launch or MSI authority.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import stat
from uuid import UUID

from endpoint_contracts.runtime_payload import BUNDLE_FILENAME, read_json, version_tuple
from . import durable_state, installer_fence
from .staged_update_state import read_staged_update

_SCHEMA = 'endpoint_retained_storage_v2'
_LINK = '.endpoint-retained-msi.json'
_FIELDS = {'schema_version', 'archive_id', 'operation_id', 'tree_sha256', 'version',
           'phase', 'receipt_sha256', 'legacy_materialization'}


def _fail():
    raise ValueError('PROVENANCE_CONFLICT')


def _capture(paths, archive_id):
    from .runtime_identity import _retained_bytes
    if not isinstance(archive_id, str) or not re.fullmatch('[0-9a-f]{64}', archive_id):
        _fail()
    archive = installer_fence.state_root(paths) / 'retained' / archive_id
    installer_fence.assert_state_security(archive)
    raw = _retained_bytes(archive / 'receipt.json', 16 * 1024 * 1024)
    record = read_json(raw, 16 * 1024 * 1024)
    if (not isinstance(record, dict) or record.get('schema_version') != 1
            or record.get('identity_digest') != archive_id or record.get('origin') != 'retained_msi'):
        _fail()
    version_tuple(record['version'])
    if not re.fullmatch('[0-9a-f]{64}', record['tree_sha256']):
        _fail()
    return archive, record, hashlib.sha256(raw).hexdigest()


def _read_storage(archive, record, receipt_hash):
    from .runtime_identity import _retained_bytes
    path = archive / 'storage.json'
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    value = read_json(_retained_bytes(path, 4096), 4096)
    if (not isinstance(value, dict) or set(value) != _FIELDS
            or value['schema_version'] != _SCHEMA or value['archive_id'] != archive.name
            or value['version'] != record['version'] or value['tree_sha256'] != record['tree_sha256']
            or value['receipt_sha256'] != receipt_hash
            or value['phase'] not in {'staged', 'promoting', 'published'}
            or value['legacy_materialization'] not in {'none', 'copying', 'complete'}):
        _fail()
    try:
        if str(UUID(value['operation_id'])) != value['operation_id']:
            _fail()
    except (ValueError, TypeError, AttributeError):
        _fail()
    return value


def _present(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def retained_payload_location(paths, archive_id: str) -> Path:
    from .runtime_identity import _retained_payload_root
    archive, record, receipt_hash = _capture(paths, archive_id)
    source = _retained_payload_root(archive)
    value = _read_storage(archive, record, receipt_hash)
    if value is None or value['phase'] == 'staged' or value['legacy_materialization'] == 'complete':
        return source
    target = paths.versions_root / record['version']
    if value['phase'] == 'promoting' and _present(source):
        return source
    if not _present(target) or (_present(source) and value['legacy_materialization'] == 'none'):
        _fail()
    installer_fence.assert_state_security(target)
    return target


def _authorize(paths, archive_id, operation_id, phases):
    durable_state.installer_mutation_checkpoint(required=True)
    operation = read_staged_update(paths)
    if operation is None or operation.binding.operation_id != operation_id or operation.phase not in phases:
        _fail()
    archive, record, receipt_hash = _capture(paths, archive_id)
    binding = operation.binding
    options = [(binding.selected_before, binding.selected_tree_sha256_before)]
    if binding.previous_before is not None:
        options.append((binding.previous_before, binding.previous_tree_sha256_before))
    if not any(raw.hex() == record['selector_bytes'] and digest == record['tree_sha256'] for raw, digest in options):
        _fail()
    value = _read_storage(archive, record, receipt_hash)
    if value is not None and value['operation_id'] != operation_id:
        from .staged_update_state import read_archived_staged_update
        from .installation_provenance import _archive_directory
        prior = read_archived_staged_update(paths, value['operation_id'])
        prior_options = [(prior.binding.selected_before, prior.binding.selected_tree_sha256_before),
                         (prior.binding.previous_before, prior.binding.previous_tree_sha256_before)]
        if (value['phase'] != 'published' or not any(raw is not None and raw.hex() == record['selector_bytes']
                and digest == record['tree_sha256'] for raw, digest in prior_options)):
            _fail()
        from .runtime_identity import verify_retained_archive
        verify_retained_archive(paths, archive_id)
        history = _archive_directory(archive, 'storage-history')
        leaf = history / (value['operation_id'] + '.json')
        raw = (archive / 'storage.json').read_bytes()
        if leaf.exists():
            installer_fence.assert_state_security(leaf)
            if leaf.read_bytes() != raw:
                _fail()
        else:
            durable_state.write_bytes_atomic(leaf, raw, trusted_root=history, max_bytes=4096,
                                            protect=installer_fence.protect_state)
        value = {**value, 'operation_id': operation_id,
                 'phase': 'staged' if value['legacy_materialization'] == 'complete' else value['phase'],
                 'legacy_materialization': 'none'}
        _write(archive, value)
    return archive, record, receipt_hash, value


def _write(archive, value):
    durable_state.installer_mutation_checkpoint(required=True)
    durable_state.write_json_atomic(archive / 'storage.json', value, trusted_root=archive,
                                    max_bytes=4096, protect=installer_fence.protect_state)


def _verify_residue(root, record):
    """Admit only a subset of the genuine before-tree left behind by MSI."""
    from .runtime_identity import _retained_bytes
    expected = {item['path']: item for item in record['manifest']['files']}
    directories = {parent.as_posix() for name in expected for parent in Path(name).parents if str(parent) != '.'}
    metadata = {'.endpoint-msi-runtime.json': bytes.fromhex(record['original_marker_bytes']),
                BUNDLE_FILENAME: bytes.fromhex(record['original_manifest_bytes'])}
    installer_fence.assert_state_security(root)
    for leaf in root.rglob('*'):
        installer_fence.assert_state_security(leaf)
        relative = leaf.relative_to(root).as_posix()
        details = leaf.lstat()
        if stat.S_ISDIR(details.st_mode):
            if relative not in directories:
                _fail()
            continue
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            _fail()
        if relative in metadata:
            if _retained_bytes(leaf, 4 * 1024 * 1024) != metadata[relative]:
                _fail()
        elif relative in expected:
            item = expected[relative]
            if details.st_size != item['size']:
                _fail()
            with leaf.open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != item['sha256']:
                    _fail()
        else:
            _fail()


def promote_retained_payload(paths, archive_id: str, operation_id: str) -> Path:
    from .msi_inventory import NativeMsi
    from .runtime_identity import verify_retained_archive, verify_retained_runtime, _retained_bytes
    from .disk_readiness import require_same_volume_rename
    archive, record, receipt_hash, value = _authorize(paths, archive_id, operation_id,
        {'switching', 'native-settled'})
    if NativeMsi().product(record['package']['product_code']) != -1:
        _fail()
    retained = verify_retained_archive(paths, archive_id)
    source, target = archive / 'payload', paths.versions_root / retained.identity.version
    installer_fence.assert_namespace_security(paths.versions_root, include_self=True)
    if value is None:
        require_same_volume_rename(source, target)
        value = {'schema_version': _SCHEMA, 'archive_id': archive_id, 'operation_id': operation_id,
                 'tree_sha256': record['tree_sha256'], 'version': record['version'],
                 'receipt_sha256': receipt_hash, 'phase': 'staged', 'legacy_materialization': 'none'}
        _write(archive, value)
    if value['phase'] == 'published':
        verify_retained_runtime(paths, record['version'])
        return target
    value = {**value, 'phase': 'promoting'}
    _write(archive, value)
    displaced = paths.versions_root / ('.staged-displaced-' + archive_id)
    if _present(source):
        if _present(target):
            _verify_residue(target, record)
            if _present(displaced):
                _fail()
            durable_state.durable_rename_directory(target, displaced, trusted_root=paths.install_root.parent)
        if _present(displaced):
            _verify_residue(displaced, record)
        durable_state.durable_rename_directory(source, target, trusted_root=paths.install_root.parent)
    else:
        # Replay must finish both namespace barriers even if rename was visible.
        durable_state.flush_directory(archive)
        durable_state.flush_directory(paths.versions_root)
    link = {'schema_version': 1, 'version': record['version'], 'archive_id': archive_id,
            'receipt_sha256': receipt_hash}
    link_path = target / _LINK
    if _present(link_path) and read_json(_retained_bytes(link_path, 4096), 4096) != link:
        _fail()
    durable_state.write_json_atomic(link_path, link, trusted_root=target,
                                    max_bytes=4096, protect=installer_fence.protect_state)
    verify_retained_runtime(paths, record['version'])
    _write(archive, {**value, 'phase': 'published'})
    return target


def materialize_legacy_retention(paths, archive_id: str, operation_id: str) -> None:
    from .runtime_identity import verify_retained_archive, _retained_payload_root
    from .installation_provenance import _archive_directory, _verify_retention_payload
    archive, record, _, value = _authorize(paths, archive_id, operation_id, {'rolling-back'})
    if value is None:
        verify_retained_archive(paths, archive_id)
        return
    if value['legacy_materialization'] == 'complete':
        verify_retained_archive(paths, archive_id)
        return
    retained = verify_retained_archive(paths, archive_id)
    source = paths.versions_root / retained.identity.version
    value = {**value, 'legacy_materialization': 'copying'}
    _write(archive, value)
    _archive_directory(archive, 'payload')
    payload = _retained_payload_root(archive)
    for item in retained.identity.files:
        directory = payload
        for name in Path(item.path).parts[:-1]:
            directory = _archive_directory(directory, name)
        durable_state.durable_copy_file(source / item.path, payload / item.path,
            source_root=source, trusted_root=payload, max_bytes=2 * 1024 * 1024 * 1024,
            expected_size=item.size, expected_sha256=item.sha256,
            protect=installer_fence.protect_state, validate=installer_fence.assert_state_security)
    if _verify_retention_payload(payload, record['manifest'], record['package']['sha256'],
                                 record['compatibility_foundations']) != retained.identity:
        _fail()
    _write(archive, {**value, 'legacy_materialization': 'complete'})
