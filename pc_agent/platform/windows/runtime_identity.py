"""Offline validation shared by the fixed Agent host and privileged worker."""
from __future__ import annotations

import re
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .update_paths import UPDATE_EXECUTABLE_NAME, WindowsUpdatePaths

_SEMVER_TRIPLET = re.compile(r'^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$')

# Exact independently retained immutable media identities and reviewed runtime
# tree contracts. Compatibility is deliberately bounded to foundation82;
# missing metadata in any other payload does not acquire a nullable floor.
_LEGACY_MSI_CONTRACTS = {
    '2f7d778799f1e32645af7936dfaf3f090d6ad4df5bb883827ea8a0a5d859f72a': {
        'version': '3.2.79', 'source_revision': 'd9b0fea2b14e34b05e25058e4ee004ea61643ca6',
        'file_count': 2543, 'tree_sha256': '06200efd1ee8b2914828e71eef65db8e6dd803318b44047672b8b9dc40c950c4',
        'component_guid': 'F15DDAF9-80BC-4944-921C-D2561CE923F9', 'approved_foundations': ('3.2.82',)},
    'ad4dc49703513d6dee6fd3e51ac94a09c5967112d58aed4e60a63cf6966251f5': {
        'version': '3.2.81', 'source_revision': 'c05bb0a528527ed1544c88fb0b1570c64b32084d',
        'file_count': 2543, 'tree_sha256': 'a4db007c0e313f6d5b34633aeaad10a2a47f01aeed6444b97021b3e222a580e2',
        'component_guid': 'D9917B58-851E-4230-B1AD-1B0F9D3719D7', 'approved_foundations': ('3.2.82',)},
}


def verify_legacy_msi_payload(root: Path, *, package_sha256: str,
                              excluded: frozenset[str] = frozenset()):
    from endpoint_contracts.runtime_payload import PayloadConflict, PayloadFile, PayloadIdentity, safe_path, reject_reparse_ancestors
    contract = _LEGACY_MSI_CONTRACTS.get(package_sha256)
    if contract is None or not excluded <= {'.endpoint-msi-runtime.json', '.endpoint-retained-msi.json'}:
        raise PayloadConflict()
    reject_reparse_ancestors(root)
    files, names, total = [], set(), 0
    for path in root.rglob('*'):
        reject_reparse_ancestors(path)
        relative = safe_path(path.relative_to(root).as_posix())
        if relative.casefold() in names:
            raise PayloadConflict()
        names.add(relative.casefold())
        if path.is_dir() or relative in excluded:
            continue
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise PayloadConflict()
        total += before.st_size
        if total > 2 * 1024 * 1024 * 1024 or len(files) >= 10000:
            raise PayloadConflict()
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise PayloadConflict()
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = path.lstat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise PayloadConflict()
        files.append(PayloadFile(relative, before.st_size, digest))
    original = sorted((('endpoint_agent_core.exe' if item.path == 'pc_agent.exe' else item.path), item.size, item.sha256) for item in files)
    digest = hashlib.sha256()
    for name, size, sha256 in original:
        digest.update(f'{name}\0{size}\0{sha256}\n'.encode())
    if (len(files) != contract['file_count'] or digest.hexdigest() != contract['tree_sha256']
        or 'pc_agent.exe' not in {item.path for item in files}):
        raise PayloadConflict()
    return PayloadIdentity(contract['version'], contract['source_revision'], None, tuple(sorted(files, key=lambda item:item.path)))


def _reject_reparse_chain(root: Path, leaf: Path) -> None:
    try:
        leaf.absolute().relative_to(root.absolute())
    except ValueError as error:
        raise ValueError('selected runtime is outside versions root') from error
    for part in (Path(), *leaf.relative_to(root).parents[::-1], leaf.relative_to(root)):
        candidate = root if part == Path() else root / part
        try:
            details = candidate.lstat()
        except OSError as error:
            raise ValueError('selected runtime is missing') from error
        if candidate.is_symlink() or getattr(details, 'st_file_attributes', 0) & 0x400:
            raise ValueError('selected runtime contains a reparse point')


def validate_runtime_executable(paths: WindowsUpdatePaths, version: str) -> Path:
    if not _SEMVER_TRIPLET.fullmatch(version):
        raise ValueError('selected runtime version is invalid')
    executable = paths.versions_root / version / UPDATE_EXECUTABLE_NAME
    _reject_reparse_chain(paths.versions_root, executable)
    if not executable.is_file():
        raise ValueError('selected runtime executable is missing')
    retained_link = executable.parent / '.endpoint-retained-msi.json'
    try:
        retained_link.lstat()
    except FileNotFoundError:
        pass
    else:
        verify_retained_runtime(paths, version)
    return executable


@dataclass(frozen=True)
class RetainedCore:
    identity: object
    archive: Path
    record: dict
    record_bytes: bytes
    link_bytes: bytes


def _retained_bytes(path: Path, maximum: int) -> bytes:
    from .installer_fence import assert_state_security
    assert_state_security(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
        raise ValueError('PROVENANCE_CONFLICT')
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('PROVENANCE_CONFLICT')
        data = stream.read(maximum + 1)
    after = path.lstat()
    if (len(data) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise ValueError('PROVENANCE_CONFLICT')
    return data


def verify_retained_archive(paths: WindowsUpdatePaths, archive_id: str) -> RetainedCore:
    """Verify protected historical package/payload evidence without loading MSI."""
    from endpoint_contracts.runtime_payload import read_json, verify_payload, manifest_files
    from .installer_fence import state_root, assert_state_security
    if not isinstance(archive_id, str) or not re.fullmatch('[0-9a-f]{64}', archive_id):
        raise ValueError('PROVENANCE_CONFLICT')
    archive = state_root(paths) / 'retained' / archive_id
    assert_state_security(archive)
    record_bytes = _retained_bytes(archive / 'receipt.json', 16 * 1024 * 1024)
    record = read_json(record_bytes, 16 * 1024 * 1024)
    fields = {'schema_version', 'origin', 'phase', 'transaction_id', 'identity_digest', 'version',
        'source_revision', 'minimum_launcher_version', 'tree_sha256', 'file_count', 'package',
        'former_native_inventory', 'manifest', 'selector_bytes', 'original_receipt_bytes', 'original_marker_bytes',
        'original_manifest_bytes', 'compatibility_foundations'}
    if (set(record) != fields or type(record['schema_version']) is not int or record['schema_version'] != 1
        or record['origin'] != 'retained_msi' or record['phase'] != 'prepared' or record['identity_digest'] != archive_id):
        raise ValueError('PROVENANCE_CONFLICT')
    if read_json(bytes.fromhex(record['original_manifest_bytes']), 4 * 1024 * 1024) != record['manifest']:
        raise ValueError('PROVENANCE_CONFLICT')
    package = record['package']
    if (not isinstance(package, dict) or set(package) != {'sha256','size','product_code','package_code','version'}
        or not isinstance(package['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', package['sha256'])
        or type(package['size']) is not int or not 0 < package['size'] <= 512 * 1024 * 1024):
        raise ValueError('PROVENANCE_CONFLICT')
    package_path = archive / 'package.msi'
    assert_state_security(package_path)
    before = package_path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != package['size']:
        raise ValueError('PROVENANCE_CONFLICT')
    with package_path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('PROVENANCE_CONFLICT')
        if hashlib.file_digest(stream, 'sha256').hexdigest() != package['sha256']:
            raise ValueError('PROVENANCE_CONFLICT')
    after = package_path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('PROVENANCE_CONFLICT')
    payload_root = archive / 'payload'
    assert_state_security(payload_root)
    compatibility = record['compatibility_foundations']
    if not isinstance(compatibility, list):
        raise ValueError('PROVENANCE_CONFLICT')
    if compatibility:
        contract = _LEGACY_MSI_CONTRACTS.get(package['sha256'])
        if contract is None or tuple(compatibility) != contract['approved_foundations']:
            raise ValueError('PROVENANCE_CONFLICT')
        identity = verify_legacy_msi_payload(payload_root, package_sha256=package['sha256'])
        if identity.files != manifest_files(record['manifest']):
            raise ValueError('PROVENANCE_CONFLICT')
    else:
        identity = verify_payload(payload_root, record['manifest'])
    if (identity.version != record['version'] or identity.source_revision != record['source_revision']
        or identity.minimum_launcher_version != record['minimum_launcher_version']
        or identity.tree_sha256 != record['tree_sha256'] or type(record['file_count']) is not int
        or identity.file_count != record['file_count']):
        raise ValueError('PROVENANCE_CONFLICT')
    for item in identity.files:
        assert_state_security(payload_root / item.path)
    return RetainedCore(identity, archive, record, record_bytes, b'')


def verify_retained_runtime(paths: WindowsUpdatePaths, version: str) -> RetainedCore:
    from endpoint_contracts.runtime_payload import read_json, verify_payload
    if not _SEMVER_TRIPLET.fullmatch(version):
        raise ValueError('PROVENANCE_CONFLICT')
    root = paths.versions_root / version
    link_bytes = _retained_bytes(root / '.endpoint-retained-msi.json', 4096)
    link = read_json(link_bytes, 4096)
    if (set(link) != {'schema_version','version','archive_id','receipt_sha256'}
        or type(link['schema_version']) is not int or link['schema_version'] != 1 or link['version'] != version):
        raise ValueError('PROVENANCE_CONFLICT')
    retained = verify_retained_archive(paths, link['archive_id'])
    if hashlib.sha256(retained.record_bytes).hexdigest() != link['receipt_sha256']:
        raise ValueError('PROVENANCE_CONFLICT')
    if retained.record['compatibility_foundations']:
        identity = verify_legacy_msi_payload(root, package_sha256=retained.record['package']['sha256'],
            excluded=frozenset({'.endpoint-retained-msi.json'}))
    else:
        identity = verify_payload(root, retained.record['manifest'], excluded=frozenset({'.endpoint-retained-msi.json'}))
    if identity != retained.identity or identity.version != version:
        raise ValueError('PROVENANCE_CONFLICT')
    return RetainedCore(identity, retained.archive, retained.record, retained.record_bytes, link_bytes)
