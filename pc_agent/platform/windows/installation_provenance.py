"""Full core identity inspection and installer-owned provenance transitions.

Foundation authority is independent of the selected executable. All inspection
is read-only; native MSI inventory is loaded only for an MSI-owned core.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import stat
import uuid

from endpoint_contracts.runtime_payload import (
    BUNDLE_FILENAME, MAX_MANIFEST_BYTES, PayloadConflict, PayloadIdentity,
    read_json, reject_reparse_ancestors, verify_payload, version_tuple,
)
from .update_paths import WindowsUpdatePaths

ProvenanceConflict = PayloadConflict
ZIP_RECEIPT = '.endpoint-update.json'
MSI_MARKER = '.endpoint-msi-runtime.json'
RETAINED_RECEIPT = '.endpoint-retained-msi.json'
_HASH = re.compile(r'^[0-9a-f]{64}$')
_SOURCE = re.compile(r'^[0-9a-f]{40}$')


@dataclass(frozen=True)
class CoreEvidence:
    origin: str
    identity: PayloadIdentity
    selector_bytes: bytes
    manifest_bytes: bytes
    receipt_bytes: bytes
    owner_bytes: bytes = b''
    compatibility_foundations: tuple[str, ...] = ()

    @property
    def digest(self) -> str:
        digest = hashlib.sha256()
        for value in (self.origin.encode(), self.identity.tree_sha256.encode(),
                      self.selector_bytes, self.manifest_bytes, self.receipt_bytes, self.owner_bytes,
                      json.dumps(self.compatibility_foundations).encode()):
            digest.update(len(value).to_bytes(8, 'big'))
            digest.update(value)
        return digest.hexdigest()


@dataclass(frozen=True)
class CoreInspection:
    current: CoreEvidence | None
    previous: CoreEvidence | None


def _assert_security(path: Path) -> None:
    from .update_transaction import _assert_state_security
    _assert_state_security(path)


def _read(path: Path, maximum: int) -> bytes:
    try:
        reject_reparse_ancestors(path)
        _assert_security(path)
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise ProvenanceConflict()
        with path.open('rb') as stream:
            data = stream.read(maximum + 1)
        after = path.stat()
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ProvenanceConflict()
        if len(data) != before.st_size:
            raise ProvenanceConflict()
        return data
    except (OSError, ValueError) as error:
        raise ProvenanceConflict() from error


def _selector(path: Path):
    data = _read(path, 4096)
    value = read_json(data, 4096)
    if set(value) not in ({'version'}, {'schema_version', 'source_revision', 'version'}):
        raise ProvenanceConflict()
    version_tuple(value['version'])
    if len(value) != 1 and (type(value['schema_version']) is not int or value['schema_version'] != 1
        or not isinstance(value['source_revision'], str) or not _SOURCE.fullmatch(value['source_revision'])):
        raise ProvenanceConflict()
    return data, value


def _present(path: Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def _inspect_zip(root: Path, selector_data: bytes, selector: dict) -> CoreEvidence:
    if _present(root / MSI_MARKER) or _present(root / RETAINED_RECEIPT):
        raise ProvenanceConflict()
    receipt_data = _read(root / ZIP_RECEIPT, 4096)
    receipt = read_json(receipt_data, 4096)
    if (set(receipt) != {'version', 'sha256', 'size'} or receipt['version'] != selector['version']
        or not isinstance(receipt['sha256'], str) or not _HASH.fullmatch(receipt['sha256'])
        or type(receipt['size']) is not int or not 0 < receipt['size'] <= 512 * 1024 * 1024):
        raise ProvenanceConflict()
    manifest_data = _read(root / BUNDLE_FILENAME, MAX_MANIFEST_BYTES)
    identity = verify_payload(root, read_json(manifest_data, MAX_MANIFEST_BYTES),
        excluded=frozenset({ZIP_RECEIPT, BUNDLE_FILENAME}))
    return CoreEvidence('zip', identity, selector_data, manifest_data, receipt_data)


def _inspect_legacy_msi(paths: WindowsUpdatePaths, root: Path, selector_data: bytes, selector: dict) -> CoreEvidence:
    from . import msi_inventory
    from .runtime_identity import _LEGACY_MSI_CONTRACTS, verify_legacy_msi_payload
    cache = paths.updates_root.parent / 'installer-cache'
    receipt_data = _read(cache / 'installer-provenance.json', 4096)
    receipt = read_json(receipt_data, 4096)
    fields = {'cache_file', 'initial_runtime_tree_sha256', 'package_sha256', 'product_code',
        'release_manifest_schema_version', 'schema_version', 'source_revision', 'version'}
    if set(receipt) != fields or receipt['schema_version'] != 'endpoint_windows_installer_provenance_v1':
        raise ProvenanceConflict()
    contract = _LEGACY_MSI_CONTRACTS.get(receipt['package_sha256'])
    if (contract is None or receipt['version'] != selector['version'] or receipt['version'] != contract['version']
        or receipt['source_revision'] != contract['source_revision']
        or receipt['initial_runtime_tree_sha256'] != contract['tree_sha256']
        or receipt['release_manifest_schema_version'] != 'endpoint_windows_release_v1'
        or receipt['cache_file'] != f"msi-{receipt['package_sha256']}/EndpointAgent.msi"):
        raise ProvenanceConflict()
    package_path = cache / receipt['cache_file']
    _assert_security(package_path)
    package = msi_inventory.read_package(package_path, receipt['package_sha256'])
    if package.product_code != receipt['product_code'] or package.version != contract['version']:
        raise ProvenanceConflict()
    msi_inventory.verify_installed(package, paths.install_root)
    marker = read_json(_read(root / MSI_MARKER, 4096), 4096)
    if marker != {'schema_version':1, 'version':contract['version'], 'component_guid':contract['component_guid']}:
        raise ProvenanceConflict()
    identity = verify_legacy_msi_payload(root, package_sha256=package.sha256, excluded=frozenset({MSI_MARKER}))
    manifest = {'schema_version':1, 'version':identity.version, 'source_revision':identity.source_revision,
        'files':[asdict(item) for item in identity.files]}
    return CoreEvidence('msi', identity, selector_data, json.dumps(manifest, separators=(',', ':')).encode(),
        receipt_data, json.dumps(asdict(package), separators=(',', ':')).encode(), contract['approved_foundations'])


def _inspect_modern_msi(paths: WindowsUpdatePaths, root: Path, selector_data: bytes, selector: dict) -> CoreEvidence:
    from . import msi_inventory
    from .installer_fence import state_root, assert_state_security
    receipt_path = state_root(paths) / 'core-owners' / f"{selector['version']}.json"
    assert_state_security(receipt_path)
    receipt_bytes = _read(receipt_path, 4096)
    receipt = read_json(receipt_bytes, 4096)
    if (set(receipt) != {'schema_version', 'release'} or type(receipt['schema_version']) is not int or receipt['schema_version'] != 1
        or not isinstance(receipt['release'],dict) or not isinstance(receipt['release'].get('package_sha256'),str)
        or not _HASH.fullmatch(receipt['release']['package_sha256'])):
        raise ProvenanceConflict()
    release = receipt['release']
    package_path = state_root(paths) / 'packages' / release['package_sha256'] / 'EndpointAgent.msi'
    assert_state_security(package_path)
    expected = msi_inventory.read_expected_package(package_path, release)
    msi_inventory.verify_installed(expected.package, paths.install_root)
    marker = read_json(_read(root / MSI_MARKER, 4096), 4096)
    core = next(item for item in expected.package.files if item.path == f'versions/{expected.identity.version}/pc_agent.exe')
    component = expected.package.components[core.component]
    if marker != {'schema_version':1, 'version':expected.identity.version, 'component_guid':component.guid.strip('{}')}:
        raise ProvenanceConflict()
    manifest_bytes = _read(root / BUNDLE_FILENAME, MAX_MANIFEST_BYTES)
    if read_json(manifest_bytes, MAX_MANIFEST_BYTES) != expected.manifest:
        raise ProvenanceConflict()
    identity = verify_payload(root, expected.manifest, excluded=frozenset({MSI_MARKER, BUNDLE_FILENAME}))
    if identity != expected.identity:
        raise ProvenanceConflict()
    return CoreEvidence('msi', identity, selector_data, manifest_bytes, receipt_bytes,
        json.dumps(asdict(expected.package), separators=(',', ':')).encode())


def _inspect_core(paths: WindowsUpdatePaths, selector_path: Path, resulting_foundation: str) -> CoreEvidence:
    selector_data, selector = _selector(selector_path)
    return _inspect_core_value(paths, selector_data, selector, resulting_foundation)


def _inspect_core_value(paths: WindowsUpdatePaths, selector_data: bytes, selector: dict, resulting_foundation: str) -> CoreEvidence:
    root = paths.versions_root / selector['version']
    reject_reparse_ancestors(root)
    _assert_security(root)
    if _present(root / ZIP_RECEIPT):
        evidence = _inspect_zip(root, selector_data, selector)
    elif _present(root / RETAINED_RECEIPT):
        from .runtime_identity import verify_retained_runtime
        retained = verify_retained_runtime(paths, selector['version'])
        evidence = CoreEvidence('retained_msi', retained.identity, selector_data,
            bytes.fromhex(retained.record['original_manifest_bytes']), retained.link_bytes, retained.record_bytes,
            tuple(retained.record['compatibility_foundations']))
    elif _present(root / MSI_MARKER):
        from .installer_fence import state_root
        if _present(state_root(paths) / 'core-owners' / f"{selector['version']}.json"):
            evidence = _inspect_modern_msi(paths, root, selector_data, selector)
        else:
            evidence = _inspect_legacy_msi(paths, root, selector_data, selector)
    else:
        # Non-ZIP ownership must be established from protected package/archive
        # authority, never from an executable or marker merely being present.
        raise ProvenanceConflict()
    if (evidence.identity.version != selector['version']
        or (selector.get('source_revision') != evidence.identity.source_revision
            and not (set(selector) == {'version'} and evidence.compatibility_foundations))
        or (evidence.compatibility_foundations and resulting_foundation not in evidence.compatibility_foundations)
        or (evidence.identity.minimum_launcher_version is not None
            and version_tuple(evidence.identity.minimum_launcher_version) > version_tuple(resulting_foundation))):
        raise ProvenanceConflict()
    return evidence


def inspect_installed_core(paths: WindowsUpdatePaths, *, resulting_foundation: str) -> CoreInspection:
    """Capture complete selector and core identity before an installer can write."""
    version_tuple(resulting_foundation)
    try:
        current = _inspect_core(paths, paths.current_path, resulting_foundation) if _present(paths.current_path) else None
        previous = _inspect_core(paths, paths.previous_path, resulting_foundation) if _present(paths.previous_path) else None
        if current is None and previous is not None:
            raise ProvenanceConflict()
        return CoreInspection(current, previous)
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise ProvenanceConflict() from error


def _archive_directory(parent: Path, name: str) -> Path:
    from .installer_fence import assert_state_security, protect_state
    from .durable_state import flush_directory, installer_mutation_checkpoint
    assert_state_security(parent)
    destination = parent / name
    if not _present(destination):
        # The parent already restricts writers and supplies the intended
        # inherited readers. Apply the explicit protected policy before bytes.
        installer_mutation_checkpoint()
        destination.mkdir()
        protect_state(destination)
    assert_state_security(destination)
    if not destination.is_dir():
        raise ProvenanceConflict()
    flush_directory(parent)
    return destination


def retention_allocations(paths: WindowsUpdatePaths, evidence: CoreEvidence, package_size: int):
    """Charge real archive plus possible rehydration and largest copy temporary."""
    from .installer_fence import state_root
    if type(package_size) is not int or not 0 < package_size <= 512 * 1024 * 1024:
        raise ProvenanceConflict()
    payload_size = sum(item.size for item in evidence.identity.files)
    metadata_size = len(evidence.selector_bytes) + len(evidence.manifest_bytes) * 3 + len(evidence.receipt_bytes) + 65536
    return ((state_root(paths), package_size + payload_size + metadata_size + max(package_size,
        max(item.size for item in evidence.identity.files))), (paths.versions_root, payload_size + metadata_size))


def _verify_retention_payload(root: Path, manifest: dict, package_sha256: str, compatibility_foundations,
                              *, excluded: frozenset[str] = frozenset()):
    if compatibility_foundations:
        from .runtime_identity import _LEGACY_MSI_CONTRACTS, verify_legacy_msi_payload
        contract = _LEGACY_MSI_CONTRACTS.get(package_sha256)
        if contract is None or tuple(compatibility_foundations) != contract['approved_foundations']:
            raise ProvenanceConflict()
        return verify_legacy_msi_payload(root, package_sha256=package_sha256, excluded=excluded - {BUNDLE_FILENAME})
    return verify_payload(root, manifest, excluded=excluded)


def archive_retained_core(paths: WindowsUpdatePaths, evidence: CoreEvidence, *, package_path: Path,
                         package, transaction_id: str) -> Path:
    """Prepare full retention before MajorUpgrade; do not alter the live core.

    The authenticated installer phase calls this while owning exclusion. A
    prepared archive is historical capture, not a claim of an absent/live
    product. Only post-MSI reconciliation may publish its retained-core link.
    """
    from . import durable_state, msi_inventory
    from .disk_readiness import require_allocation_space
    from .installer_fence import state_root, assert_state_security, protect_state
    if evidence.origin != 'msi' or str(uuid.UUID(transaction_id)) != transaction_id:
        raise ProvenanceConflict()
    if msi_inventory.read_package(package_path, package.sha256) != package:
        raise ProvenanceConflict()
    msi_inventory.verify_installed(package, paths.install_root)
    source = paths.versions_root / evidence.identity.version
    manifest = read_json(evidence.manifest_bytes, MAX_MANIFEST_BYTES)
    observed = _verify_retention_payload(source, manifest, package.sha256, evidence.compatibility_foundations,
        excluded=frozenset({MSI_MARKER, BUNDLE_FILENAME}))
    if observed != evidence.identity:
        raise ProvenanceConflict()
    marker = _read(source / MSI_MARKER, 4096)
    package_size = package_path.stat().st_size
    require_allocation_space(retention_allocations(paths, evidence, package_size))
    parent = _archive_directory(state_root(paths), 'retained')
    archive = _archive_directory(parent, evidence.digest)
    payload_root = _archive_directory(archive, 'payload')
    expected = {
        'schema_version': 1, 'origin': 'retained_msi', 'phase': 'prepared',
        'transaction_id': transaction_id, 'identity_digest': evidence.digest,
        'version': evidence.identity.version, 'source_revision': evidence.identity.source_revision,
        'minimum_launcher_version': evidence.identity.minimum_launcher_version,
        'compatibility_foundations': list(evidence.compatibility_foundations),
        'tree_sha256': evidence.identity.tree_sha256, 'file_count': evidence.identity.file_count,
        'package': {'sha256': package.sha256, 'size': package_size,
            'product_code': package.product_code, 'package_code': package.package_code, 'version': package.version},
        'former_native_inventory': asdict(package), 'manifest': manifest,
        'selector_bytes': evidence.selector_bytes.hex(), 'original_receipt_bytes': evidence.receipt_bytes.hex(),
        'original_marker_bytes': marker.hex(), 'original_manifest_bytes': evidence.manifest_bytes.hex(),
    }
    record = archive / 'receipt.json'
    if _present(record):
        assert_state_security(record)
        existing=read_json(_read(record, 16 * 1024 * 1024), 16 * 1024 * 1024)
        if str(uuid.UUID(existing['transaction_id']))!=existing['transaction_id']:
            raise ProvenanceConflict()
        # Capture identity is independent of the later owner session. Reuse
        # repeats every package/payload validation and durability barrier.
        expected['transaction_id']=existing['transaction_id']
        if existing != json.loads(json.dumps(expected)):
            raise ProvenanceConflict()
    durable_state.durable_copy_file(package_path, archive / 'package.msi', source_root=package_path.parent,
        trusted_root=archive, max_bytes=512 * 1024 * 1024, expected_size=package_size,
        expected_sha256=package.sha256, protect=protect_state, validate=assert_state_security)
    for item in evidence.identity.files:
        directory = payload_root
        for name in Path(item.path).parts[:-1]:
            directory = _archive_directory(directory, name)
        durable_state.durable_copy_file(source / item.path, payload_root / item.path,
            source_root=source, trusted_root=payload_root, max_bytes=2 * 1024 * 1024 * 1024,
            expected_size=item.size, expected_sha256=item.sha256, protect=protect_state, validate=assert_state_security)
    if (_verify_retention_payload(payload_root, manifest, package.sha256, evidence.compatibility_foundations) != evidence.identity
        or _verify_retention_payload(source, manifest, package.sha256, evidence.compatibility_foundations,
            excluded=frozenset({MSI_MARKER, BUNDLE_FILENAME})) != evidence.identity
        or _read(source / MSI_MARKER, 4096) != marker):
        raise ProvenanceConflict()
    msi_inventory.verify_installed(package, paths.install_root)
    durable_state.write_json_atomic(record, expected, trusted_root=archive,
        max_bytes=16 * 1024 * 1024, protect=protect_state)
    return archive


def restore_retained_core(paths: WindowsUpdatePaths, archive_id: str) -> None:
    """Resume exact archived payload publication only after native owner removal.

    The installer fence remains active throughout. Per-file publication is
    resumable; the retained-origin link is written only after full verification.
    Neither a ZIP receipt nor an active MSI marker is manufactured.
    """
    from . import durable_state, msi_inventory
    from .installer_fence import protect_state, assert_state_security
    from .runtime_identity import verify_retained_archive, verify_retained_runtime
    from .disk_readiness import require_allocation_space
    retained = verify_retained_archive(paths, archive_id)
    if msi_inventory.NativeMsi().product(retained.record['package']['product_code']) != -1:
        raise ProvenanceConflict()
    root = paths.versions_root / retained.identity.version
    expected = {item.path: item for item in retained.identity.files}
    marker = bytes.fromhex(retained.record['original_marker_bytes'])
    link = {'schema_version': 1, 'version': retained.identity.version, 'archive_id': archive_id,
        'receipt_sha256': hashlib.sha256(retained.record_bytes).hexdigest()}
    if _present(root):
        reject_reparse_ancestors(root)
        _assert_security(root)
        for file in root.rglob('*'):
            reject_reparse_ancestors(file)
            _assert_security(file)
            if file.is_dir():
                continue
            relative = file.relative_to(root).as_posix()
            if relative == MSI_MARKER:
                if _read(file, 4096) != marker:
                    raise ProvenanceConflict()
            elif relative == BUNDLE_FILENAME:
                if _read(file, MAX_MANIFEST_BYTES) != bytes.fromhex(retained.record['original_manifest_bytes']):
                    raise ProvenanceConflict()
            elif relative == RETAINED_RECEIPT:
                if read_json(_read(file, 4096), 4096) != link:
                    raise ProvenanceConflict()
            else:
                item = expected.get(relative)
                if item is None or file.stat().st_nlink != 1 or file.stat().st_size != item.size:
                    raise ProvenanceConflict()
                with file.open('rb') as stream:
                    if hashlib.file_digest(stream, 'sha256').hexdigest() != item.sha256:
                        raise ProvenanceConflict()
    require_allocation_space(((root, sum(item.size for item in retained.identity.files
        if not _present(root / item.path)) + 16384),))
    journal = retained.archive / 'rehydration.json'
    if _present(journal) and read_json(_read(journal, 4096), 4096) != link:
        raise ProvenanceConflict()
    durable_state.write_json_atomic(journal, link, trusted_root=retained.archive,
        max_bytes=4096, protect=protect_state)
    if not _present(root):
        _assert_security(paths.versions_root)
        durable_state.installer_mutation_checkpoint()
        root.mkdir()
        protect_state(root)
        durable_state.flush_directory(root.parent)
    else:
        # Native owner is absent and every remaining file was matched above.
        # Apply the explicit retained-archive reader/writer policy, rather than
        # assuming the removed MSI's inherited ACL equals that policy.
        protect_state(root)
        for path in root.rglob('*'):
            protect_state(path)
    for item in retained.identity.files:
        directory = root
        for name in Path(item.path).parts[:-1]:
            directory = _archive_directory(directory, name)
        durable_state.durable_copy_file(retained.archive / 'payload' / item.path, root / item.path,
            source_root=retained.archive / 'payload', trusted_root=root,
            max_bytes=2 * 1024 * 1024 * 1024, expected_size=item.size, expected_sha256=item.sha256,
            protect=protect_state, validate=assert_state_security)
    if _verify_retention_payload(root, retained.record['manifest'], retained.record['package']['sha256'],
        retained.record['compatibility_foundations'], excluded=frozenset({MSI_MARKER, BUNDLE_FILENAME, RETAINED_RECEIPT})) != retained.identity:
        raise ProvenanceConflict()
    # Original ownership evidence is already inside the durable receipt.
    for name in (MSI_MARKER, BUNDLE_FILENAME):
        durable_state.durable_unlink(root / name, trusted_root=root, missing_ok=True)
    durable_state.write_json_atomic(root / RETAINED_RECEIPT, link, trusted_root=root,
        max_bytes=4096, protect=protect_state)
    verify_retained_runtime(paths, retained.identity.version)
    durable_state.durable_unlink(journal, trusted_root=retained.archive, missing_ok=True)


def _expected_request(expected_msi):
    from .msi_inventory import read_expected_package
    if (set(expected_msi) != {'package_path','release','transaction_id','selected','previous'}
        or str(uuid.UUID(expected_msi['transaction_id'])) != expected_msi['transaction_id']):
        raise ProvenanceConflict()
    for key in ('selected', 'previous'):
        if expected_msi[key] is not None and (not isinstance(expected_msi[key], str) or not _HASH.fullmatch(expected_msi[key])):
            raise ProvenanceConflict()
    return read_expected_package(Path(expected_msi['package_path']), expected_msi['release'])


def _selector_bytes(identity) -> bytes:
    return json.dumps({'schema_version':1, 'source_revision':identity.source_revision, 'version':identity.version},
        separators=(',', ':')).encode()


def prepare_installer_provenance(paths: WindowsUpdatePaths, expected_msi) -> str:
    """Final read-only comparison followed by durable preparation, before MSI."""
    from . import durable_state, msi_inventory
    from .installer_fence import state_root, protect_state, assert_state_security
    from .disk_readiness import require_allocation_space
    expected = _expected_request(expected_msi)
    inspected = inspect_installed_core(paths, resulting_foundation=expected.package.version)
    if ((inspected.current.digest if inspected.current else None) != expected_msi['selected']
        or (inspected.previous.digest if inspected.previous else None) != expected_msi['previous']):
        raise ProvenanceConflict()
    candidate = None
    candidate_root = paths.versions_root / expected.identity.version
    if _present(candidate_root):
        for evidence in (inspected.current, inspected.previous):
            if evidence and evidence.identity.version == expected.identity.version:
                candidate = evidence
                break
        if candidate is None:
            selector = {'schema_version':1,'version':expected.identity.version,'source_revision':expected.identity.source_revision}
            candidate = _inspect_core_value(paths, _selector_bytes(expected.identity), selector, expected.package.version)
        if candidate.identity != expected.identity:
            raise ProvenanceConflict()
        # Identical payload bytes do not transfer historical or another
        # package's ownership to this live product.
        if candidate.origin == 'retained_msi' or (candidate.origin == 'msi' and
            read_json(candidate.receipt_bytes,4096) != {'schema_version':1,'release':expected_msi['release']}):
            raise ProvenanceConflict()
    selected = inspected.current
    if selected is None or version_tuple(selected.identity.version) < version_tuple(expected.identity.version):
        result, after = 'migrated', _selector_bytes(expected.identity)
        previous_after = selected.selector_bytes if selected else None
    elif selected.identity.version == expected.identity.version:
        result = 'already_current' if selected.origin == 'msi' else 'handoff'
        after = selected.selector_bytes
        previous_after = inspected.previous.selector_bytes if inspected.previous else None
    else:
        result, after = 'preserved', selected.selector_bytes
        previous_after = inspected.previous.selector_bytes if inspected.previous else None
    package_path = Path(expected_msi['package_path'])
    allocations=[(state_root(paths),2*package_path.stat().st_size+MAX_MANIFEST_BYTES+16384)]
    jobs=[]
    retained_versions=set()
    for evidence in (inspected.current, inspected.previous):
        if evidence is None or evidence.origin != 'msi':
            continue
        receipt = read_json(evidence.receipt_bytes, 4096)
        if receipt.get('schema_version') == 'endpoint_windows_installer_provenance_v1':
            old_path = paths.updates_root.parent / 'installer-cache' / receipt['cache_file']
            old_hash = receipt['package_sha256']
        else:
            old_hash = receipt['release']['package_sha256']
            old_path = state_root(paths) / 'packages' / old_hash / 'EndpointAgent.msi'
        old_package = msi_inventory.read_package(old_path, old_hash)
        if old_package.product_code != expected.package.product_code and evidence.identity.version not in retained_versions:
            retained_versions.add(evidence.identity.version)
            jobs.append((evidence,old_path,old_package))
            allocations.extend(retention_allocations(paths,evidence,old_path.stat().st_size))
    # Admit the combined incoming media, every retained package/payload,
    # copy temporaries and later rehydration before the first archive byte.
    require_allocation_space(tuple(allocations))
    archives=[]
    for evidence,old_path,old_package in jobs:
        archive=archive_retained_core(paths,evidence,package_path=old_path,package=old_package,
            transaction_id=expected_msi['transaction_id'])
        archives.append(archive.name)
    package_root = _archive_directory(_archive_directory(state_root(paths), 'packages'), expected.package.sha256)
    durable_state.durable_copy_file(package_path, package_root / 'EndpointAgent.msi', source_root=package_path.parent,
        trusted_root=package_root, max_bytes=512*1024*1024, expected_size=package_path.stat().st_size,
        expected_sha256=expected.package.sha256, protect=protect_state, validate=assert_state_security)
    root = _archive_directory(_archive_directory(state_root(paths), 'provenance'), expected_msi['transaction_id'])
    if candidate and candidate.origin == 'zip':
        for name, data in (('handoff-receipt.json',candidate.receipt_bytes), ('handoff-manifest.json',candidate.manifest_bytes)):
            target = root / name
            if _present(target) and _read(target, MAX_MANIFEST_BYTES) != data:
                raise ProvenanceConflict()
            durable_state.write_bytes_atomic(target, data, trusted_root=root, max_bytes=MAX_MANIFEST_BYTES, protect=protect_state)
    plan = {'schema_version':1, 'phase':'prepared', 'package_sha256':expected.package.sha256,
        'transaction_id':expected_msi['transaction_id'], 'result':result, 'archives':archives,
        'selected':expected_msi['selected'],'previous':expected_msi['previous'],
        'current_before':selected.selector_bytes.hex() if selected else None,
        'previous_before':inspected.previous.selector_bytes.hex() if inspected.previous else None,
        'current_after':after.hex(), 'previous_after':previous_after.hex() if previous_after else None,
        'handoff':bool(candidate and candidate.origin=='zip')}
    plan_path = root / 'plan.json'
    if _present(plan_path) and read_json(_read(plan_path, 16384), 16384) != plan:
        raise ProvenanceConflict()
    durable_state.write_json_atomic(plan_path, plan, trusted_root=root, max_bytes=16384, protect=protect_state)
    return result


def inspect_runtime_retirement(paths: WindowsUpdatePaths, expected, *, recovery=False) -> CoreInspection:
    from .msi_inventory import verify_installed,verify_foundation
    from .update_transaction import active_update_state
    if active_update_state(paths) is not None:
        raise ValueError('UPDATE_IN_PROGRESS')
    inspected = inspect_installed_core(paths, resulting_foundation=expected.package.version)
    if (inspected.current is None or inspected.previous is None
        or inspected.current.origin != 'zip' or inspected.previous.origin != 'zip'
        or inspected.current.identity.version == inspected.previous.identity.version
        or expected.identity.version in {inspected.current.identity.version,inspected.previous.identity.version}):
        raise ProvenanceConflict()
    if recovery:
        verify_foundation(expected.package,paths.install_root,expected=expected)
        root=paths.versions_root/expected.identity.version
        core=next(item for item in expected.package.files if item.path==f'versions/{expected.identity.version}/pc_agent.exe')
        metadata={}
        for name,value in ((MSI_MARKER,{'schema_version':1,'version':expected.identity.version,
            'component_guid':expected.package.components[core.component].guid.strip('{}')}),(BUNDLE_FILENAME,expected.manifest)):
            if _present(root/name):
                raw=_read(root/name,MAX_MANIFEST_BYTES)
                if read_json(raw,MAX_MANIFEST_BYTES)!=value: raise ProvenanceConflict()
                metadata[name]=(raw,)
        _partial_tree(root,expected.identity,metadata)
        return inspected
    verify_installed(expected.package, paths.install_root)
    verify_foundation(expected.package,paths.install_root,expected=expected)
    selector={'schema_version':1,'version':expected.identity.version,'source_revision':expected.identity.source_revision}
    inactive=_inspect_core_value(paths,_selector_bytes(expected.identity),selector,expected.package.version)
    if inactive.origin!='msi' or inactive.identity!=expected.identity:
        raise ProvenanceConflict()
    return inspected


def prepare_maintenance_provenance(paths,request,operation):
    """Archive exact authority before feature removal without changing it."""
    from .installer_fence import state_root,assert_state_security,protect_state
    from .durable_state import write_json_atomic
    expected=_expected_request(request)
    if operation not in {'retire-initial-runtime','uninstall'}: raise ProvenanceConflict()
    state=state_root(paths)
    leaves={'core_owner':state/'core-owners'/f'{expected.identity.version}.json',
            'foundation':state/'foundation.json'}
    record={'schema_version':1,'transaction_id':request['transaction_id'],'operation':operation,
            'release':request['release']}
    for name,path in leaves.items():
        if _present(path):
            assert_state_security(path)
            data=_read(path,4096)
            if read_json(data,4096)!={'schema_version':1,'release':request['release']}: raise ProvenanceConflict()
            record[name]=data.hex()
        else:
            if name=='foundation' or operation=='retire-initial-runtime': raise ProvenanceConflict()
            record[name]=None
    root=_archive_directory(_archive_directory(state,'transactions'),request['transaction_id'])
    target=root/'maintenance.json'
    if _present(target) and read_json(_read(target,16384),16384)!=record: raise ProvenanceConflict()
    write_json_atomic(target,record,trusted_root=root,max_bytes=16384,protect=protect_state)


def validate_maintenance_recovery(paths,request,operation):
    """Read-only historical authority check before resuming native removal."""
    from .installer_fence import state_root,assert_state_security
    expected=_expected_request(request)
    state=state_root(paths)
    path=state/'transactions'/request['transaction_id']/'maintenance.json'
    assert_state_security(path)
    record=read_json(_read(path,16384),16384)
    if (set(record)!={'schema_version','transaction_id','operation','release','core_owner','foundation'}
        or type(record['schema_version']) is not int or record['schema_version']!=1
        or record['transaction_id']!=request['transaction_id'] or record['operation']!=operation
        or operation not in {'retire-initial-runtime','uninstall'} or record['release']!=request['release']):
        raise ProvenanceConflict()
    for name,leaf in {'core_owner':state/'core-owners'/f'{expected.identity.version}.json',
                      'foundation':state/'foundation.json'}.items():
        saved=record[name]
        if saved is None:
            if name=='foundation' or operation=='retire-initial-runtime' or _present(leaf): raise ProvenanceConflict()
            continue
        if not isinstance(saved,str) or len(saved)>8192: raise ProvenanceConflict()
        data=bytes.fromhex(saved)
        if read_json(data,4096)!={'schema_version':1,'release':request['release']}: raise ProvenanceConflict()
        if _present(leaf):
            assert_state_security(leaf)
            if _read(leaf,4096)!=data: raise ProvenanceConflict()
        elif name=='foundation' and operation=='retire-initial-runtime': raise ProvenanceConflict()
    return record


def retire_maintenance_authority(paths,request,operation):
    """After native removal, retire only authority captured by this transaction."""
    from .installer_fence import state_root,assert_state_security
    from .durable_state import durable_unlink
    expected=_expected_request(request)
    state=state_root(paths)
    record=validate_maintenance_recovery(paths,request,operation)
    leaves={'core_owner':state/'core-owners'/f'{expected.identity.version}.json'}
    if operation=='uninstall': leaves['foundation']=state/'foundation.json'
    for name,leaf in leaves.items():
        saved=record[name]
        if saved is None:
            if _present(leaf): raise ProvenanceConflict()
            continue
        data=bytes.fromhex(saved)
        if read_json(data,4096)!={'schema_version':1,'release':request['release']}: raise ProvenanceConflict()
        if _present(leaf):
            assert_state_security(leaf)
            if _read(leaf,4096)!=data: raise ProvenanceConflict()
        durable_unlink(leaf,trusted_root=leaf.parent,missing_ok=True)


def _partial_tree(root,identity,metadata):
    """Read-only recovery evidence; absence is repairable, unknown bytes are not."""
    if not _present(root):
        return
    reject_reparse_ancestors(root)
    _assert_security(root)
    expected={item.path:item for item in identity.files}
    for path in root.rglob('*'):
        reject_reparse_ancestors(path)
        if path.is_dir():
            continue
        relative=path.relative_to(root).as_posix()
        if relative in metadata:
            if _read(path,MAX_MANIFEST_BYTES) not in metadata[relative]:
                raise ProvenanceConflict()
        else:
            item=expected.get(relative)
            if item is None or path.stat().st_nlink!=1 or path.stat().st_size!=item.size:
                raise ProvenanceConflict()
            with path.open('rb') as stream:
                if hashlib.file_digest(stream,'sha256').hexdigest()!=item.sha256:
                    raise ProvenanceConflict()


def validate_interrupted_reconciliation(paths: WindowsUpdatePaths, expected_msi) -> None:
    """Inspect immutable saved authority; caller has not yet gained mutation entry."""
    from .installer_fence import state_root
    from .runtime_identity import verify_retained_archive
    expected=_expected_request(expected_msi)
    root=state_root(paths)/'provenance'/expected_msi['transaction_id']
    plan=_read_plan(root,expected_msi,expected)
    core=next(item for item in expected.package.files if item.path==f'versions/{expected.identity.version}/pc_agent.exe')
    candidate=paths.versions_root/expected.identity.version
    metadata={}
    for name,value in ((MSI_MARKER,{'schema_version':1,'version':expected.identity.version,
        'component_guid':expected.package.components[core.component].guid.strip('{}')}),
        (BUNDLE_FILENAME,expected.manifest)):
        if _present(candidate/name):
            raw=_read(candidate/name,MAX_MANIFEST_BYTES)
            if read_json(raw,MAX_MANIFEST_BYTES)!=value: raise ProvenanceConflict()
            metadata[name]=(raw,)
    if plan['handoff']:
        metadata[ZIP_RECEIPT]=(_read(root/'handoff-receipt.json',4096),)
        if read_json(_read(root/'handoff-manifest.json',MAX_MANIFEST_BYTES),MAX_MANIFEST_BYTES)!=expected.manifest:
            raise ProvenanceConflict()
    _partial_tree(candidate,expected.identity,metadata)
    retained_versions=set()
    for archive_id in plan['archives']:
        retained=verify_retained_archive(paths,archive_id)
        retained_versions.add(retained.identity.version)
        retained_root=paths.versions_root/retained.identity.version
        link={'schema_version':1,'version':retained.identity.version,'archive_id':archive_id,
            'receipt_sha256':hashlib.sha256(retained.record_bytes).hexdigest()}
        link_bytes=b''
        if _present(retained_root/RETAINED_RECEIPT):
            link_bytes=_read(retained_root/RETAINED_RECEIPT,4096)
            if read_json(link_bytes,4096)!=link: raise ProvenanceConflict()
        _partial_tree(retained_root,retained.identity,{
            MSI_MARKER:(bytes.fromhex(retained.record['original_marker_bytes']),),
            BUNDLE_FILENAME:(bytes.fromhex(retained.record['original_manifest_bytes']),),
            RETAINED_RECEIPT:(link_bytes,)})
    for name,before,after in (('current.json',plan['current_before'],plan['current_after']),
                             ('previous.json',plan['previous_before'],plan['previous_after'])):
        path=paths.install_root/name
        actual=_read(path,4096).hex() if _present(path) else None
        if actual not in (before,after):
            if before is not None or actual is None or after is None or read_json(bytes.fromhex(actual),4096)!=read_json(bytes.fromhex(after),4096):
                raise ProvenanceConflict()
        if actual is not None:
            raw=bytes.fromhex(actual);selector=read_json(raw,4096)
            if selector['version'] not in retained_versions|{expected.identity.version}:
                _inspect_core_value(paths,raw,selector,expected.package.version)


def _read_plan(root,expected_msi,expected):
    plan=read_json(_read(root/'plan.json',16384),16384)
    fields={'schema_version','phase','package_sha256','transaction_id','result','archives',
        'current_before','previous_before','current_after','previous_after','handoff','selected','previous'}
    if (not isinstance(plan,dict) or set(plan)!=fields or type(plan['schema_version']) is not int or plan['schema_version']!=1
        or plan['phase'] not in {'prepared','native_verified','complete'}
        or plan['transaction_id']!=expected_msi['transaction_id'] or plan['package_sha256']!=expected.package.sha256
        or any(plan[key]!=expected_msi[key] for key in ('selected','previous'))
        or plan['result'] not in {'migrated','preserved','handoff','already_current'}
        or not isinstance(plan['archives'],list) or len(plan['archives'])>2 or type(plan['handoff']) is not bool
        or any(not isinstance(value,str) or not _HASH.fullmatch(value) for value in plan['archives'])):
        raise ProvenanceConflict()
    for key in ('current_before','previous_before','current_after','previous_after'):
        value=plan[key]
        if value is None:
            if key=='current_after': raise ProvenanceConflict()
            continue
        if not isinstance(value,str) or not 0<len(value)<=8192 or len(value)%2 or not re.fullmatch('[0-9a-f]+',value):
            raise ProvenanceConflict()
        selector=read_json(bytes.fromhex(value),4096)
        if set(selector) not in ({'version'},{'schema_version','source_revision','version'}): raise ProvenanceConflict()
        version_tuple(selector['version'])
        if len(selector)>1 and (type(selector['schema_version']) is not int or selector['schema_version']!=1
            or not isinstance(selector['source_revision'],str) or not _SOURCE.fullmatch(selector['source_revision'])):
            raise ProvenanceConflict()
    return plan


def reconcile_installed_core(paths: WindowsUpdatePaths, expected_msi) -> str:
    """Commit validated native ownership; retry the same durable data boundaries."""
    from . import durable_state, msi_inventory
    from .installer_fence import state_root, assert_state_security, protect_state
    expected = _expected_request(expected_msi)
    root = state_root(paths) / 'provenance' / expected_msi['transaction_id']
    assert_state_security(root)
    plan_path = root / 'plan.json'
    plan = _read_plan(root,expected_msi,expected)
    msi_inventory.verify_installed(expected.package, paths.install_root)
    candidate_root = paths.versions_root / expected.identity.version
    marker = read_json(_read(candidate_root / MSI_MARKER, 4096), 4096)
    core = next(item for item in expected.package.files if item.path == f'versions/{expected.identity.version}/pc_agent.exe')
    if marker != {'schema_version':1,'version':expected.identity.version,
        'component_guid':expected.package.components[core.component].guid.strip('{}')}:
        raise ProvenanceConflict()
    if (verify_payload(candidate_root, expected.manifest, excluded=frozenset({MSI_MARKER,BUNDLE_FILENAME,ZIP_RECEIPT})) != expected.identity
        or read_json(_read(candidate_root / BUNDLE_FILENAME, MAX_MANIFEST_BYTES), MAX_MANIFEST_BYTES) != expected.manifest):
        raise ProvenanceConflict()
    for name, before, after in (('current.json',plan['current_before'],plan['current_after']),
                               ('previous.json',plan['previous_before'],plan['previous_after'])):
        path = paths.install_root / name
        actual = _read(path, 4096).hex() if _present(path) else None
        if actual not in (before, after):
            # A first install may create the same selector with MSI-authored
            # JSON formatting. Its complete semantic identity must still match.
            if before is not None or actual is None or after is None or read_json(bytes.fromhex(actual),4096) != read_json(bytes.fromhex(after),4096):
                raise ProvenanceConflict()
    if plan['handoff']:
        archived = _read(root / 'handoff-receipt.json', 4096)
        receipt = candidate_root / ZIP_RECEIPT
        if _present(receipt):
            if _read(receipt,4096) != archived:
                raise ProvenanceConflict()
        elif plan['phase'] == 'prepared':
            raise ProvenanceConflict()
        _read(root / 'handoff-manifest.json', MAX_MANIFEST_BYTES)
    elif _present(candidate_root / ZIP_RECEIPT):
        raise ProvenanceConflict()
    for archive_id in plan['archives']:
        restore_retained_core(paths, archive_id)
    if plan['phase'] == 'prepared':
        plan['phase'] = 'native_verified'
        durable_state.write_json_atomic(plan_path, plan, trusted_root=root, max_bytes=16384, protect=protect_state)
    if plan['handoff']:
        durable_state.durable_unlink(candidate_root / ZIP_RECEIPT, trusted_root=candidate_root, missing_ok=True)
    authority = {'schema_version':1, 'release':expected_msi['release']}
    owners = _archive_directory(state_root(paths), 'core-owners')
    durable_state.write_json_atomic(owners / f'{expected.identity.version}.json', authority,
        trusted_root=owners, max_bytes=4096, protect=protect_state)
    for name, value in (('previous.json',plan['previous_after']),('current.json',plan['current_after'])):
        if value is not None:
            from .acl import preserve_state_file_permissions
            path = paths.install_root / name
            template = path if _present(path) else paths.current_path
            durable_state.write_bytes_atomic(path, bytes.fromhex(value), trusted_root=paths.install_root,
                max_bytes=4096, protect=lambda temporary:preserve_state_file_permissions(template,temporary))
    inspected = inspect_installed_core(paths, resulting_foundation=expected.package.version)
    if inspected.current is None:
        raise ProvenanceConflict()
    durable_state.write_json_atomic(state_root(paths) / 'foundation.json', authority,
        trusted_root=state_root(paths), max_bytes=4096, protect=protect_state)
    plan['phase'] = 'complete'
    durable_state.write_json_atomic(plan_path, plan, trusted_root=root, max_bytes=16384, protect=protect_state)
    return plan['result']
