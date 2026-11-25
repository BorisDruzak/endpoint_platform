"""Publishing a retained runtime must move its verified bytes, not recopy them."""
import hashlib
import json
import os
import shutil
from types import SimpleNamespace
from uuid import uuid4

import pytest

from endpoint_contracts.runtime_payload import verify_payload
from pc_agent.platform.windows import durable_state, installer_fence, msi_inventory, runtime_identity
from pc_agent.platform.windows import installation_provenance as provenance
from pc_agent.platform.windows import staged_update_state as staged_state
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
from pc_agent.tests.windows.test_installation_provenance import payload
from pc_agent.tests.windows.test_installer_fence import native_protected_root
from pc_agent.tests.windows.test_staged_update_state import release


@pytest.fixture
def retained(request, tmp_path, monkeypatch):
    from pc_agent.platform.windows import retained_storage
    base = request.getfixturevalue("native_protected_root") if os.name == "nt" else tmp_path
    paths = WindowsUpdatePaths(base / "Agent", base / "data/updates/pending_update.json")
    root = paths.versions_root / "3.2.120"
    root.parent.mkdir(parents=True)
    manifest = payload(root, version="3.2.120", minimum="3.2.120", source="a" * 40)
    selector = json.dumps({"schema_version": 1, "version": "3.2.120", "source_revision": "a" * 40}).encode()
    paths.current_path.write_bytes(selector)
    (root / provenance.MSI_MARKER).write_bytes(b"{}")
    state_root = installer_fence.state_root(paths)
    state_root.mkdir()
    for path in [base, *base.rglob("*")]:
        installer_fence.protect_state(path)
    identity = verify_payload(root, manifest, excluded=frozenset({provenance.MSI_MARKER}))
    media = base / "original.msi"
    media.write_bytes(b"original native package fixture")
    installer_fence.protect_state(media)
    old = release("3.2.120", "a")
    old["package_sha256"] = hashlib.sha256(media.read_bytes()).hexdigest()
    old["initial_runtime_tree_sha256"] = identity.tree_sha256
    package = msi_inventory.PackageInventory(old["package_sha256"], old["product_code"],
        "{" + str(uuid4()).upper() + "}", "3.2.120",
        {"EndpointAgentFeature": 1, "EndpointAgentInitialRuntimeFeature": 1}, {}, ())
    monkeypatch.setattr(msi_inventory, "read_package", lambda *_: package)
    monkeypatch.setattr(msi_inventory, "verify_installed", lambda *_: None)
    monkeypatch.setattr(msi_inventory, "NativeMsi", lambda: SimpleNamespace(product=lambda _: -1))
    evidence = provenance.CoreEvidence("msi", identity, selector, json.dumps(manifest).encode(),
                                      json.dumps({"schema_version": 1, "release": old}).encode())
    binding = staged_state.StagedUpdateBinding(str(uuid4()), old, release("3.2.122", "b"), selector, None,
                                               identity.tree_sha256, None, "3.2.122", "b" * 40, "b" * 64)
    owner = {"pid": os.getpid(), "created": 1, "hash": "d" * 64, "sid": "S-1-5-18", "elevated": True}
    with durable_state.installer_mutation_checkpoints(lambda: None):
        staged_state.begin_staged_update(paths, binding, owner)
        archive = provenance.archive_retained_core(paths, evidence, package_path=media,
            package=package, transaction_id=binding.operation_id)
        for before, after in (("preparing", "prepared"), ("prepared", "switching"), ("switching", "native-settled")):
            staged_state.advance_staged_update(paths, binding.operation_id, before, after)
    # Only this fixture's fixed version directory, after simulated native removal.
    assert root.resolve().parent == paths.versions_root.resolve() and root.name == "3.2.120"
    shutil.rmtree(root)
    return retained_storage, paths, archive, identity, binding


def promote(retained):
    storage, paths, archive, _, binding = retained
    with durable_state.installer_mutation_checkpoints(lambda: None):
        return storage.promote_retained_payload(paths, archive.name, binding.operation_id)


def test_promotion_writes_no_payload_bytes(retained, monkeypatch):
    storage, paths, archive, identity, _ = retained
    source = runtime_identity._retained_payload_root(archive)
    before = {item.path: (source / item.path).stat().st_ino for item in identity.files}
    def no_copy(*_args, **_kwargs):
        pytest.fail("promotion attempted a second payload copy")
    monkeypatch.setattr(durable_state, "durable_copy_file", no_copy)
    target = promote(retained)
    assert not source.exists()
    assert {item.path: (target / item.path).stat().st_ino for item in identity.files} == before
    assert runtime_identity.verify_retained_archive(paths, archive.name).identity == identity
    assert runtime_identity.verify_retained_runtime(paths, identity.version).identity == identity
    assert storage.retained_payload_location(paths, archive.name) == target


def test_reconciliation_uses_promotion_when_staged(retained, monkeypatch):
    _, paths, archive, identity, _ = retained
    def no_copy(*_args, **_kwargs):
        pytest.fail("staged reconciliation copied the retained runtime again")
    monkeypatch.setattr(durable_state, "durable_copy_file", no_copy)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        provenance.restore_retained_core(paths, archive.name)
    assert not (archive / "payload").exists()
    assert runtime_identity.verify_retained_runtime(paths, identity.version).identity == identity


@pytest.mark.parametrize("edge", ["before-rename", "after-rename", "source-flush", "destination-flush", "published"])
def test_promotion_retries_each_durable_edge(retained, monkeypatch, edge):
    storage, paths, archive, identity, _ = retained
    rename = durable_state.durable_rename_directory
    flush = durable_state.flush_directory
    write = durable_state.write_json_atomic
    failed = False
    renaming = False
    def trip():
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("interrupted promotion")
    def rename_once(*args, **kwargs):
        nonlocal renaming
        if edge == "before-rename": trip()
        renaming = True
        try:
            result = rename(*args, **kwargs)
        finally:
            renaming = False
        if edge == "after-rename": trip()
        return result
    def flush_once(path):
        result = flush(path)
        if renaming and edge == "source-flush" and path == archive: trip()
        if renaming and edge == "destination-flush" and path == paths.versions_root: trip()
        return result
    def write_once(path, value, **kwargs):
        if edge == "published" and path.name == "storage.json" and value["phase"] == "published": trip()
        return write(path, value, **kwargs)
    monkeypatch.setattr(durable_state, "durable_rename_directory", rename_once)
    monkeypatch.setattr(durable_state, "flush_directory", flush_once)
    monkeypatch.setattr(durable_state, "write_json_atomic", write_once)
    with pytest.raises(OSError, match="interrupted promotion"):
        promote(retained)
    target = promote(retained)
    assert not (archive / "payload").exists()
    assert runtime_identity.verify_retained_runtime(paths, identity.version).identity == identity
    assert storage.retained_payload_location(paths, archive.name) == target


def test_v1_receipt_is_unchanged(retained):
    _, _, archive, _, _ = retained
    before = (archive / "receipt.json").read_bytes()
    promote(retained)
    assert (archive / "receipt.json").read_bytes() == before
    assert json.loads(before)["schema_version"] == 1


def native_recapture(retained):
    """Simulate ordinary native reinstall of the same immutable runtime."""
    _, paths, archive, identity, _ = retained
    record = json.loads((archive / 'receipt.json').read_bytes())
    source = paths.versions_root / identity.version
    (source / provenance.RETAINED_RECEIPT).unlink(missing_ok=True)
    (source / provenance.MSI_MARKER).write_bytes(bytes.fromhex(record['original_marker_bytes']))
    (source / provenance.MSI_MARKER).touch()
    installer_fence.protect_state(source / provenance.MSI_MARKER)
    evidence = provenance.CoreEvidence('msi', identity, bytes.fromhex(record['selector_bytes']),
        bytes.fromhex(record['original_manifest_bytes']), bytes.fromhex(record['original_receipt_bytes']))
    package = msi_inventory.read_package(archive / 'package.msi', record['package']['sha256'])
    return lambda: provenance.archive_retained_core(paths, evidence, package_path=paths.install_root.parent / 'original.msi',
        package=package, transaction_id=str(uuid4()))


@pytest.mark.parametrize('broken_dual_location', [False, True])
def test_native_reinstall_recaptures_published_archive_without_rewriting_history(retained, broken_dual_location):
    storage, paths, archive, identity, binding = retained
    target = promote(retained)
    recapture = native_recapture(retained)
    before = (archive / 'receipt.json').read_bytes()
    if broken_dual_location:
        (archive / 'payload').mkdir()
        installer_fence.protect_state(archive / 'payload')
    with durable_state.installer_mutation_checkpoints(lambda: None):
        recapture()
    value = json.loads((archive / 'storage.json').read_bytes())
    assert value['phase'] == 'published'
    assert value['legacy_materialization'] == 'complete'
    assert value['operation_id'] == binding.operation_id
    assert (archive / 'receipt.json').read_bytes() == before
    assert target.is_dir()
    assert storage.retained_payload_location(paths, archive.name) == runtime_identity._retained_payload_root(archive)
    assert runtime_identity.verify_retained_archive(paths, archive.name).identity == identity


@pytest.mark.parametrize('edge', ['copying', 'first-copy', 'complete-before', 'complete-after'])
def test_native_recapture_resumes_after_each_durable_edge(retained, monkeypatch, edge):
    _, paths, archive, identity, _ = retained
    promote(retained)
    recapture = native_recapture(retained)
    write, copy = durable_state.write_json_atomic, durable_state.durable_copy_file
    failed = False
    def trip():
        nonlocal failed
        if not failed:
            failed = True
            raise OSError('interrupted native recapture')
    def write_once(path, value, **kwargs):
        journal = path.name == 'storage.json'
        if journal and edge == 'complete-before' and value['legacy_materialization'] == 'complete':
            trip()
        result = write(path, value, **kwargs)
        if journal and ((edge == 'copying' and value['legacy_materialization'] == 'copying')
                        or (edge == 'complete-after' and value['legacy_materialization'] == 'complete')):
            trip()
        return result
    def copy_once(source, destination, **kwargs):
        result = copy(source, destination, **kwargs)
        if edge == 'first-copy' and destination.name == 'pc_agent.exe':
            trip()
        return result
    monkeypatch.setattr(durable_state, 'write_json_atomic', write_once)
    monkeypatch.setattr(durable_state, 'durable_copy_file', copy_once)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        with pytest.raises(OSError, match='interrupted native recapture'):
            recapture()
        recapture()
    assert runtime_identity.verify_retained_archive(paths, archive.name).identity == identity
    assert json.loads((archive / 'storage.json').read_bytes())['legacy_materialization'] == 'complete'


def test_native_recapture_preserves_foreign_partial_payload(retained):
    _, _, archive, _, _ = retained
    promote(retained)
    recapture = native_recapture(retained)
    residue = archive / 'payload'
    residue.mkdir()
    foreign = residue / 'foreign-evidence'
    foreign.write_bytes(b'keep')
    installer_fence.protect_state(residue)
    installer_fence.protect_state(foreign)
    with durable_state.installer_mutation_checkpoints(lambda: None), pytest.raises(ValueError):
        recapture()
    assert foreign.read_bytes() == b'keep'


@pytest.mark.parametrize('fault', ['missing-member', 'wrong-native', 'no-authority'])
def test_recapture_rejects_changed_complete_archive_and_missing_native_authority(retained, monkeypatch, fault):
    _, _, archive, _, _ = retained
    promote(retained)
    recapture = native_recapture(retained)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        recapture()
    original = (archive / 'storage.json').read_bytes()
    if fault == 'missing-member':
        (runtime_identity._retained_payload_root(archive) / 'pc_agent.exe').unlink()
    elif fault == 'wrong-native':
        def wrong(*_): raise ValueError('native owner differs')
        monkeypatch.setattr(msi_inventory, 'verify_installed', wrong)
    if fault == 'no-authority':
        with pytest.raises(ValueError): recapture()
    else:
        with durable_state.installer_mutation_checkpoints(lambda: None), pytest.raises(ValueError): recapture()
    assert (archive / 'storage.json').read_bytes() == original


def test_recaptured_native_archive_can_be_republished_by_later_exact_operation(retained):
    storage, paths, archive, identity, binding = retained
    target = promote(retained)
    recapture = native_recapture(retained)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        recapture()
        staged_state.advance_staged_update(paths, binding.operation_id, 'native-settled', 'rolling-back')
        staged_state.advance_staged_update(paths, binding.operation_id, 'rolling-back', 'rolled-back')
        next_binding = staged_state.StagedUpdateBinding(str(uuid4()), binding.old_release, release('3.2.124', 'c'),
            binding.selected_before, None, identity.tree_sha256, None, '3.2.124', 'c' * 40, 'c' * 64)
        owner = {'pid': os.getpid(), 'created': 1, 'hash': 'd' * 64, 'sid': 'S-1-5-18', 'elevated': True}
        staged_state.begin_staged_update(paths, next_binding, owner)
        for before, after in [('preparing', 'prepared'), ('prepared', 'switching'), ('switching', 'native-settled')]:
            staged_state.advance_staged_update(paths, next_binding.operation_id, before, after)
        assert target.resolve().parent == paths.versions_root.resolve() and target.name == identity.version
        shutil.rmtree(target)
        storage.promote_retained_payload(paths, archive.name, next_binding.operation_id)
    assert runtime_identity.verify_retained_runtime(paths, identity.version).identity == identity
    history = json.loads((archive / 'storage-history' / (binding.operation_id + '.json')).read_bytes())
    assert history['operation_id'] == binding.operation_id and history['legacy_materialization'] == 'complete'


def test_conflicting_destination_is_not_removed(retained):
    _, paths, archive, identity, _ = retained
    target = paths.versions_root / identity.version
    target.mkdir()
    (target / "unrelated").write_bytes(b"preserve this evidence")
    for path in [target, target / "unrelated"]:
        installer_fence.protect_state(path)
    with pytest.raises(ValueError): promote(retained)
    assert (target / "unrelated").read_bytes() == b"preserve this evidence"
    assert (archive / "payload").is_dir()


def test_legacy_materialization_runs_only_during_rollback(retained):
    storage, paths, archive, identity, binding = retained
    target = promote(retained)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        with pytest.raises(ValueError):
            storage.materialize_legacy_retention(paths, archive.name, binding.operation_id)
        assert not (archive / "payload").exists()
        staged_state.advance_staged_update(paths, binding.operation_id, "native-settled", "rolling-back")
        storage.materialize_legacy_retention(paths, archive.name, binding.operation_id)
    assert target.is_dir()
    assert verify_payload(runtime_identity._retained_payload_root(archive),
                          json.loads((archive / "receipt.json").read_bytes())["manifest"]) == identity
    assert runtime_identity.verify_retained_archive(paths, archive.name).identity == identity


def test_live_native_owner_and_wrong_operation_cannot_promote(retained, monkeypatch):
    storage, paths, archive, _, _ = retained
    with durable_state.installer_mutation_checkpoints(lambda: None), pytest.raises(ValueError):
        storage.promote_retained_payload(paths, archive.name, str(uuid4()))
    monkeypatch.setattr(msi_inventory, "NativeMsi", lambda: SimpleNamespace(product=lambda _: 5))
    with pytest.raises(ValueError): promote(retained)
    assert (archive / "payload").exists()


@pytest.mark.skipif(os.name != "nt", reason="actual NTFS parent deletion authority")
def test_untrusted_destination_parent_is_refused_before_rename(retained):
    import win32security
    _, paths, archive, _, _ = retained
    descriptor = win32security.GetNamedSecurityInfo(str(paths.versions_root), win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION)
    acl = descriptor.GetSecurityDescriptorDacl()
    acl.AddAccessAllowedAceEx(win32security.ACL_REVISION, 0, 0x40,
                             win32security.ConvertStringSidToSid("S-1-5-32-545"))
    win32security.SetNamedSecurityInfo(str(paths.versions_root), win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, acl, None)
    with pytest.raises(ValueError): promote(retained)
    assert (archive / "payload").is_dir()
    assert not (paths.versions_root / "3.2.120").exists()


def test_promotion_retains_existing_hardlink_and_reparse_rejections(retained):
    _, paths, archive, _, _ = retained
    source = runtime_identity._retained_payload_root(archive)
    external = archive / 'hardlink'
    os.link(source / 'pc_agent.exe', external)
    with pytest.raises(ValueError): promote(retained)
    assert source.is_dir()
    external.unlink()
    outside = archive / 'outside'
    outside.mkdir()
    link = source / 'linked-directory'
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError): promote(retained)
    assert source.is_dir()
    assert not (paths.versions_root / '3.2.120').exists()


@pytest.mark.skipif(os.name != 'nt', reason='Windows volume metadata')
def test_non_ntfs_is_rejected_before_payload_movement(retained, monkeypatch):
    import win32api
    _, paths, archive, _, _ = retained
    metadata = win32api.GetVolumeInformation(str(paths.install_root.drive) + '\\')
    monkeypatch.setattr(win32api, 'GetVolumeInformation', lambda _: (*metadata[:4], 'FAT32'))
    with pytest.raises(ValueError, match='NTFS'): promote(retained)
    assert (archive / 'payload').is_dir()
    assert not (archive / 'storage.json').exists()
