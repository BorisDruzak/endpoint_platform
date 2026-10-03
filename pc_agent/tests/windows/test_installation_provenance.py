"""Full payload identity is checked before an installer may assume ownership."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import zipfile

import pytest


def payload(root: Path, *, version="3.2.82", minimum="3.2.82", source="a" * 40):
    root.mkdir(parents=True, exist_ok=True)
    contract = {"schema_version": 1, "version": version, "source_revision": source,
        "minimum_launcher_version": minimum}
    (root / "pc_agent.exe").write_bytes(b"immutable compiled core")
    (root / "endpoint-runtime-contract.json").write_text(json.dumps(contract), encoding="utf-8")
    manifest = {"schema_version": 1, "version": version, "source_revision": source,
        "files": [{"path": file.name, "size": file.stat().st_size,
            "sha256": hashlib.sha256(file.read_bytes()).hexdigest()}
            for file in sorted(root.iterdir())]}
    return manifest


def test_inventory_binds_every_file_and_compatibility(tmp_path):
    from endpoint_contracts.runtime_payload import verify_payload
    manifest = payload(tmp_path)
    inventory = verify_payload(tmp_path, manifest)
    assert inventory.version == "3.2.82"
    assert inventory.source_revision == "a" * 40
    assert inventory.minimum_launcher_version == "3.2.82"
    assert inventory.file_count == 2
    assert len(inventory.tree_sha256) == 64


@pytest.mark.parametrize("defect", ["extra", "missing", "size", "hash", "source", "version", "count", "case_alias", "ads", "floor"])
def test_full_inventory_conflict_never_rewrites_evidence(tmp_path, defect):
    from endpoint_contracts.runtime_payload import PayloadConflict, verify_payload
    manifest = payload(tmp_path)
    if defect == "extra":
        (tmp_path / "unknown").write_bytes(b"evidence")
    elif defect == "missing":
        (tmp_path / "pc_agent.exe").unlink()
    elif defect == "size":
        manifest["files"][1]["size"] += 1
    elif defect == "hash":
        manifest["files"][1]["sha256"] = "b" * 64
    elif defect in {"source", "version"}:
        manifest["source_revision" if defect == "source" else "version"] = "b" * 40 if defect == "source" else "3.2.83"
    elif defect == "count":
        manifest["files"].pop()
    elif defect == "case_alias":
        manifest["files"].append({**manifest["files"][1], "path": "PC_AGENT.EXE"})
    elif defect == "ads":
        manifest["files"][1]["path"] = "pc_agent.exe:stream"
    else:
        manifest["files"][0]["sha256"] = "0" * 64
        (tmp_path / "endpoint-runtime-contract.json").write_text('{"minimum_launcher_version":null}', encoding="utf-8")
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    with pytest.raises(PayloadConflict, match="PROVENANCE_CONFLICT"):
        verify_payload(tmp_path, manifest)
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


def test_metadata_absence_is_not_nullable_floor(tmp_path):
    from endpoint_contracts.runtime_payload import PayloadConflict, verify_payload
    manifest = payload(tmp_path, version="3.2.83", minimum="3.2.81")
    (tmp_path / "endpoint-runtime-contract.json").unlink()
    manifest["files"] = [item for item in manifest["files"] if item["path"] == "pc_agent.exe"]
    with pytest.raises(PayloadConflict):
        verify_payload(tmp_path, manifest)


def test_zip_registration_floor_is_bound_to_same_archive_bytes(tmp_path):
    from endpoint_contracts.runtime_payload import PayloadConflict, verify_windows_archive
    root = tmp_path / "payload"
    manifest = payload(root, version="3.2.83", minimum="3.2.81")
    archive = tmp_path / "core.zip"
    with zipfile.ZipFile(archive, "w") as target:
        for item in root.iterdir():
            target.write(item, item.name)
        target.writestr("endpoint-update-manifest.json", json.dumps(manifest))
    options = dict(sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        size=archive.stat().st_size, version="3.2.83", minimum_launcher_version="3.2.81")
    assert verify_windows_archive(archive, **options).minimum_launcher_version == "3.2.81"
    with pytest.raises(PayloadConflict):
        verify_windows_archive(archive, **{**options, "minimum_launcher_version": "3.2.82"})
    with pytest.raises(PayloadConflict):
        verify_windows_archive(archive, **{**options, "minimum_launcher_version": None})


def zip_core(paths, *, version='3.2.83', minimum='3.2.81'):
    root = paths.versions_root / version
    manifest = payload(root, version=version, minimum=minimum)
    (root / 'endpoint-update-manifest.json').write_text(json.dumps(manifest))
    (root / '.endpoint-update.json').write_text(json.dumps({'version': version, 'sha256': 'b'*64, 'size': 1234}))
    paths.current_path.write_text(json.dumps({'schema_version': 1, 'version': version, 'source_revision': 'a'*40}))
    return root


@pytest.mark.parametrize('defect', ['source', 'receipt', 'floor', 'extra', 'missing'])
def test_pre_msi_core_inspection_rejects_conflict_without_writes(tmp_path, monkeypatch, defect):
    from pc_agent.platform.windows import installation_provenance as module
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path / 'Agent', tmp_path / 'data/updates/pending_update.json')
    root = zip_core(paths, minimum='3.2.83' if defect == 'floor' else '3.2.81')
    monkeypatch.setattr(module, '_assert_security', lambda *_: None)
    if defect == 'source': paths.current_path.write_text(json.dumps({'schema_version':1,'version':'3.2.83','source_revision':'c'*40}))
    elif defect == 'receipt': (root / '.endpoint-update.json').write_text(json.dumps({'version':'3.2.82','sha256':'b'*64,'size':1234}))
    elif defect == 'extra': (root / 'unknown.bin').write_bytes(b'evidence')
    elif defect == 'missing': (root / 'pc_agent.exe').unlink()
    before = {str(path): path.read_bytes() for path in tmp_path.rglob('*') if path.is_file()}
    with pytest.raises(module.ProvenanceConflict, match='PROVENANCE_CONFLICT'):
        module.inspect_installed_core(paths, resulting_foundation='3.2.82')
    assert before == {str(path): path.read_bytes() for path in tmp_path.rglob('*') if path.is_file()}


def test_pre_msi_inspection_preserves_compatible_newer_zip_identity(tmp_path, monkeypatch):
    from pc_agent.platform.windows import installation_provenance as module
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path / 'Agent', tmp_path / 'data/updates/pending_update.json')
    zip_core(paths)
    monkeypatch.setattr(module, '_assert_security', lambda *_: None)
    first = module.inspect_installed_core(paths, resulting_foundation='3.2.82')
    assert first.current.origin == 'zip'
    assert first.current.identity.version == '3.2.83'
    assert first.previous is None
    assert first == module.inspect_installed_core(paths, resulting_foundation='3.2.82')


@pytest.fixture
def msi_archive_input(tmp_path, monkeypatch):
    from dataclasses import replace
    from pc_agent.platform.windows import installation_provenance as module, installer_fence as fence, msi_inventory
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path / 'Agent', tmp_path / 'data/updates/pending_update.json')
    root = zip_core(paths, version='3.2.82', minimum='3.2.82')
    monkeypatch.setattr(module, '_assert_security', lambda *_: None)
    monkeypatch.setattr(fence, 'assert_state_security', lambda *_a, **_kw: None)
    monkeypatch.setattr(fence, 'protect_state', lambda *_a, **_kw: None)
    evidence = replace(module.inspect_installed_core(paths, resulting_foundation='3.2.82').current, origin='msi')
    (root / '.endpoint-update.json').unlink()
    (root / '.endpoint-msi-runtime.json').write_text('{}')
    fence.state_root(paths).mkdir()
    package_path = tmp_path / 'source.msi'; package_path.write_bytes(b'exact original package')
    package = msi_inventory.PackageInventory(hashlib.sha256(package_path.read_bytes()).hexdigest(),
        '{11111111-1111-4111-8111-111111111111}', '{22222222-2222-4222-8222-222222222222}',
        '3.2.82', {'EndpointAgentFeature':1, 'EndpointAgentInitialRuntimeFeature':1}, {}, ())
    monkeypatch.setattr(msi_inventory, 'read_package', lambda *_: package)
    monkeypatch.setattr(msi_inventory, 'verify_installed', lambda *_: None)
    return module, paths, root, evidence, package_path, package


def test_retained_archive_publishes_receipt_only_after_complete_exact_copy(msi_archive_input):
    module, paths, root, evidence, package_path, package = msi_archive_input
    archive = module.archive_retained_core(paths, evidence, package_path=package_path,
        package=package, transaction_id='11111111-1111-4111-8111-111111111111')
    record = json.loads((archive / 'receipt.json').read_text())
    assert record['origin'] == 'retained_msi'
    assert record['package']['sha256'] == package.sha256
    assert (archive / 'package.msi').read_bytes() == package_path.read_bytes()
    assert (archive / 'payload/pc_agent.exe').read_bytes() == (root / 'pc_agent.exe').read_bytes()
    assert not (archive / 'payload/.endpoint-msi-runtime.json').exists()
    assert module.archive_retained_core(paths, evidence, package_path=package_path,
        package=package, transaction_id='11111111-1111-4111-8111-111111111111') == archive


def test_retained_copy_interruption_keeps_live_core_and_has_no_completed_receipt(msi_archive_input, monkeypatch):
    from pc_agent.platform.windows import durable_state
    module, paths, root, evidence, package_path, package = msi_archive_input
    before = {p.name:p.read_bytes() for p in root.iterdir()}
    original = durable_state.durable_copy_file
    count = 0
    def interrupted(*args, **kwargs):
        nonlocal count
        count += 1
        if count == 2: raise OSError('allocation interrupted')
        return original(*args, **kwargs)
    monkeypatch.setattr(durable_state, 'durable_copy_file', interrupted)
    with pytest.raises(OSError, match='allocation interrupted'):
        module.archive_retained_core(paths, evidence, package_path=package_path,
            package=package, transaction_id='11111111-1111-4111-8111-111111111111')
    assert not list(paths.install_root.parent.glob('installer-state/retained/*/receipt.json'))
    assert before == {p.name:p.read_bytes() for p in root.iterdir()}


def test_rehydrate_retained_core_after_owner_removal_without_live_msi_claim(msi_archive_input, monkeypatch):
    from pc_agent.platform.windows import msi_inventory, runtime_identity
    from types import SimpleNamespace
    module, paths, root, evidence, package_path, package = msi_archive_input
    archive = module.archive_retained_core(paths, evidence, package_path=package_path,
        package=package, transaction_id='11111111-1111-4111-8111-111111111111')
    monkeypatch.setattr(msi_inventory, 'NativeMsi', lambda: SimpleNamespace(product=lambda _code:-1))
    for path in root.iterdir(): path.unlink()
    module.restore_retained_core(paths, archive.name)
    retained = runtime_identity.verify_retained_runtime(paths, '3.2.82')
    assert retained.identity == evidence.identity
    assert not (root / '.endpoint-msi-runtime.json').exists()
    assert not (root / '.endpoint-update.json').exists()
    assert (root / '.endpoint-retained-msi.json').exists()
    assert not (archive / 'rehydration.json').exists()


def test_rehydrate_requires_absent_native_owner_and_preserves_unknown_bytes(msi_archive_input, monkeypatch):
    from pc_agent.platform.windows import msi_inventory
    from types import SimpleNamespace
    module, paths, root, evidence, package_path, package = msi_archive_input
    archive = module.archive_retained_core(paths, evidence, package_path=package_path,
        package=package, transaction_id='11111111-1111-4111-8111-111111111111')
    monkeypatch.setattr(msi_inventory, 'NativeMsi', lambda: SimpleNamespace(product=lambda _code:5))
    with pytest.raises(module.ProvenanceConflict): module.restore_retained_core(paths, archive.name)
    monkeypatch.setattr(msi_inventory, 'NativeMsi', lambda: SimpleNamespace(product=lambda _code:-1))
    extra = root / 'unknown'; extra.write_bytes(b'forensic evidence')
    with pytest.raises(module.ProvenanceConflict): module.restore_retained_core(paths, archive.name)
    assert extra.read_bytes() == b'forensic evidence'


def test_rehydrate_copy_failure_resumes_from_same_archive_and_selector(msi_archive_input, monkeypatch):
    from pc_agent.platform.windows import msi_inventory, durable_state, runtime_identity
    from types import SimpleNamespace
    module, paths, root, evidence, package_path, package = msi_archive_input
    archive = module.archive_retained_core(paths, evidence, package_path=package_path,
        package=package, transaction_id='11111111-1111-4111-8111-111111111111')
    monkeypatch.setattr(msi_inventory, 'NativeMsi', lambda: SimpleNamespace(product=lambda _code:-1))
    selector = paths.current_path.read_bytes()
    for path in root.iterdir(): path.unlink()
    original = durable_state.durable_copy_file
    calls = 0
    def interrupted(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2: raise OSError('copy interrupted')
        return original(*args, **kwargs)
    monkeypatch.setattr(durable_state, 'durable_copy_file', interrupted)
    with pytest.raises(OSError, match='copy interrupted'): module.restore_retained_core(paths, archive.name)
    assert (archive / 'rehydration.json').exists()
    assert not (root / '.endpoint-retained-msi.json').exists()
    assert paths.current_path.read_bytes() == selector
    monkeypatch.setattr(durable_state, 'durable_copy_file', original)
    module.restore_retained_core(paths, archive.name)
    assert runtime_identity.verify_retained_runtime(paths, '3.2.82').identity == evidence.identity
    assert paths.current_path.read_bytes() == selector


def test_declared_nullable_floor_is_distinct_from_missing_metadata(tmp_path):
    from endpoint_contracts.runtime_payload import verify_payload
    manifest = payload(tmp_path, version='3.2.90', minimum=None)
    assert verify_payload(tmp_path, manifest).minimum_launcher_version is None


def test_legacy_absence_requires_exact_reviewed_package_source_and_tree(tmp_path, monkeypatch):
    from pc_agent.platform.windows import runtime_identity
    source = 'a'*40
    (tmp_path / 'pc_agent.exe').write_bytes(b'immutable legacy core')
    digest = hashlib.sha256((tmp_path / 'pc_agent.exe').read_bytes()).hexdigest()
    tree = hashlib.sha256(f'endpoint_agent_core.exe\0{len(b"immutable legacy core")}\0{digest}\n'.encode()).hexdigest()
    monkeypatch.setattr(runtime_identity, '_LEGACY_MSI_CONTRACTS', {'b'*64: {
        'version':'3.2.81', 'source_revision':source, 'file_count':1, 'tree_sha256':tree,
        'component_guid':'D9917B58-851E-4230-B1AD-1B0F9D3719D7', 'approved_foundations':('3.2.82',)}})
    identity = runtime_identity.verify_legacy_msi_payload(tmp_path, package_sha256='b'*64)
    assert identity.source_revision == source
    with pytest.raises(ValueError): runtime_identity.verify_legacy_msi_payload(tmp_path, package_sha256='c'*64)
    (tmp_path / 'pc_agent.exe').write_bytes(b'changed legacy core')
    with pytest.raises(ValueError): runtime_identity.verify_legacy_msi_payload(tmp_path, package_sha256='b'*64)


def test_reviewed_legacy_native_owner_survives_as_explicit_retained_archive(msi_archive_input, monkeypatch):
    from dataclasses import replace
    from types import SimpleNamespace
    from pc_agent.platform.windows import msi_inventory, runtime_identity
    module, paths, _root, _evidence, original_package, package = msi_archive_input
    package = replace(package, version='3.2.81')
    core = paths.versions_root / '3.2.81'; core.mkdir()
    data = b'immutable legacy core'
    (core / 'pc_agent.exe').write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    tree = hashlib.sha256(f'endpoint_agent_core.exe\0{len(data)}\0{sha}\n'.encode()).hexdigest()
    component = 'D9917B58-851E-4230-B1AD-1B0F9D3719D7'
    (core / '.endpoint-msi-runtime.json').write_text(json.dumps({'schema_version':1,'version':'3.2.81','component_guid':component}))
    contract = {'version':'3.2.81','source_revision':'a'*40,'file_count':1,'tree_sha256':tree,
        'component_guid':component,'approved_foundations':('3.2.82',)}
    monkeypatch.setattr(runtime_identity, '_LEGACY_MSI_CONTRACTS', {package.sha256:contract})
    monkeypatch.setattr(msi_inventory, 'read_package', lambda *_: package)
    cache = paths.updates_root.parent / 'installer-cache'; cache.mkdir(parents=True)
    cached = cache / f'msi-{package.sha256}' / 'EndpointAgent.msi'; cached.parent.mkdir()
    cached.write_bytes(original_package.read_bytes())
    (cache / 'installer-provenance.json').write_text(json.dumps({
        'schema_version':'endpoint_windows_installer_provenance_v1','release_manifest_schema_version':'endpoint_windows_release_v1',
        'cache_file':f'msi-{package.sha256}/EndpointAgent.msi','package_sha256':package.sha256,
        'product_code':package.product_code,'version':'3.2.81','source_revision':'a'*40,'initial_runtime_tree_sha256':tree}))
    paths.current_path.write_text(json.dumps({'version':'3.2.81'}))
    captured = module.inspect_installed_core(paths, resulting_foundation='3.2.82').current
    assert captured.origin == 'msi'
    assert captured.compatibility_foundations == ('3.2.82',)
    from pc_agent.platform.windows import service_launcher
    monkeypatch.setattr(service_launcher,'AGENT_VERSION','3.2.82')
    assert service_launcher.build_agent_child_command(paths)[0]==str(core/'pc_agent.exe')
    with pytest.raises(module.ProvenanceConflict): module.inspect_installed_core(paths, resulting_foundation='3.2.83')
    archive = module.archive_retained_core(paths, captured, package_path=cached, package=package,
        transaction_id='11111111-1111-4111-8111-111111111111')
    monkeypatch.setattr(msi_inventory, 'NativeMsi', lambda: SimpleNamespace(product=lambda _code:-1))
    for path in core.iterdir(): path.unlink()
    module.restore_retained_core(paths, archive.name)
    result = module.inspect_installed_core(paths, resulting_foundation='3.2.82').current
    assert result.origin == 'retained_msi'
    assert result.identity == captured.identity


@pytest.fixture
def handoff_input(tmp_path, monkeypatch):
    from pc_agent.platform.windows import installation_provenance as module, installer_fence as fence, msi_inventory
    from pc_agent.platform.windows import installer_transaction_bridge as bridge
    from pc_agent.tests.windows.test_installer_service_quarantine import Services
    service_class=bridge.InstallerServices
    monkeypatch.setattr(bridge,'InstallerServices',lambda paths,**kw:service_class(paths,api=Services(paths.install_root),flush=lambda _:None,**kw))
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    from endpoint_contracts.runtime_payload import verify_payload
    paths = WindowsUpdatePaths(tmp_path / 'Agent', tmp_path / 'data/updates/pending_update.json')
    root = zip_core(paths, version='3.2.82', minimum='3.2.82')
    manifest = json.loads((root / 'endpoint-update-manifest.json').read_text())
    identity = verify_payload(root, manifest, excluded=frozenset({'.endpoint-update.json','endpoint-update-manifest.json'}))
    monkeypatch.setattr(module, '_assert_security', lambda *_: None)
    monkeypatch.setattr(fence, 'assert_state_security', lambda *_a, **_kw: None)
    monkeypatch.setattr(fence, 'protect_state', lambda *_a, **_kw: None)
    fence.state_root(paths).mkdir()
    package_path=tmp_path/'candidate.msi'; package_path.write_bytes(b'canonical package model')
    component=msi_inventory.Component('core','{33333333-3333-4333-8333-333333333333}', 'INITIALRUNTIMEDIR','corefile',('EndpointAgentInitialRuntimeFeature',))
    package=msi_inventory.PackageInventory(hashlib.sha256(package_path.read_bytes()).hexdigest(),
        '{11111111-1111-4111-8111-111111111111}','{22222222-2222-4222-8222-222222222222}',
        '3.2.82',{'EndpointAgentFeature':1,'EndpointAgentInitialRuntimeFeature':1},{'core':component},
        (msi_inventory.InstalledFile('corefile','core','versions/3.2.82/pc_agent.exe',(root/'pc_agent.exe').stat().st_size),))
    foundation=[]
    for name,(file_id,component_id) in msi_inventory.FOUNDATION_EXECUTABLES.items():
        (paths.install_root/name).write_bytes(b'payload')
        foundation.append({'path':name,'file':file_id,'component':component_id,'size':7,'sha256':hashlib.sha256(b'payload').hexdigest()})
    expected=msi_inventory.ExpectedMsi(package,identity,manifest,(root/'endpoint-runtime-contract.json').read_bytes(),tuple(foundation))
    monkeypatch.setattr(msi_inventory,'read_expected_package',lambda *_:expected)
    monkeypatch.setattr(msi_inventory,'verify_installed',lambda *_:None)
    def foundation_verified(_package,install_root,*,expected):
        with msi_inventory.verified_foundation_bytes(expected,install_root): pass
        return 'complete'
    monkeypatch.setattr(msi_inventory,'verify_foundation',foundation_verified)
    release={'schema_version':'endpoint_windows_release_v1','version':'3.2.82','source_revision':'a'*40,
        'package_sha256':package.sha256,'product_code':package.product_code,'initial_runtime_tree_sha256':'c'*64}
    request={'package_path':package_path,'release':release,'transaction_id':'11111111-1111-4111-8111-111111111111',
        'selected':module.inspect_installed_core(paths,resulting_foundation='3.2.82').current.digest,'previous':None}
    return module,paths,root,request,expected


def test_same_canonical_msi_handoff_archives_zip_evidence_automatically(handoff_input):
    module,paths,root,request,expected=handoff_input
    original_receipt=(root/'.endpoint-update.json').read_bytes()
    assert module.prepare_installer_provenance(paths,request)=='handoff'
    (root/'.endpoint-msi-runtime.json').write_text(json.dumps({'schema_version':1,'version':'3.2.82',
        'component_guid':'33333333-3333-4333-8333-333333333333'}))
    assert module.reconcile_installed_core(paths,request)=='handoff'
    assert not (root/'.endpoint-update.json').exists()
    archived=list((paths.install_root.parent/'installer-state/provenance').glob('*/handoff-receipt.json'))
    assert len(archived)==1 and archived[0].read_bytes()==original_receipt
    assert module.inspect_installed_core(paths,resulting_foundation='3.2.82').current.origin=='msi'
    assert module.reconcile_installed_core(paths,request)=='handoff'


def test_same_version_changed_payload_conflicts_before_preparation(handoff_input):
    module,paths,root,request,expected=handoff_input
    (root/'pc_agent.exe').write_bytes(b'conflicting same-version core')
    with pytest.raises(module.ProvenanceConflict): module.prepare_installer_provenance(paths,request)
    assert not (paths.install_root.parent/'installer-state/provenance').exists()
    assert (root/'.endpoint-update.json').exists()


@pytest.mark.parametrize('origin',['retained_msi','msi'])
def test_equal_payload_does_not_transfer_other_msi_ownership(handoff_input,monkeypatch,origin):
    from dataclasses import replace
    module,paths,root,request,expected=handoff_input
    old=module.inspect_installed_core(paths,resulting_foundation='3.2.82').current
    other_release={**request['release'],'package_sha256':'b'*64}
    evidence=replace(old,origin=origin,receipt_bytes=json.dumps({'schema_version':1,'release':other_release}).encode())
    monkeypatch.setattr(module,'inspect_installed_core',lambda *_a,**_kw:module.CoreInspection(evidence,None))
    request['selected']=evidence.digest
    with pytest.raises(module.ProvenanceConflict): module.prepare_installer_provenance(paths,request)
    assert not (paths.install_root.parent/'installer-state/packages').exists()


def test_incoming_and_retention_disk_costs_are_admitted_together_before_copy(handoff_input,monkeypatch):
    from dataclasses import replace
    from pc_agent.platform.windows import disk_readiness,msi_inventory,durable_state
    module,paths,root,request,expected=handoff_input
    zip_core(paths,version='3.2.83',minimum='3.2.81')
    evidence=module.inspect_installed_core(paths,resulting_foundation='3.2.82').current
    old_release={**request['release'],'version':'3.2.83','package_sha256':'b'*64}
    evidence=replace(evidence,origin='msi',receipt_bytes=json.dumps({'schema_version':1,'release':old_release}).encode())
    monkeypatch.setattr(module,'inspect_installed_core',lambda *_a,**_kw:module.CoreInspection(evidence,None))
    request['selected']=evidence.digest
    old_path=paths.install_root.parent/'installer-state/packages'/('b'*64)/'EndpointAgent.msi'
    old_path.parent.mkdir(parents=True);old_path.write_bytes(b'old complete media')
    old_package=replace(expected.package,version='3.2.83',sha256='b'*64,product_code='{44444444-4444-4444-8444-444444444444}')
    monkeypatch.setattr(msi_inventory,'read_package',lambda *_:old_package)
    observed=[]
    def insufficient(allocations):
        observed.extend(allocations)
        raise disk_readiness.DiskInsufficient()
    monkeypatch.setattr(disk_readiness,'require_allocation_space',insufficient)
    monkeypatch.setattr(durable_state,'durable_copy_file',lambda *_a,**_kw:pytest.fail('copy before aggregate admission'))
    with pytest.raises(disk_readiness.DiskInsufficient): module.prepare_installer_provenance(paths,request)
    retained=module.retention_allocations(paths,evidence,old_path.stat().st_size)
    assert observed[1:]==list(retained)
    assert observed[0][1]>=2*request['package_path'].stat().st_size+module.MAX_MANIFEST_BYTES
    assert not (paths.install_root.parent/'installer-state/retained').exists()


@pytest.mark.parametrize('boundary', ['receipt_unlinked', 'owner_published', 'foundation_published'])
def test_handoff_resumes_after_each_ownership_publication_boundary(handoff_input, monkeypatch, boundary):
    from pc_agent.platform.windows import durable_state
    module,paths,root,request,expected=handoff_input
    receipt=(root/'.endpoint-update.json').read_bytes()
    module.prepare_installer_provenance(paths,request)
    (root/'.endpoint-msi-runtime.json').write_text(json.dumps({'schema_version':1,'version':'3.2.82',
        'component_guid':'33333333-3333-4333-8333-333333333333'}))
    original_unlink=durable_state.durable_unlink
    original_write=durable_state.write_json_atomic
    def unlink(path, **kwargs):
        original_unlink(path, **kwargs)
        if boundary=='receipt_unlinked' and path.name=='.endpoint-update.json':
            raise OSError('interrupted after durable boundary')
    def write(path, *args, **kwargs):
        original_write(path, *args, **kwargs)
        if ((boundary=='owner_published' and path.parent.name=='core-owners')
            or (boundary=='foundation_published' and path.name=='foundation.json')):
            raise OSError('interrupted after durable boundary')
    monkeypatch.setattr(durable_state,'durable_unlink',unlink)
    monkeypatch.setattr(durable_state,'write_json_atomic',write)
    with pytest.raises(OSError,match='interrupted after durable boundary'):
        module.reconcile_installed_core(paths,request)
    archive=paths.install_root.parent/'installer-state/provenance'/request['transaction_id']
    assert (archive/'handoff-receipt.json').read_bytes()==receipt
    monkeypatch.setattr(durable_state,'durable_unlink',original_unlink)
    monkeypatch.setattr(durable_state,'write_json_atomic',original_write)
    assert module.reconcile_installed_core(paths,request)=='handoff'
    assert module.inspect_installed_core(paths,resulting_foundation='3.2.82').current.origin=='msi'


def test_newer_compatible_zip_and_previous_are_preserved_during_foundation_repair(handoff_input):
    module,paths,root,request,expected=handoff_input
    newer=zip_core(paths,version='3.2.83',minimum='3.2.81')
    paths.previous_path.write_bytes(json.dumps({'schema_version':1,'version':'3.2.82','source_revision':'a'*40}).encode())
    inspection=module.inspect_installed_core(paths,resulting_foundation='3.2.82')
    request.update(selected=inspection.current.digest,previous=inspection.previous.digest)
    current_before=paths.current_path.read_bytes()
    previous_before=paths.previous_path.read_bytes()
    assert module.prepare_installer_provenance(paths,request)=='preserved'
    (root/'.endpoint-msi-runtime.json').write_text(json.dumps({'schema_version':1,'version':'3.2.82',
        'component_guid':'33333333-3333-4333-8333-333333333333'}))
    assert module.reconcile_installed_core(paths,request)=='preserved'
    assert paths.current_path.read_bytes()==current_before
    assert paths.previous_path.read_bytes()==previous_before
    assert (newer/'.endpoint-update.json').exists()


def test_recovery_accepts_only_inventoried_partial_candidate_and_saved_selectors(handoff_input):
    module,paths,root,request,expected=handoff_input
    module.prepare_installer_provenance(paths,request)
    (root/'pc_agent.exe').unlink()
    module.validate_interrupted_reconciliation(paths,request)
    (root/'unrelated.txt').write_bytes(b'unknown evidence')
    with pytest.raises(module.ProvenanceConflict): module.validate_interrupted_reconciliation(paths,request)
    assert (root/'unrelated.txt').read_bytes()==b'unknown evidence'


def test_retirement_requires_independent_current_and_previous_zip_cores(handoff_input,monkeypatch):
    from pc_agent.platform.windows import update_transaction
    monkeypatch.setattr(update_transaction,'_assert_state_security',lambda _:None)
    module,paths,root,request,expected=handoff_input
    module.prepare_installer_provenance(paths,request)
    (root/'.endpoint-msi-runtime.json').write_text(json.dumps({'schema_version':1,'version':'3.2.82',
        'component_guid':'33333333-3333-4333-8333-333333333333'}))
    module.reconcile_installed_core(paths,request)
    zip_core(paths,version='3.2.84',minimum='3.2.82')
    with pytest.raises(module.ProvenanceConflict): module.inspect_runtime_retirement(paths,expected)
    zip_core(paths,version='3.2.85',minimum='3.2.82')
    paths.previous_path.write_text(json.dumps({'schema_version':1,'version':'3.2.84','source_revision':'a'*40}))
    inspected=module.inspect_runtime_retirement(paths,expected)
    assert inspected.current.identity.version=='3.2.85'
    assert inspected.previous.identity.version=='3.2.84'
    (root/'pc_agent.exe').write_bytes(b'changed inactive MSI payload')
    with pytest.raises(module.ProvenanceConflict): module.inspect_runtime_retirement(paths,expected)


@pytest.mark.parametrize('copy_failure',[True,False])
def test_pre_fence_preparation_never_changes_live_ownership(handoff_input,monkeypatch,copy_failure):
    from types import SimpleNamespace
    from pc_agent.platform.windows import installer_transaction_bridge as bridge,durable_state,installer_fence,update_transaction
    module,paths,root,request,expected=handoff_input
    monkeypatch.setattr(update_transaction,'_assert_state_security',lambda _:None)
    package=paths.install_root.parent/'installer-cache'/f'msi-{expected.package.sha256}'/'EndpointAgent.msi'
    package.parent.mkdir(parents=True);package.write_bytes(request['package_path'].read_bytes())
    before={name:(root/name).read_bytes() for name in ('.endpoint-update.json','endpoint-update-manifest.json','pc_agent.exe')}
    selector=paths.current_path.read_bytes()
    capability={'package':request['release'],'transaction_id':request['transaction_id'],'selected':request['selected'],
        'previous':None,'recovery':False,'operation':'install','service_states':{'EndpointAgent':'running','EndpointAgentUpdater':'stopped'}}
    completions=[]
    client=SimpleNamespace(capability=capability,phase='prepare',checkpoint=lambda:None,
        identity=SimpleNamespace(value={'pid':200,'created':2000,'hash':'a'*64}),request=lambda *args:completions.append(args))
    if copy_failure:
        def failed(*_args,**_kwargs): raise OSError('allocation/copy failed')
        monkeypatch.setattr(durable_state,'durable_copy_file',failed)
        with pytest.raises(OSError,match='allocation/copy failed'): bridge.execute_authorized_phase(client,paths)
        assert installer_fence.read_fence(paths) is None
        assert completions==[]
    else:
        bridge.execute_authorized_phase(client,paths)
        assert installer_fence.read_fence(paths)['phase']=='msi-starting'
        assert completions==[('complete',{'result':'handoff'})]
    assert paths.current_path.read_bytes()==selector
    assert {name:(root/name).read_bytes() for name in before}==before


def test_foundation_configuration_requires_fresh_owner_before_each_action(handoff_input,monkeypatch):
    from types import SimpleNamespace
    from pc_agent.platform.windows import installer_transaction_bridge as bridge,acl,service_control,installer_fence
    module,paths,root,request,expected=handoff_input
    events=[]
    monkeypatch.setattr(bridge,'_advance_fence',lambda *_:events.append('fence'))
    monkeypatch.setattr(installer_fence,'read_fence',lambda *_: {'phase':'msi-executing'})
    for target,name in ((service_control,'configure_service_sids'),(acl,'apply_machine_data_acl'),
                        (acl,'apply_tray_status_acl'),(service_control,'restrict_updater_start_permissions')):
        monkeypatch.setattr(target,name,lambda name=name:events.append(name))
    def checkpoint():
        events.append('owner')
        if 'configure_service_sids' in events: raise ValueError('OWNER_AUTH_FAILED')
    client=SimpleNamespace(capability={'package':request['release'],'transaction_id':request['transaction_id'],
        'selected':request['selected'],'previous':None,'operation':'install'},phase='foundation-config',
        checkpoint=checkpoint,request=lambda *_:events.append('complete'))
    with pytest.raises(ValueError,match='OWNER_AUTH_FAILED'): bridge.execute_authorized_phase(client,paths)
    assert events==['fence','owner','configure_service_sids','owner']


def test_partial_quarantine_preserves_original_snapshot_and_recovery_does_not_replace_it(handoff_input,monkeypatch):
    from types import SimpleNamespace
    from pc_agent.platform.windows import installer_transaction_bridge as bridge,installer_fence,update_transaction
    from pc_agent.tests.windows.test_installer_service_quarantine import Services
    module,paths,root,request,expected=handoff_input
    monkeypatch.setattr(update_transaction,'_assert_state_security',lambda _:None)
    package=paths.install_root.parent/'installer-cache'/f'msi-{expected.package.sha256}'/'EndpointAgent.msi'
    package.parent.mkdir(parents=True);package.write_bytes(request['package_path'].read_bytes())
    capability={'package':request['release'],'transaction_id':request['transaction_id'],'selected':request['selected'],
        'previous':None,'recovery':False,'operation':'install','service_states':{'EndpointAgent':'running','EndpointAgentUpdater':'stopped'}}
    completions=[]
    client=SimpleNamespace(capability=capability,phase='prepare',checkpoint=lambda:None,
        identity=SimpleNamespace(value={'pid':200,'created':2000,'hash':'a'*64}),request=lambda *args:completions.append(args))
    api=Services(paths.install_root);api.fail='EndpointAgentUpdater'
    factory=bridge.InstallerServices
    service_class=factory(paths).__class__
    def flushed(name):
        fence=installer_fence.read_fence(paths)
        assert fence['service_startup']['EndpointAgent']=={'start_type':2,'delayed_auto':True}
        assert not fence['startup_restored']
    monkeypatch.setattr(bridge,'InstallerServices',lambda paths,**kw:service_class(paths,api=api,flush=flushed,**kw))
    before=paths.current_path.read_bytes()
    with pytest.raises(OSError,match='configuration failed'): bridge.execute_authorized_phase(client,paths)
    fence=installer_fence.read_fence(paths)
    assert fence['phase']=='prepared' and api.values['EndpointAgent'][1]==4
    assert completions==[] and paths.current_path.read_bytes()==before
    original=fence['service_startup']
    capability['recovery']=True;api.fail=None
    bridge.execute_authorized_phase(client,paths)
    assert installer_fence.read_fence(paths)['service_startup']==original
    assert api.values['EndpointAgentUpdater'][1]==4
    assert paths.current_path.read_bytes()==before


def test_finish_checks_foundation_bytes_before_enable_and_records_restoration_before_retirement(handoff_input,monkeypatch):
    from dataclasses import replace
    from types import SimpleNamespace
    from pc_agent.platform.windows import installer_transaction_bridge as bridge,installer_fence,update_transaction,msi_inventory,durable_state
    from pc_agent.tests.windows.test_installer_service_quarantine import Services
    module,paths,root,request,expected=handoff_input
    monkeypatch.setattr(update_transaction,'_assert_state_security',lambda _:None)
    package=paths.install_root.parent/'installer-cache'/f'msi-{expected.package.sha256}'/'EndpointAgent.msi'
    package.parent.mkdir(parents=True);package.write_bytes(request['package_path'].read_bytes())
    records=[]
    for path,(file_id,component) in msi_inventory.FOUNDATION_EXECUTABLES.items():
        (paths.install_root/path).write_bytes(b'payload')
        records.append({'path':path,'file':file_id,'component':component,'size':7,'sha256':hashlib.sha256(b'payload').hexdigest()})
    expected=replace(expected,foundation_files=tuple(records))
    monkeypatch.setattr(msi_inventory,'read_expected_package',lambda *_:expected)
    api=Services(paths.install_root);service_class=bridge.InstallerServices(paths).__class__
    monkeypatch.setattr(bridge,'InstallerServices',lambda paths,**kw:service_class(paths,api=api,flush=lambda _:None,**kw))
    capability={'package':request['release'],'transaction_id':request['transaction_id'],'selected':request['selected'],
        'previous':None,'recovery':False,'operation':'install','service_states':{'EndpointAgent':'running','EndpointAgentUpdater':'stopped'}}
    client=SimpleNamespace(capability=capability,phase='prepare',checkpoint=lambda:None,
        identity=SimpleNamespace(value={'pid':200,'created':2000,'hash':'a'*64}),request=lambda *_:None)
    bridge.execute_authorized_phase(client,paths)
    client.phase='finish';api.calls.clear()
    executable=paths.install_root/'endpoint-agent-updater.exe';executable.write_bytes(b'changed')
    with pytest.raises(ValueError): bridge.execute_authorized_phase(client,paths)
    assert api.calls==[] and installer_fence.read_fence(paths)['startup_restored'] is False
    executable.write_bytes(b'payload')
    unlink=durable_state.durable_unlink
    def retire(path,**kw):
        assert installer_fence.read_fence(paths)['startup_restored'] is True
        assert api.values['EndpointAgent'][1]==2 and api.values['EndpointAgentUpdater'][1]==3
        unlink(path,**kw)
    monkeypatch.setattr(durable_state,'durable_unlink',retire)
    bridge.execute_authorized_phase(client,paths)
    assert installer_fence.read_fence(paths) is None


def test_fresh_setup_reuses_fully_verified_inert_retention(msi_archive_input):
    module,paths,root,evidence,package_path,package=msi_archive_input
    archive=module.archive_retained_core(paths,evidence,package_path=package_path,package=package,
        transaction_id='11111111-1111-4111-8111-111111111111')
    before=(archive/'receipt.json').read_bytes()
    assert module.archive_retained_core(paths,evidence,package_path=package_path,package=package,
        transaction_id='22222222-2222-4222-8222-222222222222')==archive
    assert (archive/'receipt.json').read_bytes()==before


def test_runtime_retirement_archives_owner_without_retiring_foundation(handoff_input):
    module,paths,root,request,expected=handoff_input
    module.prepare_installer_provenance(paths,request)
    (root/'.endpoint-msi-runtime.json').write_text(json.dumps({'schema_version':1,'version':'3.2.82',
        'component_guid':'33333333-3333-4333-8333-333333333333'}))
    module.reconcile_installed_core(paths,request)
    state=paths.install_root.parent/'installer-state'
    owner=state/'core-owners/3.2.82.json'
    before=owner.read_bytes();foundation=(state/'foundation.json').read_bytes()
    module.prepare_maintenance_provenance(paths,request,'retire-initial-runtime')
    assert owner.read_bytes()==before
    module.retire_maintenance_authority(paths,request,'retire-initial-runtime')
    assert not owner.exists()
    assert (state/'foundation.json').read_bytes()==foundation
    saved=json.loads((state/'transactions'/request['transaction_id']/'maintenance.json').read_bytes())
    assert bytes.fromhex(saved['core_owner'])==before
    module.retire_maintenance_authority(paths,request,'retire-initial-runtime')


def test_retirement_recovery_checks_surviving_zip_and_partial_initial_bytes(handoff_input,monkeypatch):
    from pc_agent.platform.windows import msi_inventory,update_transaction
    module,paths,root,request,expected=handoff_input
    monkeypatch.setattr(update_transaction,'_assert_state_security',lambda _:None)
    monkeypatch.setattr(msi_inventory,'verify_foundation',lambda *_a,**_kw:'foundation_only')
    module.prepare_installer_provenance(paths,request)
    (root/'.endpoint-msi-runtime.json').write_text(json.dumps({'schema_version':1,'version':'3.2.82',
        'component_guid':'33333333-3333-4333-8333-333333333333'}))
    module.reconcile_installed_core(paths,request)
    zip_core(paths,version='3.2.84',minimum='3.2.82')
    zip_core(paths,version='3.2.85',minimum='3.2.82')
    paths.previous_path.write_text(json.dumps({'schema_version':1,'version':'3.2.84','source_revision':'a'*40}))
    module.prepare_maintenance_provenance(paths,request,'retire-initial-runtime')
    (root/'pc_agent.exe').unlink()
    assert module.inspect_runtime_retirement(paths,expected,recovery=True).current.identity.version=='3.2.85'
    (root/'unexpected').write_bytes(b'preserve evidence')
    with pytest.raises(module.ProvenanceConflict): module.inspect_runtime_retirement(paths,expected,recovery=True)


@pytest.mark.parametrize('barrier_defect',['none','missing','old-session','changed-postconditions'])
def test_uninstall_finalization_requires_fresh_durable_barrier_before_retirement(handoff_input,monkeypatch,barrier_defect):
    from types import SimpleNamespace
    from pc_agent.platform.windows import installer_transaction_bridge as bridge,installer_fence,msi_inventory
    module,paths,root,request,expected=handoff_input
    monkeypatch.setattr(bridge,'assert_state_security',lambda *_:None)
    monkeypatch.setattr(module,'validate_maintenance_recovery',lambda *_:None)
    absence={'product_code':expected.package.product_code,'root_absent':True,'evidence':'a'*64}
    monkeypatch.setattr(msi_inventory,'verify_uninstalled',lambda *_:absence)
    retired=[]
    monkeypatch.setattr(module,'retire_maintenance_authority',lambda *_:retired.append('retired'))
    capability={'package':request['release'],'transaction_id':request['transaction_id'],
        'session_id':'33333333-3333-4333-8333-333333333333','selected':request['selected'],
        'previous':None,'recovery':True,'uninstall_finalization':True,'operation':'uninstall',
        'service_states':{'EndpointAgent':'running','EndpointAgentUpdater':'stopped'}}
    client=SimpleNamespace(capability=capability,phase='uninstall-finalize-enter',checkpoint=lambda:None,
        identity=SimpleNamespace(value={'pid':200,'created':2000,'hash':'a'*64}),request=lambda *_:None)
    installer_fence.publish_fence(paths,bridge._public_fence(expected,capability))
    bridge.execute_authorized_phase(client,paths)
    archive=installer_fence.state_root(paths)/'transactions'/request['transaction_id']
    barrier=archive/('barrier-'+capability['session_id']+'.json')
    assert barrier.is_file() and installer_fence.read_fence(paths) is not None and retired==[]
    if barrier_defect=='missing': barrier.unlink()
    elif barrier_defect=='old-session':
        data=json.loads(barrier.read_bytes());data['session_id']='44444444-4444-4444-8444-444444444444'
        barrier.write_text(json.dumps(data))
    elif barrier_defect=='changed-postconditions': absence['evidence']='b'*64
    client.phase='reconcile'
    if barrier_defect!='none':
        with pytest.raises((ValueError,OSError)): bridge.execute_authorized_phase(client,paths)
        assert retired==[] and installer_fence.read_fence(paths) is not None
    else:
        assert bridge.execute_authorized_phase(client,paths)=={'result':'uninstalled'}
        assert retired==['retired'] and installer_fence.read_fence(paths) is not None
        client.phase='finish'
        bridge.execute_authorized_phase(client,paths)
        assert installer_fence.read_fence(paths) is None
        assert (archive/'completed.json').is_file()


@pytest.mark.parametrize('defect',[None,'component','receipt','payload'])
def test_newer_msi_owner_remaining_installed_is_preserved(handoff_input,monkeypatch,defect):
    from dataclasses import replace
    from types import SimpleNamespace
    from pc_agent.platform.windows import msi_inventory
    from endpoint_contracts.runtime_payload import verify_payload
    module,paths,candidate,request,expected=handoff_input
    newer=zip_core(paths,version='3.2.83',minimum='3.2.81')
    (newer/'.endpoint-update.json').unlink()
    manifest=json.loads((newer/'endpoint-update-manifest.json').read_text())
    identity=verify_payload(newer,manifest,excluded=frozenset({'endpoint-update-manifest.json'}))
    old_bytes=b'exact newer MSI package'
    old_hash=hashlib.sha256(old_bytes).hexdigest()
    old_file=replace(expected.package.files[0],path='versions/3.2.83/pc_agent.exe')
    old_package=replace(expected.package,version='3.2.83',sha256=old_hash,
        product_code='{44444444-4444-4444-8444-444444444444}',files=(old_file,))
    old_expected=replace(expected,package=old_package,identity=identity,manifest=manifest,
        contract_bytes=(newer/'endpoint-runtime-contract.json').read_bytes())
    old_release={**request['release'],'version':'3.2.83','product_code':old_package.product_code,'package_sha256':old_hash}
    state=paths.install_root.parent/'installer-state'
    media=state/'packages'/old_hash/'EndpointAgent.msi';media.parent.mkdir(parents=True);media.write_bytes(old_bytes)
    owners=state/'core-owners';owners.mkdir()
    receipt=owners/'3.2.83.json';receipt.write_text(json.dumps({'schema_version':1,'release':old_release}))
    marker=json.dumps({'schema_version':1,'version':'3.2.83','component_guid':'33333333-3333-4333-8333-333333333333'})
    (newer/'.endpoint-msi-runtime.json').write_text(marker)
    monkeypatch.setattr(msi_inventory,'read_expected_package',lambda _path,release:old_expected if release==old_release else expected)
    monkeypatch.setattr(msi_inventory,'read_package',lambda _path,digest:old_package if digest==old_hash else expected.package)
    state_after={'bad_component':False}
    checked=[]
    def verify(package,root):
        checked.append(package.product_code)
        if package==old_package and state_after['bad_component']: raise module.ProvenanceConflict()
    monkeypatch.setattr(msi_inventory,'verify_installed',verify)
    monkeypatch.setattr(msi_inventory,'NativeMsi',lambda:SimpleNamespace(product=lambda _:5))
    before=module.inspect_installed_core(paths,resulting_foundation='3.2.82').current
    request['selected']=before.digest
    assert module.prepare_installer_provenance(paths,request)=='preserved'
    (candidate/'.endpoint-msi-runtime.json').write_text(json.dumps({'schema_version':1,'version':'3.2.82','component_guid':'33333333-3333-4333-8333-333333333333'}))
    if defect=='component': state_after['bad_component']=True
    elif defect=='receipt': receipt.write_text('{}')
    elif defect=='payload': (newer/'pc_agent.exe').write_bytes(b'changed')
    checked.clear()
    if defect:
        with pytest.raises(module.ProvenanceConflict): module.reconcile_installed_core(paths,request)
    else:
        assert module.reconcile_installed_core(paths,request)=='preserved'
        assert old_package.product_code in checked
        after=module.inspect_installed_core(paths,resulting_foundation='3.2.82').current
        assert after.origin=='msi' and after.digest==before.digest
        from pc_agent.platform.windows import service_launcher
        monkeypatch.setattr(service_launcher,'AGENT_VERSION','3.2.82')
        assert service_launcher.build_agent_child_command(paths)[0]==str(newer/'pc_agent.exe')
        assert module.reconcile_installed_core(paths,request)=='preserved'
    assert (newer/'.endpoint-msi-runtime.json').read_text()==marker
    assert not (newer/'.endpoint-retained-msi.json').exists()


@pytest.mark.parametrize('defect',[None,'missing_link','missing_archive_receipt','changed_payload'])
def test_boot_requires_complete_retained_ownership(msi_archive_input,monkeypatch,defect):
    from types import SimpleNamespace
    from pc_agent.platform.windows import msi_inventory,service_launcher
    module,paths,root,evidence,package_path,package=msi_archive_input
    archive=module.archive_retained_core(paths,evidence,package_path=package_path,package=package,
        transaction_id='11111111-1111-4111-8111-111111111111')
    monkeypatch.setattr(msi_inventory,'NativeMsi',lambda:SimpleNamespace(product=lambda _:-1))
    monkeypatch.setattr(service_launcher,'AGENT_VERSION','3.2.82')
    module.restore_retained_core(paths,archive.name)
    if defect=='missing_link': (root/'.endpoint-retained-msi.json').unlink()
    elif defect=='missing_archive_receipt': (archive/'receipt.json').unlink()
    elif defect=='changed_payload': (root/'pc_agent.exe').write_bytes(b'changed')
    if defect:
        with pytest.raises((ValueError,OSError)):
            service_launcher.build_agent_child_command(paths)
    else:
        assert service_launcher.build_agent_child_command(paths)[0]==str(root/'pc_agent.exe')
