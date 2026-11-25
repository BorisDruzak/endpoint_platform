"""MSI ownership requires live product, feature and component evidence."""
from pathlib import Path
import pytest


def package(module):
    return module.PackageInventory('a'*64, '{11111111-1111-4111-8111-111111111111}',
        '{22222222-2222-4222-8222-222222222222}', '3.2.82',
        {'EndpointAgentFeature': 1, 'EndpointAgentInitialRuntimeFeature': 1},
        {'core': module.Component('core', '{33333333-3333-4333-8333-333333333333}', 'INITIALRUNTIMEDIR', 'corefile', ('EndpointAgentInitialRuntimeFeature',))},
        (module.InstalledFile('corefile', 'core', 'versions/3.2.82/pc_agent.exe', 4),))


class Native:
    def product(self, code): return 5
    def property(self, code, name):
        return {'VersionString': '3.2.82', 'PackageCode': '{22222222-2222-4222-8222-222222222222}'}[name]
    def feature(self, product, feature): return 3
    def component(self, product, component): return 3, str(self.root / 'versions/3.2.82/pc_agent.exe')


@pytest.mark.parametrize('defect', ['product', 'version', 'package', 'feature', 'component', 'keypath'])
def test_live_msi_mismatch_is_conflict(tmp_path, defect):
    from pc_agent.platform.windows import msi_inventory as module
    native = Native(); native.root = tmp_path
    if defect == 'product': native.product = lambda _code: -1
    elif defect in {'version', 'package'}:
        base = native.property
        native.property = lambda code, name: 'wrong' if name == ('VersionString' if defect == 'version' else 'PackageCode') else base(code, name)
    elif defect == 'feature': native.feature = lambda *_: 2
    elif defect == 'component': native.component = lambda *_: (2, str(tmp_path / 'versions/3.2.82/pc_agent.exe'))
    else: native.component = lambda *_: (3, str(tmp_path / 'another.exe'))
    with pytest.raises(module.ProvenanceConflict, match='PROVENANCE_CONFLICT'):
        module.verify_installed(package(module), tmp_path, native=native)


def test_equal_version_missing_runtime_feature_requires_handoff(tmp_path):
    from pc_agent.platform.windows import msi_inventory as module
    native = Native(); native.root = tmp_path
    native.feature = lambda _product, feature: 2 if feature == 'EndpointAgentInitialRuntimeFeature' else 3
    assert module.installed_feature_state(package(module), native=native) == 'foundation_only'


def test_live_complete_product_identity(tmp_path):
    from pc_agent.platform.windows import msi_inventory as module
    native = Native(); native.root = tmp_path
    module.verify_installed(package(module), tmp_path, native=native)


def test_persist_installed_flushes_package_files_before_directories_and_registry(tmp_path, monkeypatch):
    from pc_agent.platform.windows import durable_state, msi_inventory as module

    install_root = tmp_path / 'Agent'
    inventory = package(module)
    payload = install_root / inventory.files[0].path
    original = tmp_path / 'source.msi'
    calls = []

    def flush_file(path, *, trusted_root, verified_identity):
        assert trusted_root == install_root
        assert verified_identity is None
        calls.append(path)

    def persist_cache(path, package):
        assert path == original and package == inventory
        calls.append('cache')

    monkeypatch.setattr(durable_state, 'flush_existing_file', flush_file)
    monkeypatch.setattr(durable_state, 'flush_directory', calls.append)
    monkeypatch.setattr(module, 'persist_registered_cache', persist_cache)
    monkeypatch.setattr(module, '_flush_installation_registry', lambda: calls.append('registry'))

    module.persist_installed(inventory, install_root, original_path=original)

    assert calls == [payload, payload.parent, install_root / 'versions',
                     install_root, tmp_path, 'cache', 'registry']


def test_foundation_verification_rejects_missing_component_with_runtime_retired(tmp_path):
    from dataclasses import replace
    from pc_agent.platform.windows import msi_inventory as module
    p=package(module)
    p=replace(p,components={**p.components,'host':module.Component('host',
        '{44444444-4444-4444-8444-444444444444}','INSTALLFOLDER','hostfile',('EndpointAgentFeature',))},
        files=(*p.files,module.InstalledFile('hostfile','host','endpoint-agent-service.exe',4)))
    native=Native();native.root=tmp_path
    native.feature=lambda _p,f:2 if f==module.RUNTIME_FEATURE else 3
    native.component=lambda *_:(3,str(tmp_path/'endpoint-agent-service.exe'))
    assert module.verify_foundation(p,tmp_path,native=native)=='foundation_only'
    native.component=lambda *_:(2,str(tmp_path/'endpoint-agent-service.exe'))
    with pytest.raises(module.ProvenanceConflict): module.verify_foundation(p,tmp_path,native=native)


@pytest.mark.parametrize('remaining',['none','product','feature','component','resources','directory'])
def test_uninstall_postconditions_require_full_absence(tmp_path,remaining):
    from types import SimpleNamespace
    from pc_agent.platform.windows import msi_inventory as module
    root=tmp_path/'removed-agent'
    if remaining=='directory': root.mkdir()
    native=SimpleNamespace(product=lambda *_:5 if remaining=='product' else -1,
        feature=lambda *_:3 if remaining=='feature' else -1,
        component=lambda *_:(3 if remaining=='component' else -1,''),
        resources_absent=lambda *_:remaining!='resources')
    if remaining=='none':
        evidence=module.verify_uninstalled(package(module),root,native=native)
        assert evidence['component_count']==1 and len(evidence['ownership_sha256'])==64
    else:
        with pytest.raises(module.ProvenanceConflict): module.verify_uninstalled(package(module),root,native=native)


@pytest.mark.parametrize('minimum',[None,'3.2.82','3.2.83'])
@pytest.mark.parametrize('schema', [1, 2])
def test_embedded_runtime_inventory_must_match_feature_file_ownership(tmp_path, monkeypatch,minimum,schema):
    import hashlib, json
    from dataclasses import replace
    from pc_agent.platform.windows import msi_inventory as module
    from pc_agent.tests.windows.test_installation_provenance import payload
    manifest = payload(tmp_path,minimum=minimum)
    contract_bytes = (tmp_path / 'endpoint-runtime-contract.json').read_bytes()
    p = package(module)
    files = tuple(module.InstalledFile(row['path'], 'core', 'versions/3.2.82/'+row['path'], row['size']) for row in manifest['files'])
    files += (module.InstalledFile('manifest','core','versions/3.2.82/endpoint-update-manifest.json',100),
        module.InstalledFile('marker','core','versions/3.2.82/.endpoint-msi-runtime.json',100))
    components=dict(p.components);foundation=[]
    for path,(file_id,component) in module.FOUNDATION_EXECUTABLES.items():
        components[component]=module.Component(component,'{33333333-3333-4333-8333-333333333333}','INSTALLFOLDER',path,('EndpointAgentFeature',))
        files+=(module.InstalledFile(file_id,component,path,7),)
        foundation.append({'path':path,'file':file_id,'component':component,'size':7,'sha256':hashlib.sha256(b'payload').hexdigest()})
    if schema == 2:
        from pc_agent.platform.windows.foundation_layout import shared_binding
        path = '_foundation-runtime/python312.dll'
        file_id, component = shared_binding(path)
        components[component] = module.Component(component,
            '{44444444-4444-4444-8444-444444444444}', 'SHAREDDIR', file_id, ('EndpointAgentFeature',))
        files += (module.InstalledFile(file_id, component, path, 3),)
        foundation.append(dict(path=path, file=file_id, component=component, size=3, sha256='b'*64))
    p = replace(p, files=files,components=components)
    monkeypatch.setattr(module, 'read_package', lambda *_:p)
    monkeypatch.setattr(module, 'read_binary', lambda *_a, **_kw:json.dumps({'schema_version':schema,'manifest':manifest,'contract_bytes':contract_bytes.hex(),'foundation_files':foundation}).encode())
    tree = hashlib.sha256()
    for row in sorted(manifest['files'], key=lambda row:'endpoint_agent_core.exe' if row['path']=='pc_agent.exe' else row['path']):
        name='endpoint_agent_core.exe' if row['path']=='pc_agent.exe' else row['path']
        tree.update(f"{name}\0{row['size']}\0{row['sha256']}\n".encode())
    release = {'schema_version':'endpoint_windows_release_v1','version':'3.2.82','source_revision':'a'*40,
        'package_sha256':'a'*64,'product_code':p.product_code,'initial_runtime_tree_sha256':tree.hexdigest()}
    if minimum=='3.2.83':
        with pytest.raises(module.ProvenanceConflict): module.read_expected_package(tmp_path/'test.msi',release)
        return
    expected = module.read_expected_package(tmp_path / 'test.msi', release)
    assert expected.identity.source_revision == 'a'*40
    assert expected.foundation_schema == schema
    if schema == 2:
        original = p
        p = replace(p, components={**p.components, component: replace(p.components[component], keypath='wrong')})
        with pytest.raises(module.ProvenanceConflict):
            module.read_expected_package(tmp_path/'test.msi', release)
        p = replace(p, components={**p.components, component: replace(p.components[component], features=(module.RUNTIME_FEATURE,))})
        with pytest.raises(module.ProvenanceConflict):
            module.read_expected_package(tmp_path/'test.msi', release)
        p = replace(original, files=(*original.files,
            module.InstalledFile('foreign', component, '_foundation-runtime/foreign.dll', 7)))
        with pytest.raises(module.ProvenanceConflict):
            module.read_expected_package(tmp_path/'test.msi', release)
        p = original
    p = replace(p, components={'core':replace(p.components['core'], features=('EndpointAgentFeature',))})
    with pytest.raises(module.ProvenanceConflict): module.read_expected_package(tmp_path / 'test.msi', release)


@pytest.mark.parametrize('defect',['none','missing','extra','hash','size','hardlink'])
def test_installed_foundation_executable_inventory_is_complete_and_exact(tmp_path,monkeypatch,defect):
    import hashlib,os
    from types import SimpleNamespace
    from pc_agent.platform.windows import msi_inventory as module,update_transaction
    monkeypatch.setattr(update_transaction,'_assert_state_security',lambda *_:None)
    records=[]
    for path,(file_id,component) in module.FOUNDATION_EXECUTABLES.items():
        (tmp_path/path).write_bytes(b'payload')
        records.append({'path':path,'file':file_id,'component':component,'size':7,'sha256':hashlib.sha256(b'payload').hexdigest()})
    first=tmp_path/records[0]['path']
    if defect=='missing': records.pop()
    elif defect=='extra': records.append({**records[0],'path':'extra.exe'})
    elif defect=='hash': first.write_bytes(b'changed')
    elif defect=='size': first.write_bytes(b'short')
    elif defect=='hardlink': os.link(first,tmp_path/'alias.exe')
    expected=SimpleNamespace(foundation_files=tuple(records))
    if defect=='none':
        with module.verified_foundation_bytes(expected,tmp_path): pass
    else:
        with pytest.raises((ValueError,OSError)):
            with module.verified_foundation_bytes(expected,tmp_path): pytest.fail('invalid foundation enabled')


@pytest.mark.parametrize('drift', [False, True])
def test_component_verification_bounds_feature_queries_and_rechecks_after_walk(tmp_path, drift):
    from dataclasses import replace
    from pc_agent.platform.windows import msi_inventory as module
    p = package(module)
    components = tuple(replace(next(iter(p.components.values())), name=f'core{i}') for i in range(40))
    native = Native(); native.root = tmp_path
    events = []
    def feature(_product, name):
        events.append(('feature', name))
        return 2 if drift and any(kind == 'component' for kind, _ in events) else 3
    def component(_product, name):
        events.append(('component', name))
        return 3, str(tmp_path / 'versions/3.2.82/pc_agent.exe')
    native.feature = feature; native.component = component
    if drift:
        with pytest.raises(module.ProvenanceConflict):
            module._verify_components(p, tmp_path, native, iter(components))
    else:
        module._verify_components(p, tmp_path, native, iter(components))
    assert [kind for kind, _ in events] == ['feature'] + ['component'] * 40 + ['feature']


def test_component_verification_rejects_feature_before_component_access(tmp_path):
    from pc_agent.platform.windows import msi_inventory as module
    native = Native(); native.root = tmp_path
    native.feature = lambda *_: 2
    native.component = lambda *_: pytest.fail('unavailable feature reached component query')
    with pytest.raises(module.ProvenanceConflict):
        module._verify_components(package(module), tmp_path, native, package(module).components.values())


@pytest.mark.parametrize('defect', [None, 'shared-root-absent', 'different-keypath', 'present-absent',
    'missing-local', 'wrong-package', 'wrong-state', 'altered-bytes', 'foreign-shared-file'])
def test_interrupted_foundation_checks_removed_keypaths_and_remaining_bytes(tmp_path, monkeypatch, defect):
    from dataclasses import replace
    from hashlib import sha256
    from types import SimpleNamespace
    from pc_agent.platform.windows import msi_inventory as module, update_transaction

    monkeypatch.setattr(update_transaction, '_assert_state_security', lambda _: None)
    shared = '_foundation-runtime/deleted/proof.dll'
    retained = '_foundation-runtime/live.dll'
    paths = (shared, retained, 'current.json')
    components = {
        f'component{index}': module.Component(f'component{index}', f'guid{index}',
            'INSTALLFOLDER', f'file{index}', (module.FOUNDATION_FEATURE,))
        for index, _ in enumerate(paths)
    }
    inventory = replace(package(module), components=components, files=tuple(
        module.InstalledFile(f'file{index}', f'component{index}', path, 5)
        for index, path in enumerate(paths)
    ))
    rows = tuple(dict(path=path, file=f'file{index}', component=f'component{index}',
        size=5, sha256=sha256(b'bytes').hexdigest()) for index, path in enumerate(paths[:2]))
    monkeypatch.setattr(module, '_foundation_records', lambda records, **_: records)
    expected = SimpleNamespace(package=inventory, foundation_files=rows, foundation_schema=3)
    native = Native()
    locations = {f'guid{index}': (3 if path == retained else 2, str(tmp_path / path))
                 for index, path in enumerate(paths)}
    native.component = lambda _product, guid: locations[guid]
    live = tmp_path / retained
    live.parent.mkdir()
    live.write_bytes(b'bytes')
    if defect == 'shared-root-absent':
        live.unlink()
        live.parent.rmdir()
        locations['guid1'] = (2, str(live))
    elif defect == 'different-keypath':
        locations['guid0'] = (2, str(tmp_path / 'unknown.dll'))
    elif defect == 'present-absent':
        (tmp_path / shared).parent.mkdir()
        (tmp_path / shared).write_bytes(b'bytes')
    elif defect == 'missing-local':
        live.unlink()
    elif defect == 'wrong-package':
        native.property = lambda *_: 'different'
    elif defect == 'wrong-state':
        locations['guid0'] = (-1, str(tmp_path / shared))
    elif defect == 'altered-bytes':
        live.write_bytes(b'other')
    elif defect == 'foreign-shared-file':
        (live.parent / 'foreign.dll').write_bytes(b'other')

    if defect is None:
        assert module.verify_interrupted_foundation(expected, tmp_path, native=native) == {shared, 'current.json'}
    elif defect == 'shared-root-absent':
        assert module.verify_interrupted_foundation(expected, tmp_path, native=native) == set(paths)
    else:
        with pytest.raises((ValueError, OSError)):
            module.verify_interrupted_foundation(expected, tmp_path, native=native)


@pytest.mark.parametrize("size", [0, 5])
def test_binary_size_rejects_invalid_stream_and_closes_handles(monkeypatch, tmp_path, size):
    from pc_agent.platform.windows import msi_inventory as module

    closed = []

    def open_handle(handle):
        def open_api(*args):
            args[-1]._obj.value = handle
            return 0
        return open_api

    functions = {
        "MsiOpenDatabaseW": open_handle(1),
        "MsiDatabaseOpenViewW": open_handle(2),
        "MsiViewExecute": lambda *_: 0,
        "MsiViewFetch": open_handle(3),
        "MsiRecordDataSize": lambda *_: size,
        "MsiCloseHandle": closed.append,
    }

    class SizeOnlyMsi:
        def _api(self, name, *_args, **_kwargs):
            return functions[name]

    monkeypatch.setattr(module, "NativeMsi", SizeOnlyMsi)
    with pytest.raises(module.ProvenanceConflict):
        module.binary_size(tmp_path / "package.msi", "EndpointInstallerHost", maximum=4)
    assert closed == [3, 2, 1]
