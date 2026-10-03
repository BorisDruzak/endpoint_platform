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
def test_embedded_runtime_inventory_must_match_feature_file_ownership(tmp_path, monkeypatch,minimum):
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
    p = replace(p, files=files,components=components)
    monkeypatch.setattr(module, 'read_package', lambda *_:p)
    monkeypatch.setattr(module, 'read_binary', lambda *_a, **_kw:json.dumps({'schema_version':1,'manifest':manifest,'contract_bytes':contract_bytes.hex(),'foundation_files':foundation}).encode())
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
