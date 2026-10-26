"""The wrapper's predecessor is read from verified foundation authority."""
import json
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import installation_provenance as provenance, installer_fence as fence, msi_inventory
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths


def test_legacy_foundation_extension_is_exact_and_keeps_historical_contracts():
    from pc_agent.platform.windows import runtime_identity as identity
    canonical={
        '2f7d778799f1e32645af7936dfaf3f090d6ad4df5bb883827ea8a0a5d859f72a',
        'ad4dc49703513d6dee6fd3e51ac94a09c5967112d58aed4e60a63cf6966251f5',
    }
    expected={version:frozenset(canonical) for version in ('3.2.94','3.2.95','3.2.96','3.2.97','3.2.98','3.2.99','3.2.103','3.2.106','3.2.109','3.2.112','3.2.113','3.2.114','3.2.115','3.2.116','3.2.117','3.2.118','3.2.119','3.2.120')}
    expected.update({version:frozenset({'2f7d778799f1e32645af7936dfaf3f090d6ad4df5bb883827ea8a0a5d859f72a'}) for version in ('3.2.122','3.2.123','3.2.124','3.2.125','3.2.126','3.2.127','3.2.128','3.2.129','3.2.130','3.2.131','3.2.132','3.2.133','3.2.134','3.2.135','3.2.136','3.2.137','3.2.138','3.2.139','3.2.140','3.2.141','3.2.142','3.2.144','3.2.145','3.2.146','3.2.147','3.2.148','3.2.149')})
    assert identity._LEGACY_FOUNDATION_EXTENSIONS == expected
    for package in canonical:
        assert identity._LEGACY_MSI_CONTRACTS[package]['approved_foundations']==('3.2.82',)
        assert identity.legacy_foundation_compatible(package,'3.2.82')
        assert identity.legacy_foundation_compatible(package,'3.2.94')
        assert identity.legacy_foundation_compatible(package,'3.2.95')
        assert identity.legacy_foundation_compatible(package,'3.2.96')
        assert identity.legacy_foundation_compatible(package,'3.2.97')
        assert identity.legacy_foundation_compatible(package,'3.2.98')
        assert identity.legacy_foundation_compatible(package,'3.2.99')
        assert identity.legacy_foundation_compatible(package,'3.2.106')
        assert identity.legacy_foundation_compatible(package,'3.2.109')
        assert identity.legacy_foundation_compatible(package,'3.2.112')
        assert identity.legacy_foundation_compatible(package,'3.2.113')
        assert identity.legacy_foundation_compatible(package,'3.2.114')
        assert identity.legacy_foundation_compatible(package,'3.2.115')
        assert identity.legacy_foundation_compatible(package,'3.2.116')
        assert identity.legacy_foundation_compatible(package,'3.2.117')
        assert identity.legacy_foundation_compatible(package,'3.2.118')
        assert identity.legacy_foundation_compatible(package,'3.2.119')
        assert identity.legacy_foundation_compatible(package,'3.2.120')
        for version in ('3.2.81','3.2.93','3.2.100','3.2.121','4.0.0'):
            assert not identity.legacy_foundation_compatible(package,version)
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.94')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.95')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.96')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.97')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.98')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.99')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.106')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.109')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.112')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.113')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.114')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.115')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.116')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.117')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.118')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.119')
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.120')


@pytest.mark.parametrize('defect',['none','absent','fields','schema','native'])
def test_foundation_release_requires_native_package_identity(tmp_path,monkeypatch,defect):
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    root=fence.state_root(paths);root.mkdir()
    release={'package_sha256':'b'*64,'version':'3.2.92'}
    value={'schema_version':1,'release':release}
    if defect=='fields':value['approved']=True
    if defect=='schema':value['schema_version']=True
    if defect!='absent':(root/'foundation.json').write_text(json.dumps(value))
    monkeypatch.setattr(fence,'assert_state_security',lambda *_a,**_k:None)
    monkeypatch.setattr(provenance,'_assert_security',lambda *_a:None)
    expected=SimpleNamespace(package=SimpleNamespace(sha256='b'*64))
    calls=[]
    def package(path,actual):
        assert path==root/'packages'/('b'*64)/'EndpointAgent.msi' and actual==release
        calls.append('package');return expected
    def verify(package,install_root,*,expected):
        if defect=='native':raise ValueError('PROVENANCE_CONFLICT')
        calls.append('native');return 'complete'
    monkeypatch.setattr(msi_inventory,'read_expected_package',package)
    monkeypatch.setattr(msi_inventory,'verify_foundation',verify)
    if defect in {'none','absent'}:
        result=provenance.verified_foundation_release(paths)
        assert result==(release if defect=='none' else None)
        assert calls==(['package','native'] if defect=='none' else [])
    else:
        with pytest.raises(ValueError):provenance.verified_foundation_release(paths)


def test_foundation_without_modern_marker_uses_exact_readonly_legacy_inspection(tmp_path,monkeypatch):
    from pc_agent.platform.windows import legacy_foundation_upgrade as legacy
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    root=fence.state_root(paths);root.mkdir()
    release={'version':'3.2.81','package_sha256':'a'*64}
    seen=[]
    def inspect(actual):assert actual is paths;seen.append(actual);return release
    monkeypatch.setattr(legacy,'inspect_foundation',inspect)
    assert provenance.verified_foundation_release(paths)==release
    assert seen==[paths] and not (root/'foundation.json').exists()


def test_unified_windows_candidate_uses_new_immutable_version():
    from pc_agent.version import AGENT_VERSION
    assert AGENT_VERSION == "3.2.150"
