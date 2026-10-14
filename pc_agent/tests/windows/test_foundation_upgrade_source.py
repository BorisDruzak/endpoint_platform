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
    assert identity._LEGACY_FOUNDATION_EXTENSIONS=={'3.2.94':frozenset(canonical)}
    for package in canonical:
        assert identity._LEGACY_MSI_CONTRACTS[package]['approved_foundations']==('3.2.82',)
        assert identity.legacy_foundation_compatible(package,'3.2.82')
        assert identity.legacy_foundation_compatible(package,'3.2.94')
        for version in ('3.2.81','3.2.93','3.2.95','4.0.0'):
            assert not identity.legacy_foundation_compatible(package,version)
    assert not identity.legacy_foundation_compatible('0'*64,'3.2.94')


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
