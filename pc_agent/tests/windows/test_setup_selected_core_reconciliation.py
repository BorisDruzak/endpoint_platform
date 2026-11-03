"""A complete native package is distinct from the actually selected Core."""
import json
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import setup_entry, installation_provenance as provenance, msi_inventory
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths


@pytest.mark.parametrize('version,origin,required', [
    ('3.2.157','zip',True), ('3.2.158','zip',True),
    ('3.2.158','msi',False), ('3.2.161','zip',False),
])
def test_equal_foundation_checks_selected_core_and_preserves_newer_compatible_core(tmp_path,monkeypatch,version,origin,required):
    media=tmp_path/'EndpointAgent.msi'
    release={'version':'3.2.158','package_sha256':'a'*64}
    media.with_name('EndpointAgent.release.json').write_text(json.dumps(release),encoding='utf-8')
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    identity=SimpleNamespace(version='3.2.158',source_revision='b'*40)
    expected=SimpleNamespace(package=SimpleNamespace(version='3.2.158'),identity=identity)
    monkeypatch.setattr(msi_inventory,'read_expected_package',lambda *_:expected)
    monkeypatch.setattr(msi_inventory,'installed_feature_state',lambda _: 'complete')
    monkeypatch.setattr(provenance,'_read',lambda *_:json.dumps({'schema_version':1,'release':release}).encode())
    selected=SimpleNamespace(origin=origin,identity=SimpleNamespace(version=version,source_revision='b'*40))
    monkeypatch.setattr(provenance,'inspect_installed_core',lambda *a,**k:SimpleNamespace(current=selected))
    monkeypatch.setattr(provenance,'_selector_bytes',lambda _:b'fixture selector')
    monkeypatch.setattr(provenance,'_inspect_core_value',lambda *a:SimpleNamespace(origin='msi',identity=identity))
    assert setup_entry._msi_reconciliation_required(media,paths=paths) is required
