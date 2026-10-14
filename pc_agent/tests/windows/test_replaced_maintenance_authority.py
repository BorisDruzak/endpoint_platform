"""Recovery retires only old authority while preserving an exact new foundation."""
from contextlib import contextmanager
import json
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import installation_provenance as provenance,installer_fence as fence,msi_inventory
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths


@pytest.fixture
def replacement(tmp_path,monkeypatch):
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    root=fence.state_root(paths);root.mkdir();(root/'core-owners').mkdir()
    old={'version':'3.2.92','package_sha256':'b'*64,'source_revision':'a'*40}
    new={'version':'3.2.94','package_sha256':'d'*64,'source_revision':'e'*40}
    old_request={'release':old,'transaction_id':'11111111-1111-4111-8111-111111111111'}
    new_request={'release':new,'transaction_id':'33333333-3333-4333-8333-333333333333'}
    before=json.dumps({'schema_version':1,'release':old}).encode()
    record={'schema_version':1,'operation':'uninstall','transaction_id':old_request['transaction_id'],
        'release':old,'core_owner':before.hex(),'foundation':before.hex()}
    original=root/'transactions'/old_request['transaction_id'];original.mkdir(parents=True)
    (original/'maintenance.json').write_text(json.dumps(record))
    (root/'core-owners'/'3.2.92.json').write_bytes(before)
    (root/'foundation.json').write_text(json.dumps({'schema_version':1,'release':new}))
    monkeypatch.setattr(fence,'assert_state_security',lambda *_a,**_k:None)
    monkeypatch.setattr(provenance,'_assert_security',lambda *_a:None)
    monkeypatch.setattr(provenance,'_expected_request',lambda request:SimpleNamespace(
        package=SimpleNamespace(version=request['release']['version']),identity=SimpleNamespace(version=request['release']['version'])))
    events=[]
    monkeypatch.setattr(msi_inventory,'verify_replaced_product',lambda *_a:events.append('native-replacement'))
    @contextmanager
    def verified(*_a):events.append('new-bytes-pinned');yield
    monkeypatch.setattr(msi_inventory,'verified_foundation_bytes',verified)
    return paths,old_request,new_request,record,events


def test_replaced_retirement_preserves_successor_and_original_saved_authority(replacement):
    paths,old,new,record,events=replacement
    root=fence.state_root(paths);current=(root/'foundation.json').read_bytes()
    before=(root/'transactions'/old['transaction_id']/'maintenance.json').read_bytes()
    provenance.retire_replaced_maintenance_authority(paths,old,new)
    assert events==['native-replacement','new-bytes-pinned']
    assert (root/'foundation.json').read_bytes()==current
    assert not (root/'core-owners'/'3.2.92.json').exists()
    assert (root/'transactions'/old['transaction_id']/'maintenance.json').read_bytes()==before


@pytest.mark.parametrize('defect',['wrong-new','old-present','changed-original','wrong-operation','foreign-old-owner'])
def test_replaced_retirement_never_normalizes_foreign_or_unsettled_authority(replacement,monkeypatch,defect):
    paths,old,new,record,events=replacement;root=fence.state_root(paths)
    if defect=='wrong-new':(root/'foundation.json').write_text(json.dumps({'schema_version':1,'release':{**new['release'],'source_revision':'0'*40}}))
    elif defect=='old-present':
        def failed(*_a):raise ValueError('PROVENANCE_CONFLICT')
        monkeypatch.setattr(msi_inventory,'verify_replaced_product',failed)
    elif defect=='changed-original':
        record['foundation']=json.dumps({'schema_version':1,'release':new['release']}).encode().hex()
        (root/'transactions'/old['transaction_id']/'maintenance.json').write_text(json.dumps(record))
    elif defect=='wrong-operation':
        record['operation']='retire-initial-runtime';(root/'transactions'/old['transaction_id']/'maintenance.json').write_text(json.dumps(record))
    elif defect=='foreign-old-owner':(root/'core-owners'/'3.2.92.json').write_bytes(b'foreign')
    current=(root/'foundation.json').read_bytes();old_owner=(root/'core-owners'/'3.2.92.json').read_bytes()
    with pytest.raises(ValueError):provenance.retire_replaced_maintenance_authority(paths,old,new)
    assert (root/'foundation.json').read_bytes()==current
    assert (root/'core-owners'/'3.2.92.json').read_bytes()==old_owner
