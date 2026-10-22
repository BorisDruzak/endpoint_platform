"""Build-time admission reads the complete compiled MSI through its runtime contract."""
import json
from types import SimpleNamespace

import pytest


def test_build_verifier_uses_full_expected_package_reader(tmp_path, monkeypatch):
    from pc_agent.platform.windows import msi_inventory
    from tools.canary.verify_msi_payload import verify_package
    release = {'schema_version': 'endpoint_windows_release_v1', 'package_sha256': 'a'*64}
    path = tmp_path/'release.json'
    path.write_text(json.dumps(release))
    calls = []
    def read(msi, actual):
        calls.append((msi, actual))
        return SimpleNamespace(identity=SimpleNamespace(version='3.2.1', source_revision='b'*40),
                               foundation_schema=2, foundation_files=tuple(range(12)))
    monkeypatch.setattr(msi_inventory, 'read_expected_package', read)
    result = verify_package(tmp_path/'own.msi', path)
    assert calls == [(tmp_path/'own.msi', release)]
    assert result['foundation_schema'] == 2 and result['foundation_file_count'] == 12


def test_oversized_release_cannot_reach_the_msi_reader(tmp_path, monkeypatch):
    from pc_agent.platform.windows import msi_inventory
    from tools.canary.verify_msi_payload import verify_package
    path = tmp_path/'large.json'
    path.write_bytes(b' ' * 4097)
    monkeypatch.setattr(msi_inventory, 'read_expected_package', lambda *_: pytest.fail('unbounded input'))
    with pytest.raises(ValueError):
        verify_package(tmp_path/'own.msi', path)
