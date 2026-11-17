import hashlib
import json
import zipfile

import pytest

from endpoint_contracts.runtime_payload import PayloadConflict
from tools.release.verify_setup_core_archive import verify_reused_archive


def test_reused_archive_is_bound_to_exact_release_and_runtime(tmp_path):
    root = tmp_path / 'runtime'
    root.mkdir()
    (root / 'pc_agent.exe').write_bytes(b'exact frozen runtime')
    contract = dict(minimum_launcher_version='3.2.158', schema_version=1,
                    source_revision='a' * 40, version='3.2.158')
    (root / 'endpoint-runtime-contract.json').write_text(json.dumps(contract))
    files = [dict(path=p.name, size=p.stat().st_size, sha256=hashlib.sha256(p.read_bytes()).hexdigest())
             for p in sorted(root.iterdir())]
    manifest = dict(schema_version=1, source_revision='a' * 40, version='3.2.158', files=files)
    archive = tmp_path / 'frozen.zip'
    with zipfile.ZipFile(archive, 'w') as bundle:
        for p in root.iterdir():
            bundle.write(p, p.name)
        bundle.writestr('endpoint-update-manifest.json', json.dumps(manifest))
    from endpoint_contracts.runtime_payload import verify_payload
    identity = verify_payload(root, manifest)
    original = hashlib.sha256()
    for name, size, digest in sorted(
            ('endpoint_agent_core.exe' if f.path == 'pc_agent.exe' else f.path, f.size, f.sha256)
            for f in identity.files):
        original.update(f'{name}\0{size}\0{digest}\n'.encode())
    release = dict(version='3.2.158', source_revision='a' * 40,
                   initial_runtime_tree_sha256=original.hexdigest())
    before = archive.read_bytes()
    verify_reused_archive(archive, root, release)
    assert archive.read_bytes() == before
    with pytest.raises(PayloadConflict):
        verify_reused_archive(archive, root, {**release, 'source_revision': 'b' * 40})
    with pytest.raises(PayloadConflict):
        verify_reused_archive(archive, root, {**release, 'initial_runtime_tree_sha256': 'f' * 64})
    (root / 'pc_agent.exe').write_bytes(b'changed frozen runtime')
    with pytest.raises(PayloadConflict):
        verify_reused_archive(archive, root, release)


def test_builder_reuses_verified_core_bytes_instead_of_recompressing():
    from pathlib import Path
    source = (Path(__file__).parents[2] / 'packaging/windows/build-setup.ps1').read_text()
    assert '[string]$ExistingCoreArchive' in source
    assert 'tools.release.verify_setup_core_archive' in source
