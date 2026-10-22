"""Shared data preserve bytes and separate executable Python closures."""
import hashlib
import zipfile
import ast
from pathlib import Path

import pytest


def distribution(root, name, *, dll=b'dll', member='os.pyc', content=b'pyc'):
    folder = root / name / '_foundation-runtime'
    folder.mkdir(parents=True)
    (folder / 'python312.dll').write_bytes(dll)
    with zipfile.ZipFile(folder / 'base_library.zip', 'w') as archive:
        archive.writestr(member, content)
    return folder.parent


def test_merge_shares_only_identical_dependencies_and_unions_stdlib(tmp_path):
    from tools.canary.foundation_payload import merge_dependencies
    a = distribution(tmp_path, 'a')
    b = distribution(tmp_path, 'b', member='json.pyc')
    (a / 'entry.exe').write_bytes(b'independent PYZ a')
    (b / 'entry.exe').write_bytes(b'independent PYZ b')
    output = tmp_path / 'out'
    rows = merge_dependencies([a, b], output)
    assert {row['path'] for row in rows} == {
        '_foundation-runtime/python312.dll', '_foundation-runtime/base_library.zip'}
    assert not (output / 'entry.exe').exists()
    assert (output / '_foundation-runtime/python312.dll').read_bytes() == b'dll'
    with zipfile.ZipFile(output / '_foundation-runtime/base_library.zip') as archive:
        assert set(archive.namelist()) == {'os.pyc', 'json.pyc'}
        assert archive.read('os.pyc') == b'pyc'
    for row in rows:
        assert row['sha256'] == hashlib.sha256((output / row['path']).read_bytes()).hexdigest()


@pytest.mark.parametrize('conflict', ['dll', 'stdlib', 'alias', 'link'])
def test_dependency_conflicts_fail_before_publication(tmp_path, conflict):
    from tools.canary.foundation_payload import merge_dependencies
    a = distribution(tmp_path, 'a')
    b = distribution(tmp_path, 'b', dll=b'wrong' if conflict == 'dll' else b'dll',
                     content=b'wrong' if conflict == 'stdlib' else b'pyc')
    if conflict == 'alias':
        (b / '_foundation-runtime/python312.dll').rename(b / '_foundation-runtime/PYTHON312.DLL')
    if conflict == 'link':
        import os
        os.link(b / '_foundation-runtime/python312.dll', b / '_foundation-runtime/link.dll')
    output = tmp_path / 'out'
    with pytest.raises(ValueError):
        merge_dependencies([a, b], output)
    assert not output.exists()


@pytest.mark.parametrize('name', ['launcher_win', 'windows_service_launcher',
    'windows_provision', 'windows_user_sensor', 'windows_browser_bridge',
    'windows_browser_policy_service'])
def test_shared_specs_keep_independent_code_and_external_data(name):
    root = Path(__file__).resolve().parents[2]
    tree = ast.parse((root / 'pc_agent' / ('pyinstaller_' + name + '.spec')).read_text())
    exe = next(n for n in ast.walk(tree) if isinstance(n, ast.Call)
               and isinstance(n.func, ast.Name) and n.func.id == 'EXE')
    options = {k.arg: ast.literal_eval(k.value) for k in exe.keywords}
    assert options['exclude_binaries'] is True
    assert options['contents_directory'] == '_foundation-runtime'
    assert not any(isinstance(n, ast.Attribute) and n.attr in ('binaries', 'datas', 'zipfiles')
                   for n in exe.args)
    assert any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
               and n.func.id == 'COLLECT' for n in ast.walk(tree))


def test_shared_native_binding_preserves_self_contained_installer_and_offline_updater():
    root = Path(__file__).resolve().parents[2]
    package = (root / 'packaging/windows/wix/Package.wxs').read_text()
    build = (root / 'packaging/windows/build-msi.ps1').read_text()
    assert 'SourceFile="$(var.InstallerHostPath)"' in package
    assert 'EndpointAgentSharedFoundation' in package
    assert 'pyinstaller_windows_installer_host.spec' in build
    assert 'tools.canary.foundation_payload' in build
    assert 'schema_version = 2' in build
    updater = (root / 'pc_agent/pyinstaller_windows_updater.spec').read_text()
    assert 'COLLECT(' not in updater
