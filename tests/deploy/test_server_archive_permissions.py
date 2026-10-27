"""Server archives must retain payload bytes with portable safe tar headers."""
from __future__ import annotations

import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import pytest


REPO = Path(__file__).resolve().parents[2]
HELPER = REPO / 'tools/release/normalize_server_archive.py'


def archive_contents(path: Path):
    with tarfile.open(path) as archive:
        return [(m.name, m.mode, m.uid, m.gid, m.uname, m.gname,
                 archive.extractfile(m).read() if m.isfile() else None)
                for m in archive]


@pytest.mark.skipif(sys.platform != 'win32', reason='Actual Windows PowerShell/bsdtar producer regression')
def test_actual_windows_producer_has_safe_headers_and_identical_payload(tmp_path):
    fixture = tmp_path / 'repo'
    fixture.mkdir()
    names = ['endpoint_server/__init__.py', 'endpoint_contracts/__init__.py',
             'browser_sensor/manifest.json', 'alembic.ini', 'requirements-server.txt',
             'tools/__init__.py', 'tools/register_windows_setup_release.py',
             'tools/register_browser_sensor_release.py', 'webapp/dist/index.html',
             'webapp/dist/assets/app.js']
    expected = {}
    for name in names:
        path = fixture / name
        path.parent.mkdir(parents=True, exist_ok=True)
        expected[name] = (name + '\nUTF8:\u0442\u0435\u0441\u0442\n').encode()
        path.write_bytes(expected[name])
    release = fixture / 'tools/release'
    release.mkdir()
    shutil.copy2(REPO / 'tools/release/build_console_server_archive.ps1', release)
    if HELPER.exists():
        shutil.copy2(HELPER, release)
    for args in [['git', 'init', '-q'], ['git', 'config', 'core.autocrlf', 'false'], ['git', 'add', '.'],
                 ['git', '-c', 'user.name=Archive Test', '-c', 'user.email=archive@example.invalid',
                  'commit', '-qm', 'test fixture']]:
        subprocess.run(args, cwd=fixture, check=True, capture_output=True)
    outputs = []
    for index in range(2):
        output = tmp_path / f'release-{index}.tar.gz'
        env = os.environ | {'SERVER_ARCHIVE_TEST_SCRIPT': str(release / 'build_console_server_archive.ps1'),
                            'SERVER_ARCHIVE_TEST_OUTPUT': str(output),
                            'SERVER_ARCHIVE_TEST_PYTHON': sys.executable}
        # Only the independent Console build is a no-op; actual Git, Windows tar,
        # source staging, PowerShell producer and final archive writer all run.
        command = ("function global:npm { $global:LASTEXITCODE=0 }; "
                   "function global:python { & $env:SERVER_ARCHIVE_TEST_PYTHON @args }; "
                   "& $env:SERVER_ARCHIVE_TEST_SCRIPT -OutputPath $env:SERVER_ARCHIVE_TEST_OUTPUT")
        subprocess.run(['pwsh', '-NoProfile', '-Command', command], env=env,
                       check=True, capture_output=True, text=True)
        contents = archive_contents(output)
        assert {row[1] for row in contents if row[-1] is not None} == {0o644}
        assert {row[1] for row in contents if row[-1] is None} == {0o755}
        assert all(row[2:6] == (0, 0, 'root', 'root') for row in contents)
        payload = {'/'.join(row[0].split('/')[1:]): row[-1] for row in contents if row[-1] is not None}
        assert payload == expected
        outputs.append(output.read_bytes())
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize('unsafe', ['../outside', '/absolute', 'release/../outside', 'release/link', 'duplicate'])
def test_normalizer_rejects_unsafe_input_without_replacing_output(tmp_path, unsafe):
    source = tmp_path / 'input.tar'
    with tarfile.open(source, 'w') as archive:
        root = tarfile.TarInfo('release')
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        member = tarfile.TarInfo('release/file' if unsafe == 'duplicate' else unsafe)
        member.type = tarfile.SYMTYPE if unsafe == 'release/link' else tarfile.REGTYPE
        member.linkname = '/outside' if member.issym() else ''
        member.size = 0
        archive.addfile(member, io.BytesIO())
        if unsafe == 'duplicate':
            archive.addfile(member, io.BytesIO())
    output = tmp_path / 'output.tar.gz'
    result = subprocess.run([sys.executable, str(HELPER), '--input', str(source),
                             '--output', str(output), '--root', 'release', '--mtime', '1'],
                            capture_output=True)
    assert result.returncode != 0
    assert not output.exists()


def test_normalizer_never_overwrites_an_existing_qualified_output(tmp_path):
    source = tmp_path / 'input.tar'
    with tarfile.open(source, 'w') as archive:
        root = tarfile.TarInfo('release')
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
    output = tmp_path / 'output.tar.gz'
    output.write_bytes(b'preserve existing qualified bytes')
    result = subprocess.run([sys.executable, str(HELPER), '--input', str(source),
                             '--output', str(output), '--root', 'release', '--mtime', '1'],
                            capture_output=True)
    assert result.returncode != 0
    assert output.read_bytes() == b'preserve existing qualified bytes'
