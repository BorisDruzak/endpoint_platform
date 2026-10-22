"""Windows payload resources stay complete while avoiding per-zone MSI files."""
import hashlib
import base64
import importlib.metadata
import json
from pathlib import Path
import runpy
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[2]


def builder():
    from tools.canary.tzdata_payload import build_tzdata_archive
    return build_tzdata_archive


def fake_distribution(root,members):
    from importlib.metadata import FileHash,PackagePath
    files=[]
    for name,content in members.items():
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content)
        item=PackagePath(name)
        item.hash=FileHash('sha256='+base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b'=').decode())
        files.append(item)
    return SimpleNamespace(version='2026.3',files=files,locate_file=lambda name:root/str(name))


def test_archive_preserves_every_package_byte_and_is_deterministic(tmp_path):
    build = builder()
    first = build(tmp_path/'first.zip')
    second = build(tmp_path/'second.zip')
    assert first.read_bytes() == second.read_bytes()
    dist = importlib.metadata.distribution('tzdata')
    expected = {str(p).replace('\\','/'): Path(dist.locate_file(p)).read_bytes()
                for p in dist.files
                if str(p).replace('\\','/').startswith('tzdata/')
                and '__pycache__' not in p.parts and p.suffix != '.pyc'}
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names))
        assert [n for n in names if n.startswith('tzdata/')] == sorted(expected)
        assert all(archive.read(name) == content for name,content in expected.items())
        assert any('/licenses/' in name and name.endswith('LICENSE') for name in names)
        assert all(row.date_time == (1980,1,1,0,0,0) for row in archive.infolist())


def test_wrong_dependency_version_and_existing_foreign_output_fail_closed(tmp_path):
    build = builder()
    with pytest.raises(ValueError,match='version'):
        build(tmp_path/'wrong.zip',expected_version='0.0.0')
    target = tmp_path/'foreign.zip'
    target.write_bytes(b'preserved foreign input')
    with pytest.raises(ValueError,match='existing'):
        build(target)
    assert target.read_bytes() == b'preserved foreign input'


def test_zip_hook_loads_every_zone_without_system_timezone_files(tmp_path):
    archive = builder()(tmp_path/'tzdata-runtime.zip')
    dist = importlib.metadata.distribution('tzdata')
    from datetime import datetime
    from zoneinfo import ZoneInfo
    times = [(2000,1,1,0,0,0),(2026,7,1,0,0,0),(2026,11,1,1,30,0),(2026,11,1,1,30,1)]
    names = Path(dist.locate_file('tzdata/zones')).read_text().splitlines()
    expected = {}
    for name in names:
        with Path(dist.locate_file('tzdata/zoneinfo/'+name)).open('rb') as stream:
            zone = ZoneInfo.from_file(stream,key=name)
        expected[name] = [datetime(*t[:5],tzinfo=zone,fold=t[5]).utcoffset().total_seconds() for t in times]
    source = r'''
import json,runpy,sys,zoneinfo
from datetime import datetime
sys.frozen=True;sys._MEIPASS=sys.argv[1]
runpy.run_path(sys.argv[2])
import tzdata
assert '.zip/' in tzdata.__file__.replace('\\','/')
zoneinfo.reset_tzpath(())
expected=json.load(open(sys.argv[3]))
assert zoneinfo.available_timezones()==set(expected)
times=[(2000,1,1,0,0,0),(2026,7,1,0,0,0),(2026,11,1,1,30,0),(2026,11,1,1,30,1)]
for name,offsets in expected.items():
 z=zoneinfo.ZoneInfo(name)
 assert [datetime(*t[:5],tzinfo=z,fold=t[5]).utcoffset().total_seconds() for t in times]==offsets,name
print('all zones and folds verified')
'''
    oracle=tmp_path/'oracle.json';oracle.write_text(json.dumps(expected))
    result=subprocess.run([sys.executable,'-I','-c',source,str(tmp_path),
        str(ROOT/'pc_agent/runtime_hook_tzdata_zip.py'),str(oracle)],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='all zones and folds verified'


@pytest.mark.parametrize('defect',['absent','invalid'])
def test_frozen_hook_refuses_missing_or_invalid_archive(tmp_path,defect):
    if defect=='invalid':(tmp_path/'tzdata-runtime.zip').write_bytes(b'not a package')
    source="import runpy,sys;sys.frozen=True;sys._MEIPASS=sys.argv[1];runpy.run_path(sys.argv[2])"
    result=subprocess.run([sys.executable,'-I','-c',source,str(tmp_path),
        str(ROOT/'pc_agent/runtime_hook_tzdata_zip.py')],capture_output=True,text=True,timeout=10)
    assert result.returncode==63
    assert result.stderr.strip()=='PROVENANCE_CONFLICT'


def test_analysis_replaces_only_tzdata_modules_and_resources(tmp_path):
    from tools.canary.tzdata_payload import configure_tzdata_archive
    analysis=SimpleNamespace(pure=[('tzdata','old.py','PYMODULE'),('tzdata.zoneinfo','old.py','PYMODULE'),
                                   ('kept.module','kept.py','PYMODULE')],
        datas=[('tzdata/zoneinfo/UTC','old','DATA'),('kept.dat','kept','DATA')])
    configure_tzdata_archive(analysis,tmp_path)
    assert analysis.pure==[('kept.module','kept.py','PYMODULE')]
    assert analysis.datas[0]==('kept.dat','kept','DATA')
    assert analysis.datas[1]==('tzdata-runtime.zip',str(tmp_path/'tzdata-runtime.zip'),'DATA')


def test_resource_archive_rejects_executable_package_source(tmp_path,monkeypatch):
    from tools.canary import tzdata_payload
    root=tmp_path/'input';root.mkdir()
    members={'tzdata/__init__.py':b'import os\nos.system("must never run")',
             'tzdata/zones':b'UTC\n','tzdata-2026.3.dist-info/licenses/LICENSE':b'license'}
    distribution=fake_distribution(root,members)
    monkeypatch.setattr(tzdata_payload.importlib.metadata,'distribution',lambda _:distribution)
    with pytest.raises(ValueError,match='executable'):
        tzdata_payload.build_tzdata_archive(tmp_path/'output.zip')
    assert not (tmp_path/'output.zip').exists()


def test_archive_rejects_changed_dependency_bytes(tmp_path,monkeypatch):
    from tools.canary import tzdata_payload
    root=tmp_path/'input'
    distribution=fake_distribution(root,{'tzdata/__init__.py':b'__version__="2026.3"\nIANA_VERSION="2026c"\n',
        'tzdata/zones':b'UTC\n','tzdata-2026.3.dist-info/licenses/LICENSE':b'license'})
    (root/'tzdata/zones').write_bytes(b'changed after recorded wheel input')
    monkeypatch.setattr(tzdata_payload.importlib.metadata,'distribution',lambda _:distribution)
    with pytest.raises(ValueError,match='hash'):tzdata_payload.build_tzdata_archive(tmp_path/'output.zip')
    assert not (tmp_path/'output.zip').exists()


def test_runtime_hook_does_not_execute_package_before_bootstrap(tmp_path):
    builder()(tmp_path/'tzdata-runtime.zip')
    source="import runpy,sys;sys.frozen=True;sys._MEIPASS=sys.argv[1];runpy.run_path(sys.argv[2]);assert 'tzdata' not in sys.modules"
    result=subprocess.run([sys.executable,'-I','-c',source,str(tmp_path),
        str(ROOT/'pc_agent/runtime_hook_tzdata_zip.py')],capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
