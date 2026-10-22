"""Build-time Windows resource packing; never imported by installed agents."""
from __future__ import annotations

import ast
import base64
import hashlib
import importlib.metadata
import io
from pathlib import Path, PurePosixPath
import stat
import zipfile

TZDATA_VERSION = '2026.3'
ARCHIVE_NAME = 'tzdata-runtime.zip'
_LIMIT = 16 * 1024 * 1024


def _validate_package_source(name: str, content: bytes, version: str) -> None:
    if not name.endswith('.py'):
        return
    if not name.endswith('/__init__.py'):
        raise ValueError('executable timezone package source is not permitted')
    observed = {}
    for node in ast.parse(content).body:
        if isinstance(node,ast.Expr) and isinstance(node.value,ast.Constant) and isinstance(node.value.value,str):
            continue
        if (name == 'tzdata/__init__.py' and isinstance(node,ast.Assign) and len(node.targets)==1
                and isinstance(node.targets[0],ast.Name) and node.targets[0].id in {'__version__','IANA_VERSION'}
                and isinstance(node.value,ast.Constant) and isinstance(node.value.value,str)
                and node.targets[0].id not in observed):
            observed[node.targets[0].id] = node.value.value
            continue
        raise ValueError('executable timezone package source is not permitted')
    if name == 'tzdata/__init__.py' and (observed.get('__version__') != version or not observed.get('IANA_VERSION')):
        raise ValueError('timezone package source version differs from pinned input')


def build_tzdata_archive(output: Path, *, expected_version: str = TZDATA_VERSION) -> Path:
    distribution = importlib.metadata.distribution('tzdata')
    if distribution.version != expected_version:
        raise ValueError('tzdata dependency version differs from the pinned input')
    members = {}
    metadata_prefix = f'tzdata-{expected_version}.dist-info/'
    for item in distribution.files or ():
        name = item.as_posix()
        if '__pycache__' in item.parts or item.suffix == '.pyc':
            continue
        if not (name.startswith('tzdata/') or
                (name.startswith(metadata_prefix) and
                 ('/licenses/' in name or name.endswith('/METADATA')))):
            continue
        if ('..' in PurePosixPath(name).parts or ':' in name or '\\' in name
                or name.startswith('/') or name in members):
            raise ValueError('invalid timezone resource namespace')
        source = Path(distribution.locate_file(item))
        before = source.lstat()
        if (not stat.S_ISREG(before.st_mode) or source.is_symlink()
                or getattr(before, 'st_file_attributes', 0) & 0x400):
            raise ValueError('timezone resource is not an ordinary file')
        content = source.read_bytes()
        after = source.lstat()
        if ((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) !=
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)
                or len(content) != before.st_size or len(content) > _LIMIT):
            raise ValueError('timezone resource changed during packing')
        recorded_hash = getattr(item,'hash',None)
        actual_hash = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b'=').decode()
        if not recorded_hash or recorded_hash.mode != 'sha256' or recorded_hash.value != actual_hash:
            raise ValueError('timezone resource differs from its recorded wheel hash')
        _validate_package_source(name,content,expected_version)
        members[name] = content
    if (not {'tzdata/__init__.py','tzdata/zones'} <= members.keys()
            or not any('/licenses/' in name and name.endswith('LICENSE') for name in members)
            or sum(map(len,members.values())) > _LIMIT):
        raise ValueError('incomplete or oversized timezone distribution')
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, content in sorted(members.items()):
            entry = zipfile.ZipInfo(name, date_time=(1980,1,1,0,0,0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o444) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, content, compresslevel=9)
    content = stream.getvalue()
    output = Path(output)
    if output.exists() or output.is_symlink():
        if output.is_symlink() or not output.is_file() or output.read_bytes() != content:
            raise ValueError('existing timezone archive differs from pinned input')
        return output
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as target:
        target.write(content)
    return output


def configure_tzdata_archive(analysis, workpath: Path) -> None:
    """Use one hashed payload file without retaining a competing PYZ package."""
    archive = build_tzdata_archive(Path(workpath)/ARCHIVE_NAME)
    analysis.pure = [entry for entry in analysis.pure
                     if entry[0] != 'tzdata' and not entry[0].startswith('tzdata.')]
    analysis.datas = [entry for entry in analysis.datas
                      if not entry[0].replace('\\','/').startswith(('tzdata/','tzdata-'))]
    analysis.datas.append((ARCHIVE_NAME,str(archive),'DATA'))
