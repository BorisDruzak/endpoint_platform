"""Write portable server-only tar headers without changing any payload bytes."""
from __future__ import annotations

import argparse
import gzip
from pathlib import Path, PurePosixPath
import sys
import tarfile


def normalize(source: Path, output: Path, root: str, mtime: int) -> None:
    if not root or '/' in root or '\\' in root or root in {'.', '..'} or mtime < 0:
        raise ValueError('Invalid release root or timestamp')
    with tarfile.open(source, 'r:') as archive:
        members = archive.getmembers()
        names: set[str] = set()
        directories: set[str] = set()
        for member in members:
            path = PurePosixPath(member.name)
            name = member.name.rstrip('/')
            if (path.is_absolute() or '..' in path.parts or '\\' in name
                    or not path.parts or path.parts[0] != root
                    or path.as_posix() != name or name in names
                    or not (member.isfile() or member.isdir()) or member.size < 0):
                raise ValueError('Unsafe or duplicate server archive member')
            names.add(name)
            if member.isdir():
                directories.add(name)
        if root not in directories:
            raise ValueError('Release root must be an explicit directory')
        for name in names:
            if any(str(parent) not in directories for parent in PurePosixPath(name).parents
                   if str(parent) != '.'):
                raise ValueError('Missing or non-directory archive parent')
        # Exclusive creation preserves every earlier qualified archive. Fresh
        # TarInfo objects discard native/PAX permission and ownership overrides.
        with output.open('xb') as raw:
            with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=mtime, compresslevel=9) as zipped:
                with tarfile.open(fileobj=zipped, mode='w', format=tarfile.PAX_FORMAT) as target:
                    for member in sorted(members, key=lambda item: item.name):
                        safe = tarfile.TarInfo(member.name.rstrip('/'))
                        safe.type = tarfile.DIRTYPE if member.isdir() else tarfile.REGTYPE
                        safe.mode = 0o755 if member.isdir() else 0o644
                        safe.uid = safe.gid = 0
                        safe.uname = safe.gname = 'root'
                        safe.mtime = mtime
                        safe.size = 0 if member.isdir() else member.size
                        if member.isfile():
                            with archive.extractfile(member) as payload:
                                target.addfile(safe, payload)
                        else:
                            target.addfile(safe)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--root', required=True)
    parser.add_argument('--mtime', type=int, required=True)
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12):
        parser.error('Use the repository-supported Python3.12 interpreter')
    normalize(args.input, args.output, args.root, args.mtime)


if __name__ == '__main__':
    main()
