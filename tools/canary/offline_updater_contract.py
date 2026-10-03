"""Fail release packaging if the privileged worker retains network capabilities."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from collections.abc import Iterable

FORBIDDEN_MODULES = (
    'socket', '_socket', 'ssl', '_ssl', 'http', 'urllib.request', 'urllib.error',
    'aiohttp', 'httpx', 'requests', 'websockets', 'asyncio', '_asyncio',
    'multiprocessing',
)


def assert_offline_modules(names: Iterable[str]) -> None:
    forbidden = []
    for name in names:
        leaf = name.replace('\\', '/').rsplit('/', 1)[-1].lower()
        if any(name == p or name.startswith(p + '.') or leaf == p
               or leaf.startswith(p + '.') for p in FORBIDDEN_MODULES):
            forbidden.append(name)
        elif leaf.startswith('libssl') and leaf.endswith('.dll'):
            forbidden.append(name)
    if forbidden:
        raise ValueError('Offline updater retains network capabilities: ' + ', '.join(sorted(forbidden)))


def inspect_archive(path: Path) -> dict[str, object]:
    from PyInstaller.archive.readers import CArchiveReader
    archive = CArchiveReader(str(path))
    names = list(archive.toc)
    python_modules = []
    for name in archive.toc:
        if name.endswith('.pyz'):
            python_modules.extend(archive.open_embedded_archive(name).toc)
    if not python_modules:
        raise ValueError('Offline updater has no inspectable Python archive')
    assert_offline_modules([*names, *python_modules])
    return {'schema_version': 1, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'networkless_static_passed': True, 'python_modules': sorted(python_modules),
            'archive_members': sorted(names)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('executable', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = inspect_archive(args.executable)
    serialized = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(serialized + '\n', encoding='utf-8')
    else:
        print(serialized)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
