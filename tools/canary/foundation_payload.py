"""Build an authenticated shared DLL/data tree without merging PYZ code."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import zipfile
from xml.sax.saxutils import escape

from endpoint_contracts.runtime_payload import reject_reparse_ancestors, safe_path
from pc_agent.platform.windows.foundation_layout import SHARED_DIRECTORY, shared_binding


def merge_dependencies(distributions, output):
    """Validate all inputs before creating a fresh output tree."""
    output = Path(output)
    if output.exists():
        raise ValueError('shared Foundation destination already exists')
    reject_reparse_ancestors(output.parent)
    payload, aliases, stdlib, stdlib_aliases = {}, {}, {}, {}
    for distribution in distributions:
        root = Path(distribution) / SHARED_DIRECTORY
        reject_reparse_ancestors(root)
        if not root.is_dir():
            raise ValueError('shared Foundation input missing')
        local_aliases = set()
        for folder, directories, files in os.walk(root, followlinks=False):
            reject_reparse_ancestors(Path(folder))
            for directory in directories:
                reject_reparse_ancestors(Path(folder) / directory)
            for leaf in files:
                path = Path(folder) / leaf
                reject_reparse_ancestors(path)
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError('ambiguous shared Foundation input')
                relative = safe_path(path.relative_to(root).as_posix())
                alias = relative.casefold()
                if alias in local_aliases or (alias in aliases and aliases[alias] != relative):
                    raise ValueError('shared Foundation path alias')
                local_aliases.add(alias)
                aliases[alias] = relative
                data = path.read_bytes()
                if relative == 'base_library.zip':
                    with zipfile.ZipFile(path) as archive:
                        member_aliases = set()
                        for member in archive.infolist():
                            name = safe_path(member.filename)
                            folded = name.casefold()
                            if (member.is_dir() or folded in member_aliases
                                or (folded in stdlib_aliases and stdlib_aliases[folded] != name)):
                                raise ValueError('stdlib member alias')
                            member_aliases.add(folded)
                            stdlib_aliases[folded] = name
                            content = archive.read(member)
                            if name in stdlib and stdlib[name] != content:
                                raise ValueError('different shared stdlib bytes')
                            stdlib[name] = content
                else:
                    if relative in payload and payload[relative] != data:
                        raise ValueError('different shared dependency bytes')
                    payload[relative] = data
    if not stdlib or 'python312.dll' not in payload:
        raise ValueError('incomplete shared Foundation runtime')
    import io
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(stdlib.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    payload['base_library.zip'] = buffer.getvalue()
    rows = []
    output.mkdir()
    for relative, data in sorted(payload.items()):
        name = SHARED_DIRECTORY + '/' + relative
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        file, component = shared_binding(name)
        rows.append(dict(path=name, file=file, component=component, size=len(data),
                         sha256=hashlib.sha256(data).hexdigest()))
    return rows


def wix_fragment(rows):
    directories = {str(parent).replace('\\', '/') for row in rows
                   for parent in Path(row['path']).parents if str(parent) != '.'}
    def directory_id(name):
        return 'dirFoundation_' + hashlib.sha256(name.casefold().encode()).hexdigest()[:20]
    result = ['<?xml version="1.0" encoding="utf-8"?>',
              '<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"><Fragment>']
    for name in sorted(directories):
        parent = Path(name).parent.as_posix()
        parent_id = 'INSTALLFOLDER' if parent == '.' else directory_id(parent)
        result.append(f'<DirectoryRef Id="{parent_id}"><Directory Id="{directory_id(name)}" Name="{escape(Path(name).name)}" /></DirectoryRef>')
    result.append('<ComponentGroup Id="EndpointAgentSharedFoundation">')
    removed = set()
    for row in rows:
        name = row['path']
        parent = Path(name).parent.as_posix()
        source = '$(var.StagingDir)\\ProgramFiles\\' + name.replace('/', '\\')
        result.append(f'<Component Id="{row["component"]}" Directory="{directory_id(parent)}" Guid="*" Bitness="always64"><File Id="{row["file"]}" Source="{escape(source)}" KeyPath="yes" />')
        for directory in sorted(directories):
            if directory not in removed:
                removed.add(directory)
                result.append(f'<RemoveFolder Id="rm{directory_id(directory)}" Directory="{directory_id(directory)}" On="uninstall" />')
        result.append('</Component>')
    result.append('</ComponentGroup></Fragment></Wix>')
    return '\n'.join(result) + '\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--distribution', action='append', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--wix', type=Path, required=True)
    args = parser.parse_args()
    rows = merge_dependencies(args.distribution, args.output)
    args.inventory.write_text(json.dumps(rows, separators=(',', ':')), encoding='utf-8')
    args.wix.write_text(wix_fragment(rows), encoding='utf-8')


if __name__ == '__main__':
    main()
