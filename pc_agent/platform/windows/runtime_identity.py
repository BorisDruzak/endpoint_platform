"""Offline validation shared by the fixed Agent host and privileged worker."""
from __future__ import annotations

import re
from pathlib import Path

from .update_paths import UPDATE_EXECUTABLE_NAME, WindowsUpdatePaths

_SEMVER_TRIPLET = re.compile(r'^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$')


def _reject_reparse_chain(root: Path, leaf: Path) -> None:
    try:
        leaf.absolute().relative_to(root.absolute())
    except ValueError as error:
        raise ValueError('selected runtime is outside versions root') from error
    for part in (Path(), *leaf.relative_to(root).parents[::-1], leaf.relative_to(root)):
        candidate = root if part == Path() else root / part
        try:
            details = candidate.lstat()
        except OSError as error:
            raise ValueError('selected runtime is missing') from error
        if candidate.is_symlink() or getattr(details, 'st_file_attributes', 0) & 0x400:
            raise ValueError('selected runtime contains a reparse point')


def validate_runtime_executable(paths: WindowsUpdatePaths, version: str) -> Path:
    if not _SEMVER_TRIPLET.fullmatch(version):
        raise ValueError('selected runtime version is invalid')
    executable = paths.versions_root / version / UPDATE_EXECUTABLE_NAME
    _reject_reparse_chain(paths.versions_root, executable)
    if not executable.is_file():
        raise ValueError('selected runtime executable is missing')
    return executable
