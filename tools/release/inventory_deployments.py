"""Report deployed release storage and the paths named by rollback controls."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat


_RELEASE_NAME = re.compile(r"endpoint-platform-[0-9a-f]{12}(?:-[a-z0-9]+)*")
_COMMIT = re.compile(r"[0-9a-f]{12}")
_MAX_ENTRIES = 1_000_000
_MARKER_LIMIT = 4096
_REPARSE_POINT = 0x400
_MINIMUM_FREE_BYTES = 10 * 1024**3


def _physical_directory(details: os.stat_result) -> bool:
    return stat.S_ISDIR(details.st_mode) and not getattr(details, "st_file_attributes", 0) & _REPARSE_POINT


def _release_root_details(root: Path) -> os.stat_result:
    details = root.lstat()
    if not _physical_directory(details) or root.resolve(strict=True) != root:
        raise ValueError("releases root must be a physical directory")
    return details


def _volume_space(root: Path) -> dict[str, int | bool]:
    space = shutil.disk_usage(root)
    return {
        "volume_free_bytes": space.free,
        "volume_total_bytes": space.total,
        "minimum_free_bytes": _MINIMUM_FREE_BYTES,
        "release_space_ready": space.free >= _MINIMUM_FREE_BYTES,
    }


def read_release_space(root: Path) -> dict[str, int | bool]:
    root = root.absolute()
    _release_root_details(root)
    return _volume_space(root)


def read_deployed_release_space(source_root: Path) -> dict[str, int | bool] | None:
    """Check release volume space when running from a versioned deployment."""
    release = source_root.resolve()
    if release.parent.name == "releases" and _RELEASE_NAME.fullmatch(release.name):
        return read_release_space(release.parent)
    return None


def _identity(details: os.stat_result) -> tuple:
    return details.st_dev, details.st_ino, details.st_mtime_ns, details.st_size


def _read_marker(marker: Path) -> str:
    details = marker.lstat()
    if (
        not stat.S_ISREG(details.st_mode)
        or getattr(details, "st_file_attributes", 0) & _REPARSE_POINT
        or details.st_size > _MARKER_LIMIT
    ):
        raise ValueError("deployment marker must be a bounded regular file")
    with marker.open("rb") as stream:
        if _identity(os.fstat(stream.fileno())) != _identity(details):
            raise ValueError("deployment marker changed while opening")
        raw = stream.read(_MARKER_LIMIT + 1)
        if len(raw) != details.st_size or _identity(os.fstat(stream.fileno())) != _identity(details):
            raise ValueError("deployment marker changed while reading")
    value = raw.decode("utf-8").removesuffix("\n")
    if not value or any(ord(character) < 32 for character in value):
        raise ValueError("deployment marker must contain a single nonempty value")
    return value


def _release_target(root: Path, target: Path) -> str:
    if ".." in target.parts:
        raise ValueError("deployment pointer must name a direct release directory")
    target = Path(os.path.abspath(target))
    if target.parent != root or not _RELEASE_NAME.fullmatch(target.name):
        raise ValueError("deployment pointer must name a direct release directory")
    if not _physical_directory(target.lstat()):
        raise ValueError("deployment pointer must name a physical release directory")
    return target.name


def _pointers(root: Path, current: Path, previous: Path) -> tuple[str, str | None]:
    target = _release_target(root, current.parent / current.readlink())
    try:
        rollback = Path(_read_marker(previous))
    except FileNotFoundError:
        # An initial installation may have no rollback marker.
        return target, None
    if not rollback.is_absolute():
        raise ValueError("previous release marker must contain one absolute path")
    return target, _release_target(root, rollback)


def _staged_commit(staged: Path | None) -> str | None:
    if staged is None:
        return None
    try:
        commit = _read_marker(staged)
    except FileNotFoundError:
        return None
    if not _COMMIT.fullmatch(commit):
        raise ValueError("release-commit marker must contain a 12-character commit")
    return commit


def _release_reference(root: Path, value: str) -> str | None:
    path = Path(value)
    if not path.is_absolute():
        return None
    try:
        name, *_ = path.relative_to(root).parts
    except ValueError:
        return None
    return name if _RELEASE_NAME.fullmatch(name) else None


def _readlink(path: Path) -> str:
    value = os.fspath(path.readlink())
    return value.removeprefix("\\\\?\\") if os.name == "nt" else value


def _scan_processes(root: Path, proc: Path) -> tuple[dict[str, set[int]], list[int]]:
    """Attribute live paths without returning command lines or proc contents."""
    references: dict[str, set[int]] = {}
    incomplete = set()
    remaining = _MAX_ENTRIES

    def observe(value: str, pid: int) -> None:
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            raise ValueError("process references exceed inventory limit")
        name = _release_reference(root, value.removesuffix(" (deleted)"))
        if name is not None:
            references.setdefault(name, set()).add(pid)

    def observe_link(link: Path, pid: int) -> None:
        try:
            observe(_readlink(link), pid)
        except FileNotFoundError:
            pass  # The descriptor or process has already exited.
        except OSError:
            incomplete.add(pid)

    with os.scandir(proc) as processes:
        for entry in processes:
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            pid = int(entry.name)
            process = Path(entry.path)
            observe_link(process / "cwd", pid)
            observe_link(process / "exe", pid)
            try:
                with os.scandir(process / "fd") as descriptors:
                    for descriptor in descriptors:
                        observe_link(Path(descriptor.path), pid)
            except FileNotFoundError:
                pass
            except OSError:
                incomplete.add(pid)
            try:
                with (process / "maps").open(encoding="utf-8", errors="surrogateescape") as mappings:
                    for line in mappings:
                        fields = line.rstrip("\n").split(maxsplit=5)
                        observe(fields[5] if len(fields) == 6 else "", pid)
            except FileNotFoundError:
                pass
            except OSError:
                incomplete.add(pid)
    return references, sorted(incomplete)


def _measure(root: Path, volume: int, remaining: int) -> tuple[int, int, int, set[str]]:
    """Count apparent regular-file bytes without traversing links or mounts."""
    physical = root.lstat()
    if not _physical_directory(physical) or physical.st_dev != volume:
        return 0, 1, remaining, set()
    directories = [root]
    dependencies = set()
    total = unmeasured = 0
    while directories:
        directory = directories.pop()
        before = directory.lstat()
        if not _physical_directory(before) or before.st_dev != volume:
            raise ValueError("release directory changed during inventory")
        with os.scandir(directory) as entries:
            for entry in entries:
                remaining -= 1
                if remaining < 0:
                    raise ValueError("release directories exceed inventory limit")
                # Windows DirEntry.stat does not populate st_dev.
                details = os.lstat(entry.path) if os.name == "nt" else entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(details.st_mode) or getattr(details, "st_file_attributes", 0) & _REPARSE_POINT:
                    unmeasured += 1
                    path = Path(entry.path)
                    if stat.S_ISLNK(details.st_mode) or path.is_junction():
                        destination = os.path.abspath(directory / _readlink(path))
                        name = _release_reference(root.parent, destination)
                        if name is not None and name != root.name:
                            dependencies.add(name)
                elif details.st_dev != volume:
                    unmeasured += 1
                elif stat.S_ISDIR(details.st_mode):
                    directories.append(Path(entry.path))
                elif stat.S_ISREG(details.st_mode):
                    total += details.st_size
                else:
                    unmeasured += 1
        if _identity(directory.lstat()) != _identity(before):
            raise ValueError("release directory changed during inventory")
    return total, unmeasured, remaining, dependencies


def _add_dependency_protection(rows: dict) -> list[str]:
    """Preserve dependencies of every protected release, including cycles."""
    queue = [name for name, row in rows.items() if row["protected_by"]]
    visited = set(queue)
    required = set()
    while queue:
        for name in rows[queue.pop()]["release_dependencies"]:
            required.add(name)
            if name in rows and name not in visited:
                visited.add(name)
                queue.append(name)
    for name in required & rows.keys():
        rows[name]["protected_by"].append("release_dependency")
    return sorted(required - rows.keys())


def read_inventory(
    root: Path, current: Path, previous: Path, *, pins: list[str] | None = None,
    staged: Path | None = None, proc: Path | None = None,
) -> dict[str, object]:
    root = root.absolute()
    root_details = _release_root_details(root)
    active, rollback = _pointers(root, current, previous)
    commit = _staged_commit(staged)
    if pins and not all(_RELEASE_NAME.fullmatch(pin) for pin in pins):
        raise ValueError("pins must be exact release directory names")
    pinned = {_release_target(root, root / pin) for pin in pins or ()}
    rows, unclassified = {}, []
    remaining = _MAX_ENTRIES
    with os.scandir(root) as entries:
        for entry in entries:
            remaining -= 1
            if remaining < 0:
                raise ValueError("release directories exceed inventory limit")
            details = entry.stat(follow_symlinks=False)
            name = entry.name
            if not _RELEASE_NAME.fullmatch(name) or not _physical_directory(details):
                unclassified.append(name)
                continue
            size, unmeasured, remaining, dependencies = _measure(Path(entry.path), root_details.st_dev, remaining)
            rows[name] = {
                "name": name, "regular_file_bytes": size,
                "unmeasured_entries": unmeasured,
                "release_dependencies": sorted(dependencies),
            }
    references, incomplete = _scan_processes(root, proc) if proc is not None else ({}, [])
    for name, row in rows.items():
        pids = sorted(references.get(name, ()))
        row["protected_by"] = [
            reason for reason, selected in (
                ("current", name == active), ("previous", name == rollback), ("pin", name in pinned),
                ("staged", commit is not None and name.split("-")[2] == commit), ("process", bool(pids)),
            ) if selected
        ]
        row["process_ids"] = pids
    missing_dependencies = _add_dependency_protection(rows)
    if (
        _pointers(root, current, previous) != (active, rollback)
        or _staged_commit(staged) != commit
        or _identity(root.lstat()) != _identity(root_details)
    ):
        raise ValueError("deployment pointers changed during inventory")
    return {
        "current": active,
        "previous": rollback,
        "staged_commit": commit,
        "process_scan_performed": proc is not None,
        "process_scan_incomplete_pids": incomplete,
        "releases": [rows[name] for name in sorted(rows)],
        "missing_release_dependencies": missing_dependencies,
        "unclassified_entries": sorted(unclassified),
        **_volume_space(root),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--releases-root", type=Path, default=Path("/opt/endpoint-platform/releases"))
    parser.add_argument("--current", type=Path, default=Path("/opt/endpoint-platform/current"))
    parser.add_argument("--previous-release", type=Path, default=Path("/etc/endpoint-platform/previous-release"))
    parser.add_argument("--release-commit", type=Path, default=Path("/etc/endpoint-platform/release-commit"))
    parser.add_argument("--proc-root", type=Path, default=Path("/proc") if os.name == "posix" else None)
    parser.add_argument("--pin", action="append", default=[], metavar="RELEASE_DIRECTORY")
    parser.add_argument(
        "--check-release-space", action="store_true",
        help="check the release volume without scanning deployments; exit 2 below 10 GiB",
    )
    args = parser.parse_args()
    try:
        if args.check_release_space:
            inventory = read_release_space(args.releases_root)
        else:
            inventory = read_inventory(
                args.releases_root, args.current, args.previous_release,
                pins=args.pin, staged=args.release_commit, proc=args.proc_root,
            )
    except (OSError, ValueError) as error:
        parser.exit(1, f"deployment storage inventory failed: {error}\n")
    print(json.dumps(inventory, indent=2, sort_keys=True))
    if args.check_release_space and not inventory["release_space_ready"]:
        parser.exit(2)


if __name__ == "__main__":
    main()
