"""Compare an existing release archive with its deployed source payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile


_MAX_ENTRIES = 100_000
_MAX_PAYLOAD_BYTES = 1024**3


def _physical_kind(details: os.stat_result) -> str:
    if getattr(details, "st_file_attributes", 0) & 0x400:
        return "other"
    if stat.S_ISDIR(details.st_mode):
        return "directory"
    if stat.S_ISREG(details.st_mode):
        return "file"
    return "other"


def _identity(details: os.stat_result) -> tuple[int, ...]:
    return details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns


def _archive_entries(stream, root: str) -> tuple[dict[str, tuple], int]:
    entries = {}
    payload_bytes = 0
    with tarfile.open(fileobj=stream, mode="r|gz") as archive:
        for member in archive:
            name = member.name.rstrip("/")
            path = PurePosixPath(name)
            if (
                not path.parts or path.parts[0] != root or path.as_posix() != name
                or "\\" in name or ".." in path.parts
                or any(ord(character) < 32 or character == ":" for character in name)
                or member.type not in {tarfile.DIRTYPE, tarfile.REGTYPE, tarfile.AREGTYPE}
                or member.sparse is not None or member.size < 0
                or (member.isdir() and member.size)
            ):
                raise ValueError("unsafe archive member")
            relative = path.relative_to(root).as_posix()
            if relative in entries or len(entries) >= _MAX_ENTRIES:
                raise ValueError("archive entry limit exceeded or duplicate member")
            payload_bytes += member.size
            if payload_bytes > _MAX_PAYLOAD_BYTES:
                raise ValueError("archive payload limit exceeded")
            if member.isfile():
                with archive.extractfile(member) as source:
                    digest = hashlib.file_digest(source, "sha256").hexdigest()
                entries[relative] = ("file", member.size, digest)
            else:
                entries[relative] = ("directory",)
    if entries.get(".") != ("directory",) or any(
        entries.get(PurePosixPath(name).parent.as_posix()) != ("directory",)
        for name in entries if name != "."
    ):
        raise ValueError("archive has a missing or non-directory parent")
    return entries, payload_bytes


def _compare_tree(release: Path, expected: dict[str, tuple]) -> tuple[list[str], list[str]]:
    mismatches = set(expected) - {"."}
    extras = []
    pending = [release]
    seen = 0
    while pending:
        directory = pending.pop()
        before = directory.lstat()
        if _physical_kind(before) != "directory":
            raise ValueError("deployment tree changed during comparison")
        with os.scandir(directory) as children:
            for child in children:
                seen += 1
                if seen > _MAX_ENTRIES:
                    raise ValueError("deployment tree exceeds entry limit")
                path = Path(child.path)
                name = path.relative_to(release).as_posix()
                entry = expected.get(name)
                if entry is None:
                    extras.append(name)
                    continue
                details = path.lstat()
                if _physical_kind(details) != entry[0]:
                    continue
                if entry[0] == "directory":
                    pending.append(path)
                else:
                    if details.st_size != entry[1]:
                        continue
                    with path.open("rb") as payload:
                        if _identity(os.fstat(payload.fileno())) != _identity(details):
                            raise ValueError("deployed file changed before comparison")
                        digest = hashlib.file_digest(payload, "sha256").hexdigest()
                    if _identity(path.lstat()) != _identity(details):
                        raise ValueError("deployed file changed during comparison")
                    if digest != entry[2]:
                        continue
                mismatches.remove(name)
        if _identity(directory.lstat()) != _identity(before):
            raise ValueError("deployment tree changed during comparison")
    return sorted(mismatches), sorted(extras)


def compare(archive: Path, release: Path) -> dict[str, object]:
    release = release.absolute()
    if _physical_kind(release.lstat()) != "directory" or release.resolve(strict=True) != release:
        raise ValueError("release must be a physical directory")
    before = archive.lstat()
    if _physical_kind(before) != "file" or not 0 < before.st_size <= _MAX_PAYLOAD_BYTES:
        raise ValueError("archive must be a bounded regular file")
    with archive.open("rb") as source:
        if _identity(os.fstat(source.fileno())) != _identity(before):
            raise ValueError("archive changed before comparison")
        archive_digest = hashlib.file_digest(source, "sha256").hexdigest()
        source.seek(0)
        expected, payload_bytes = _archive_entries(source, release.name)
    mismatches, extras = _compare_tree(release, expected)
    if _identity(archive.lstat()) != _identity(before):
        raise ValueError("archive changed during comparison")
    return {
        "release": release.name,
        "archive_sha256": archive_digest,
        "archive_size": before.st_size,
        "archive_entries": len(expected),
        "archive_payload_bytes": payload_bytes,
        "archive_payload_matches": not mismatches,
        "mismatches": mismatches,
        "extra_entries": extras,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("release", type=Path)
    args = parser.parse_args()
    try:
        result = compare(args.archive, args.release)
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.exit(1, f"release payload comparison failed: {error}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["archive_payload_matches"]:
        parser.exit(2)


if __name__ == "__main__":
    main()
