#!/usr/bin/env python3
"""Assemble a deterministic local release artifact for the Linux headless agent."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path
from typing import NamedTuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = PROJECT_ROOT / "dist" / "endpoint-agent"
PLATFORM = "linux_amd64"
ARCHIVE_TYPE = "tar.gz"
MANIFEST_SCHEMA = "endpoint_linux_agent_artifact_v1"

_SEMVER_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
_REVISION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
_BASE_LIBRARY_ARCHIVE_PATH = "endpoint-agent/_internal/base_library.zip"
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


class _PayloadEntry(NamedTuple):
    source: Path
    relative: Path
    mode: int
    is_directory: bool


def _normalized_payload_mode(relative: Path, source_mode: int, *, is_directory: bool = False) -> int:
    """Accept only safe source permissions and emit the immutable archive mode."""
    source_mode = stat.S_IMODE(source_mode)
    if source_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        raise ValueError(f"unsafe artifact mode: {relative.as_posix()}")
    if is_directory:
        return 0o755
    if source_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"unsafe artifact mode: {relative.as_posix()}")
    if relative.as_posix() == "endpoint-agent":
        if not source_mode & 0o111:
            raise ValueError("headless core executable is not executable")
        return 0o755
    if source_mode & 0o111:
        raise ValueError(f"non-entrypoint payload must not be executable: {relative.as_posix()}")
    return 0o644


def _read_agent_version() -> str:
    version_path = PROJECT_ROOT / "pc_agent" / "version.py"
    match = re.search(
        r'^AGENT_VERSION\s*=\s*["\']([^"\']+)["\']',
        version_path.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if match is None:
        raise ValueError("could not read AGENT_VERSION")
    return match.group(1)


def _source_revision() -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, text=True
    ).strip()


def _validate_identifiers(version: str, revision: str) -> None:
    if len(version) > 64 or _SEMVER_PATTERN.fullmatch(version) is None:
        raise ValueError("version must be a bounded semantic version")
    if _REVISION_PATTERN.fullmatch(revision) is None:
        raise ValueError("source revision must be a bounded identifier")


def _payload_entries(source: Path) -> list[_PayloadEntry]:
    if source.is_symlink() or not source.is_dir():
        raise ValueError("Linux artifact source must be a regular directory")
    executable = source / "endpoint-agent"
    if executable.is_symlink() or not executable.is_file():
        raise ValueError("headless core executable is missing")
    _normalized_payload_mode(Path("endpoint-agent"), executable.lstat().st_mode)

    resolved_root = source.resolve(strict=True)
    entries = [
        _PayloadEntry(
            source=source,
            relative=Path("endpoint-agent"),
            mode=_normalized_payload_mode(Path("."), source.lstat().st_mode, is_directory=True),
            is_directory=True,
        )
    ]

    def visit(directory: Path) -> None:
        for entry in sorted(directory.iterdir(), key=lambda item: item.name):
            relative_source = entry.relative_to(source)
            archive_relative = Path("endpoint-agent") / relative_source
            entry_mode = entry.lstat().st_mode
            if stat.S_ISLNK(entry_mode):
                try:
                    target = entry.resolve(strict=True)
                    target.relative_to(resolved_root)
                except (OSError, RuntimeError, ValueError) as error:
                    raise ValueError(
                        f"artifact link escapes the source: {relative_source.as_posix()}"
                    ) from error
                target_mode = target.lstat().st_mode
                if not stat.S_ISREG(target_mode):
                    raise ValueError(
                        f"artifact link does not resolve to a regular file: "
                        f"{relative_source.as_posix()}"
                    )
                entries.append(
                    _PayloadEntry(
                        source=target,
                        relative=archive_relative,
                        mode=_normalized_payload_mode(relative_source, target_mode),
                        is_directory=False,
                    )
                )
            elif stat.S_ISDIR(entry_mode):
                entries.append(
                    _PayloadEntry(
                        source=entry,
                        relative=archive_relative,
                        mode=_normalized_payload_mode(
                            relative_source, entry_mode, is_directory=True
                        ),
                        is_directory=True,
                    )
                )
                visit(entry)
            elif stat.S_ISREG(entry_mode):
                entries.append(
                    _PayloadEntry(
                        source=entry,
                        relative=archive_relative,
                        mode=_normalized_payload_mode(relative_source, entry_mode),
                        is_directory=False,
                    )
                )
            else:
                raise ValueError(
                    f"artifact contains a nonregular entry: {relative_source.as_posix()}"
                )

    visit(source)
    payload_paths = {entry.relative.as_posix() for entry in entries if not entry.is_directory}
    if "endpoint-agent/endpoint-agent" not in payload_paths or any(
        path != "endpoint-agent/endpoint-agent"
        and not path.startswith("endpoint-agent/_internal/")
        for path in payload_paths
    ):
        raise ValueError("Linux artifact payload has an unexpected shape")
    return entries


def _write_deterministic_archive(
    destination: Path, entries: list[_PayloadEntry], inner_manifest: bytes
) -> None:
    with destination.open("xb") as raw_stream:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw_stream, mtime=0, compresslevel=9
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
            ) as bundle:
                for entry in entries:
                    name = entry.relative.as_posix()
                    info = tarfile.TarInfo(f"{name}/" if entry.is_directory else name)
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "root"
                    info.mtime = 0
                    info.mode = entry.mode
                    if entry.is_directory:
                        info.type = tarfile.DIRTYPE
                        bundle.addfile(info)
                    else:
                        payload = _canonical_payload(entry)
                        if payload is not None:
                            info.size = len(payload)
                            bundle.addfile(info, BytesIO(payload))
                        else:
                            info.size = entry.source.stat().st_size
                            with entry.source.open("rb") as source_stream:
                                bundle.addfile(info, source_stream)
                manifest_info = tarfile.TarInfo("manifest.json")
                manifest_info.uid = 0
                manifest_info.gid = 0
                manifest_info.uname = "root"
                manifest_info.gname = "root"
                manifest_info.mtime = 0
                manifest_info.mode = 0o644
                manifest_info.size = len(inner_manifest)
                bundle.addfile(manifest_info, BytesIO(inner_manifest))
        raw_stream.flush()
        os.fsync(raw_stream.fileno())


def _canonical_base_library(path: Path) -> bytes:
    """Return PyInstaller's base library with stable member order and metadata."""
    output = BytesIO()
    with zipfile.ZipFile(path, "r") as source:
        members = source.infolist()
        names = [member.filename for member in members]
        if len(names) != len(set(names)):
            raise ValueError("base_library.zip contains duplicate members")
        with zipfile.ZipFile(
            output,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as destination:
            for member in sorted(members, key=lambda item: item.filename):
                canonical = zipfile.ZipInfo(member.filename, date_time=_ZIP_TIMESTAMP)
                canonical.compress_type = zipfile.ZIP_DEFLATED
                canonical.create_system = 3
                canonical.external_attr = 0o100644 << 16
                destination.writestr(
                    canonical,
                    source.read(member),
                    compress_type=zipfile.ZIP_DEFLATED,
                    compresslevel=9,
                )
    return output.getvalue()


def _canonical_payload(entry: _PayloadEntry) -> bytes | None:
    if entry.relative.as_posix() == _BASE_LIBRARY_ARCHIVE_PATH:
        return _canonical_base_library(entry.source)
    return None


def _entry_sha256(entry: _PayloadEntry) -> str:
    canonical = _canonical_payload(entry)
    if canonical is not None:
        return hashlib.sha256(canonical).hexdigest()
    digest = hashlib.sha256()
    with entry.source.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inner_manifest_bytes(
    entries: list[_PayloadEntry], *, revision: str, version: str
) -> bytes:
    files = [
        {
            "mode": f"{entry.mode:04o}",
            "path": entry.relative.as_posix(),
            "sha256": _entry_sha256(entry),
        }
        for entry in entries
        if not entry.is_directory
    ]
    return json.dumps(
        {
            "files": files,
            "schema_version": 1,
            "source_revision": revision,
            "version": version,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _manifest_bytes(
    *,
    archive_name: str,
    channel: str,
    revision: str,
    sha256: str,
    size: int,
    version: str,
) -> bytes:
    build_identifier = f"endpoint-agent-{PLATFORM}-{version}"
    manifest = {
        "archive_type": ARCHIVE_TYPE,
        "artifact_name": archive_name,
        "build_identifier": build_identifier,
        "channel": channel,
        "platform": PLATFORM,
        "schema_version": MANIFEST_SCHEMA,
        "sha256": sha256,
        "size": size,
        "source_revision": revision,
        "version": version,
    }
    return (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _same_regular_file(path: Path, expected: bytes) -> bool:
    return not path.is_symlink() and path.is_file() and path.read_bytes() == expected


def build_release(
    *,
    source: Path,
    output: Path,
    version: str,
    channel: str,
    revision: str,
) -> tuple[Path, Path]:
    """Create or replay one content-addressed local Linux build output."""
    if channel not in {"stable", "canary"}:
        raise ValueError("channel must be stable or canary")
    _validate_identifiers(version, revision)
    source = Path(source)
    output = Path(output)
    if output.resolve().is_relative_to(source.resolve()):
        raise ValueError("release output must not be inside the artifact source")
    entries = _payload_entries(source)
    inner_manifest = _inner_manifest_bytes(entries, revision=revision, version=version)

    build_identifier = f"endpoint-agent-{PLATFORM}-{version}"
    archive = output / f"{build_identifier}.{ARCHIVE_TYPE}"
    manifest_path = output / f"{build_identifier}.manifest.json"
    output.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{build_identifier}.", suffix=".tmp", dir=output
    )
    os.close(file_descriptor)
    temporary_archive = Path(temporary_name)
    temporary_archive.unlink()
    temporary_manifest = temporary_archive.with_suffix(".manifest.tmp")
    try:
        _write_deterministic_archive(temporary_archive, entries, inner_manifest)
        archive_bytes = temporary_archive.read_bytes()
        manifest_bytes = _manifest_bytes(
            archive_name=archive.name,
            channel=channel,
            revision=revision,
            sha256=hashlib.sha256(archive_bytes).hexdigest(),
            size=len(archive_bytes),
            version=version,
        )
        with temporary_manifest.open("xb") as stream:
            stream.write(manifest_bytes)
            stream.flush()
            os.fsync(stream.fileno())

        if (
            archive.exists()
            or archive.is_symlink()
            or manifest_path.exists()
            or manifest_path.is_symlink()
        ):
            if _same_regular_file(archive, archive_bytes) and _same_regular_file(
                manifest_path, manifest_bytes
            ):
                return archive, manifest_path
            raise ValueError("immutable build already exists with different content")

        os.replace(temporary_archive, archive)
        os.replace(temporary_manifest, manifest_path)
        return archive, manifest_path
    finally:
        temporary_archive.unlink(missing_ok=True)
        temporary_manifest.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", required=True, choices=("stable", "canary"))
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--revision")
    args = parser.parse_args(argv)

    compiled_version = _read_agent_version()
    if args.version is not None and args.version != compiled_version:
        parser.exit(
            1,
            "Linux agent release build failed: release version must match "
            "compiled AGENT_VERSION\n",
        )
    version = compiled_version
    revision = args.revision or _source_revision()
    output = args.output or (
        PROJECT_ROOT / "dist" / "release" / PLATFORM / args.channel / version
    )
    try:
        archive, manifest = build_release(
            source=args.source,
            output=output,
            version=version,
            channel=args.channel,
            revision=revision,
        )
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        parser.exit(1, f"Linux agent release build failed: {error}\n")
    print(archive)
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
