"""Pure, offline identity checks shared by Setup and Windows ZIP registration.

This module never establishes filesystem trust, grants an installer capability,
or loads MSI/HTTP machinery. Callers separately validate their trusted roots.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import zipfile

CONTRACT_FILENAME = "endpoint-runtime-contract.json"
BUNDLE_FILENAME = "endpoint-update-manifest.json"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_CONTRACT_BYTES = 4096
MAX_FILES = 10_000
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024 * 1024
_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_SOURCE = re.compile(r"^[0-9a-f]{40}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")


class PayloadConflict(ValueError):
    def __init__(self):
        super().__init__("PROVENANCE_CONFLICT")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PayloadConflict()
        result[key] = value
    return result


def read_json(data: bytes, maximum: int) -> dict:
    if not isinstance(data, bytes) or not 0 < len(data) <= maximum:
        raise PayloadConflict()
    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(PayloadConflict()))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise PayloadConflict() from error
    if not isinstance(result, dict):
        raise PayloadConflict()
    return result


def version_tuple(version: object) -> tuple[int, int, int]:
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise PayloadConflict()
    return tuple(map(int, version.split(".")))


def safe_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise PayloadConflict()
    path = PureWindowsPath(value)
    if (path.is_absolute() or path.drive or value.startswith("/") or "\\" in value
        or any(ord(char) < 32 for char in value)
        or any(part in {"", ".", ".."} or part.endswith((".", " "))
            or any(char in part for char in ':<>"|?*') or PureWindowsPath(part).is_reserved()
            for part in value.split("/"))):
        raise PayloadConflict()
    return value


@dataclass(frozen=True)
class PayloadFile:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class PayloadIdentity:
    version: str
    source_revision: str
    minimum_launcher_version: str | None
    files: tuple[PayloadFile, ...]

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def tree_sha256(self) -> str:
        digest = hashlib.sha256()
        for item in self.files:
            digest.update(f"{item.path}\0{item.size}\0{item.sha256}\n".encode("utf-8"))
        return digest.hexdigest()


def manifest_files(manifest: Mapping[str, object]) -> tuple[PayloadFile, ...]:
    if (not isinstance(manifest, Mapping)
        or set(manifest) != {"schema_version", "version", "source_revision", "files"}
        or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1
        or not isinstance(manifest["source_revision"], str)
        or not _SOURCE.fullmatch(manifest["source_revision"])):
        raise PayloadConflict()
    version_tuple(manifest["version"])
    files = manifest["files"]
    if not isinstance(files, list) or not 0 < len(files) <= MAX_FILES:
        raise PayloadConflict()
    result, names, total = [], set(), 0
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise PayloadConflict()
        path = safe_path(entry["path"])
        size, digest = entry["size"], entry["sha256"]
        if (path.casefold() in names or type(size) is not int or size < 0
            or not isinstance(digest, str) or not _HASH.fullmatch(digest)):
            raise PayloadConflict()
        names.add(path.casefold())
        total += size
        if total > MAX_PAYLOAD_BYTES:
            raise PayloadConflict()
        result.append(PayloadFile(path, size, digest))
    if "pc_agent.exe" not in {item.path for item in result}:
        raise PayloadConflict()
    return tuple(sorted(result, key=lambda item: item.path))


def bind_contract(manifest: Mapping[str, object], files: tuple[PayloadFile, ...], data: bytes) -> PayloadIdentity:
    contract = read_json(data, MAX_CONTRACT_BYTES)
    if (set(contract) != {"schema_version", "version", "source_revision", "minimum_launcher_version"}
        or type(contract["schema_version"]) is not int or contract["schema_version"] != 1
        or contract["version"] != manifest["version"]
        or contract["source_revision"] != manifest["source_revision"]):
        raise PayloadConflict()
    if contract["minimum_launcher_version"] is not None:
        version_tuple(contract["minimum_launcher_version"])
    expected = next((item for item in files if item.path == CONTRACT_FILENAME), None)
    if expected is None or len(data) != expected.size or hashlib.sha256(data).hexdigest() != expected.sha256:
        raise PayloadConflict()
    return PayloadIdentity(contract["version"], contract["source_revision"],
        contract["minimum_launcher_version"], files)


def _regular(path: Path):
    details = path.lstat()
    if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
        or getattr(details, "st_file_attributes", 0) & 0x400):
        raise PayloadConflict()
    return details


def reject_reparse_ancestors(path: Path) -> None:
    for part in [*reversed(path.absolute().parents), path.absolute()]:
        details = part.lstat()
        if stat.S_ISLNK(details.st_mode) or getattr(details, "st_file_attributes", 0) & 0x400:
            raise PayloadConflict()


def _hash_open(source, maximum):
    digest, total = hashlib.sha256(), 0
    while block := source.read(1024 * 1024):
        total += len(block)
        if total > maximum:
            raise PayloadConflict()
        digest.update(block)
    return total, digest.hexdigest()


def verify_payload(root: Path, manifest: Mapping[str, object], *, excluded: frozenset[str] = frozenset()) -> PayloadIdentity:
    """Verify exact root inventory; exclusions apply only to named root receipts."""
    try:
        files = manifest_files(manifest)
        reject_reparse_ancestors(root)
        expected = {item.path: item for item in files}
        if excluded & expected.keys() or any("/" in name or safe_path(name) != name for name in excluded):
            raise PayloadConflict()
        actual, aliases = {}, set()
        for directory, subdirs, leaves in os.walk(root, followlinks=False):
            for name in [*subdirs, *leaves]:
                path = Path(directory) / name
                relative = safe_path(path.relative_to(root).as_posix())
                details = path.lstat()
                if getattr(details, "st_file_attributes", 0) & 0x400 or stat.S_ISLNK(details.st_mode):
                    raise PayloadConflict()
                if relative.casefold() in aliases:
                    raise PayloadConflict()
                aliases.add(relative.casefold())
            for name in leaves:
                path = Path(directory) / name
                relative = path.relative_to(root).as_posix()
                before = _regular(path)
                if relative in excluded:
                    continue
                if relative not in expected or before.st_size != expected[relative].size:
                    raise PayloadConflict()
                with path.open("rb") as source:
                    opened = os.fstat(source.fileno())
                    size, digest = _hash_open(source, expected[relative].size)
                    after = os.fstat(source.fileno())
                if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                    != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                    or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
                    or size != expected[relative].size or digest != expected[relative].sha256):
                    raise PayloadConflict()
                actual[relative] = digest
        if set(actual) != set(expected):
            raise PayloadConflict()
        with (root / CONTRACT_FILENAME).open("rb") as source:
            data = source.read(MAX_CONTRACT_BYTES + 1)
        return bind_contract(manifest, files, data)
    except (OSError, KeyError, TypeError) as error:
        raise PayloadConflict() from error


def verify_windows_archive(path: Path, *, sha256: str, size: int, version: str,
    minimum_launcher_version: str | None) -> PayloadIdentity:
    """Pin one archive descriptor; validate bytes and inventoried contract offline."""
    try:
        if (type(size) is not int or not 0 < size <= MAX_ARCHIVE_BYTES
            or not isinstance(sha256, str) or not _HASH.fullmatch(sha256)):
            raise PayloadConflict()
        reject_reparse_ancestors(path)
        before = _regular(path)
        if before.st_size != size:
            raise PayloadConflict()
        with path.open("rb") as source:
            pinned = os.fstat(source.fileno())
            if (pinned.st_dev, pinned.st_ino) != (before.st_dev, before.st_ino):
                raise PayloadConflict()
            if _hash_open(source, MAX_ARCHIVE_BYTES) != (size, sha256):
                raise PayloadConflict()
            source.seek(0)
            with zipfile.ZipFile(source) as archive:
                entries, names, expanded = {}, set(), 0
                for item in archive.infolist():
                    if len(names) >= MAX_FILES + 1:
                        raise PayloadConflict()
                    name = safe_path(item.filename.rstrip("/") if item.is_dir() else item.filename)
                    kind = stat.S_IFMT(item.external_attr >> 16)
                    if name.casefold() in names or item.flag_bits & 1 or kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
                        raise PayloadConflict()
                    names.add(name.casefold())
                    expanded += item.file_size
                    if expanded > MAX_PAYLOAD_BYTES + MAX_MANIFEST_BYTES:
                        raise PayloadConflict()
                    if not item.is_dir():
                        entries[name] = item
                bundle = entries.get(BUNDLE_FILENAME)
                if bundle is None or not 0 < bundle.file_size <= MAX_MANIFEST_BYTES:
                    raise PayloadConflict()
                manifest = read_json(archive.read(bundle), MAX_MANIFEST_BYTES)
                files = manifest_files(manifest)
                if set(entries) != {BUNDLE_FILENAME, *(item.path for item in files)}:
                    raise PayloadConflict()
                for item in files:
                    if entries[item.path].file_size != item.size:
                        raise PayloadConflict()
                    with archive.open(entries[item.path]) as payload:
                        if _hash_open(payload, item.size) != (item.size, item.sha256):
                            raise PayloadConflict()
                contract = entries.get(CONTRACT_FILENAME)
                if contract is None or contract.file_size > MAX_CONTRACT_BYTES:
                    raise PayloadConflict()
                result = bind_contract(manifest, files, archive.read(contract))
                if result.version != version or result.minimum_launcher_version != minimum_launcher_version:
                    raise PayloadConflict()
            after = os.fstat(source.fileno())
            if (pinned.st_size, pinned.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise PayloadConflict()
            return result
    except (OSError, zipfile.BadZipFile, KeyError, TypeError, RuntimeError) as error:
        raise PayloadConflict() from error
