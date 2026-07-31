"""Safe publisher for immutable ALT agent update bundles."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OPERATION_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


@dataclass(frozen=True)
class _Manifest:
    version: str
    source_revision: str
    files: dict[str, tuple[str, int]]


def apply_alt_update(
    install_root: Path, data_root: Path, pending_path: Path
) -> tuple[bool, str]:
    """Publish one verified ALT bundle without mutating a prior selection on failure."""
    install_root, data_root, pending_path = (
        Path(install_root),
        Path(data_root),
        Path(pending_path),
    )
    payload: dict[str, Any] | None = None
    try:
        payload = _load_pending(data_root, pending_path)
        artifact_path = _verified_artifact(data_root, payload)
        current = _load_selector(install_root / "current.json")
        staging_parent = install_root / "versions" / "_alt_update_staging"
        staging = staging_parent / uuid.uuid4().hex
        manifest = _extract_and_validate(
            artifact_path=artifact_path, staging=staging, expected_version=payload["version"]
        )
        target = install_root / "versions" / manifest.version
        if target.exists() or target.is_symlink():
            _verify_existing_release(target, manifest)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(staging), str(target))
            _make_release_directories_traversable(target)
        _write_selector(install_root / "current.json", manifest)
        _append_history(
            data_root,
            {
                "operation_id": payload["operation_id"],
                "previous_version": current["version"],
                "success": True,
                "version": manifest.version,
            },
        )
        pending_path.unlink(missing_ok=True)
        return True, manifest.version
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError) as exc:
        if payload is not None:
            _append_history(
                data_root,
                {
                    "operation_id": payload["operation_id"],
                    "success": False,
                    "version": payload["version"],
                },
            )
        _archive_failed_pending(data_root, pending_path)
        return False, type(exc).__name__
    finally:
        try:
            if "staging" in locals() and staging.exists():
                shutil.rmtree(staging)
        except OSError:
            pass


def _load_pending(data_root: Path, pending_path: Path) -> dict[str, Any]:
    expected_path = data_root / "updates" / "pending_alt_update.json"
    if pending_path != expected_path or not pending_path.is_file() or pending_path.is_symlink():
        raise ValueError("invalid ALT pending path")
    payload = _load_json_no_duplicates(pending_path.read_text(encoding="utf-8"))
    required = {
        "archive_type",
        "artifact_path",
        "channel",
        "operation_id",
        "requested_by",
        "requested_reason",
        "sha256",
        "size",
        "target",
        "version",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("invalid ALT pending schema")
    if (
        payload["archive_type"] != "tar.gz"
        or payload["channel"] != "canary"
        or payload["target"] != "linux_amd64"
        or payload["requested_by"] != "gateway"
        or not isinstance(payload["requested_reason"], (str, type(None)))
        or not isinstance(payload["artifact_path"], str)
        or not isinstance(payload["size"], int)
        or payload["size"] <= 0
        or not isinstance(payload["sha256"], str)
        or not _SHA256.fullmatch(payload["sha256"])
        or not isinstance(payload["version"], str)
        or not _SEMVER.fullmatch(payload["version"])
        or not isinstance(payload["operation_id"], str)
        or not _OPERATION_ID.fullmatch(payload["operation_id"])
    ):
        raise ValueError("invalid ALT pending values")
    return payload


def _verified_artifact(data_root: Path, payload: dict[str, Any]) -> Path:
    downloads = data_root / "updates" / "downloads"
    artifact = Path(payload["artifact_path"])
    try:
        artifact.relative_to(downloads)
    except ValueError as exc:
        raise ValueError("artifact is outside ALT downloads directory") from exc
    if artifact.is_symlink() or not artifact.is_file():
        raise ValueError("artifact is not a regular file")
    digest = hashlib.sha256()
    size = 0
    with artifact.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    if size != payload["size"] or digest.hexdigest() != payload["sha256"]:
        raise ValueError("artifact digest mismatch")
    return artifact


def _load_selector(path: Path) -> dict[str, Any]:
    selector = _load_json_no_duplicates(path.read_text(encoding="utf-8"))
    if (
        not isinstance(selector, dict)
        or set(selector) != {"schema_version", "source_revision", "version"}
        or selector["schema_version"] != 1
        or not isinstance(selector["version"], str)
        or not _SEMVER.fullmatch(selector["version"])
        or not isinstance(selector["source_revision"], str)
        or not _REVISION.fullmatch(selector["source_revision"])
    ):
        raise ValueError("invalid ALT current selector")
    return selector


def _extract_and_validate(
    *, artifact_path: Path, staging: Path, expected_version: str
) -> _Manifest:
    if staging.exists() or staging.is_symlink():
        raise ValueError("unsafe ALT staging path")
    staging.mkdir(parents=True, mode=0o700)
    with tarfile.open(artifact_path, "r:gz") as archive:
        members = archive.getmembers()
        if not members or len(members) > 1024:
            raise ValueError("invalid ALT archive member count")
        regular: dict[str, tarfile.TarInfo] = {}
        for member in members:
            name = _safe_member_name(member.name)
            if member.isdir():
                continue
            if not member.isfile() or name in regular:
                raise ValueError("unsafe ALT archive member")
            regular[name] = member
        manifest_member = regular.get("manifest.json")
        if manifest_member is None or manifest_member.size > 1024 * 1024:
            raise ValueError("missing ALT manifest")
        stream = archive.extractfile(manifest_member)
        if stream is None:
            raise ValueError("unreadable ALT manifest")
        manifest = _parse_manifest(stream.read(), expected_version=expected_version)
        actual = {
            name: (_member_sha256(archive, member), stat.S_IMODE(member.mode))
            for name, member in regular.items()
            if name != "manifest.json"
        }
        if actual != manifest.files or {"launcher", "pc_agent/pc_agent"} - set(actual):
            raise ValueError("ALT manifest does not match archive")
        if any(name != "launcher" and not name.startswith("pc_agent/") for name in actual):
            raise ValueError("unexpected ALT archive payload")
        for name, member in regular.items():
            destination = staging.joinpath(*PurePosixPath(name).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("unreadable ALT archive member")
            with destination.open("wb") as output:
                shutil.copyfileobj(source, output)
            os.chmod(destination, stat.S_IMODE(member.mode))
    return manifest


def _parse_manifest(raw: bytes, *, expected_version: str) -> _Manifest:
    try:
        parsed = _load_json_no_duplicates(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("invalid ALT manifest encoding") from exc
    if (
        not isinstance(parsed, dict)
        or set(parsed) != {"schema_version", "version", "source_revision", "files"}
        or parsed["schema_version"] != 1
        or parsed["version"] != expected_version
        or not isinstance(parsed["version"], str)
        or not _SEMVER.fullmatch(parsed["version"])
        or not isinstance(parsed["source_revision"], str)
        or not _REVISION.fullmatch(parsed["source_revision"])
        or not isinstance(parsed["files"], list)
        or not parsed["files"]
    ):
        raise ValueError("invalid ALT manifest schema")
    files: dict[str, tuple[str, int]] = {}
    for item in parsed["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "mode"}:
            raise ValueError("invalid ALT manifest file")
        path = _safe_member_name(item["path"])
        if (
            path == "manifest.json"
            or path in files
            or not isinstance(item["sha256"], str)
            or not _SHA256.fullmatch(item["sha256"])
            or not isinstance(item["mode"], str)
            or not re.fullmatch(r"[0-7]{4}", item["mode"])
        ):
            raise ValueError("invalid ALT manifest file")
        files[path] = (item["sha256"], int(item["mode"], 8))
    if list(files) != sorted(files):
        raise ValueError("ALT manifest files are not sorted")
    return _Manifest(parsed["version"], parsed["source_revision"], files)


def _safe_member_name(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("unsafe ALT archive path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("unsafe ALT archive path")
    return str(path)


def _member_sha256(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    source = archive.extractfile(member)
    if source is None:
        raise ValueError("unreadable ALT archive member")
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _write_selector(path: Path, manifest: _Manifest) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": manifest.source_revision,
                "version": manifest.version,
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    os.chmod(temporary, 0o644)
    temporary.replace(path)


def _make_release_directories_traversable(release_root: Path) -> None:
    """ALT code runs as the service account while release trees stay root-owned."""
    for directory, _, _ in os.walk(release_root):
        os.chmod(directory, 0o755)


def _verify_existing_release(release_root: Path, expected: _Manifest) -> None:
    """Accept a previous immutable release only when it exactly matches the bundle."""
    if release_root.is_symlink() or not release_root.is_dir():
        raise ValueError("invalid existing ALT release")
    manifest_path = release_root / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("missing existing ALT manifest")
    existing = _parse_manifest(
        manifest_path.read_bytes(), expected_version=expected.version
    )
    if existing != expected:
        raise ValueError("existing ALT manifest does not match bundle")

    expected_files = {"manifest.json", *expected.files}
    actual_files: set[str] = set()
    for path in release_root.rglob("*"):
        relative = path.relative_to(release_root).as_posix()
        if path.is_symlink():
            raise ValueError("unsafe existing ALT release entry")
        if path.is_dir():
            continue
        if not path.is_file() or relative not in expected_files:
            raise ValueError("unexpected existing ALT release entry")
        actual_files.add(relative)
        if relative == "manifest.json":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        expected_digest, expected_mode = expected.files[relative]
        if digest != expected_digest or (
            os.name != "nt" and stat.S_IMODE(path.stat().st_mode) != expected_mode
        ):
            raise ValueError("existing ALT release file does not match bundle")
    if actual_files != expected_files:
        raise ValueError("incomplete existing ALT release")


def _append_history(data_root: Path, entry: dict[str, object]) -> None:
    path = data_root / "updates" / "update_history.json"
    try:
        history = _load_json_no_duplicates(path.read_text(encoding="utf-8")) if path.exists() else []
    except (OSError, ValueError, json.JSONDecodeError):
        history = []
    if not isinstance(history, list):
        history = []
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps([*history[-99:], entry]), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def _archive_failed_pending(data_root: Path, pending_path: Path) -> None:
    expected = data_root / "updates" / "pending_alt_update.json"
    if pending_path != expected or not pending_path.exists() or pending_path.is_symlink():
        return
    try:
        pending_path.replace(expected.with_name("last_failed_alt_update.json"))
    except OSError:
        return


def _load_json_no_duplicates(value: str) -> Any:
    def reject_duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    return json.loads(value, object_pairs_hook=reject_duplicates)
