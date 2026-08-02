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
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterator


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
ROLLBACK_REQUEST_SCHEMA = "endpoint_alt_rollback_request_v1"
ROLLBACK_REQUEST_NAME = "rollback-request.json"
PREVIOUS_SELECTOR_NAME = "previous.json"
FAILED_ROLLBACK_REQUEST_NAME = "last_failed_alt_rollback_request.json"


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
    committed = False
    try:
        _validate_updates_dir(data_root)
        payload = _load_pending(data_root, pending_path)
        artifact_path = _verified_artifact(data_root, payload)
        current = _load_selector(install_root / "current.json", root_authority=True)
        _verify_selected_release(install_root, current)
        staging_parent = install_root / "versions" / "_alt_update_staging"
        staging = staging_parent / uuid.uuid4().hex
        manifest = _extract_and_validate(
            artifact_path=artifact_path,
            staging=staging,
            expected_version=payload["version"],
        )
        target = install_root / "versions" / manifest.version
        if target.exists() or target.is_symlink():
            _verify_existing_release(target, manifest)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(staging), str(target))
            _make_release_directories_traversable(target)
            _verify_existing_release(target, manifest)
        candidate = _selector_for_manifest(manifest)
        previous_path = install_root / PREVIOUS_SELECTOR_NAME
        if current == candidate:
            # Replay after current.json was already committed.  The distinct
            # root-owned rollback selector is authority and must be preserved.
            try:
                previous = _load_selector(previous_path, root_authority=True)
                if previous == candidate:
                    raise ValueError("committed ALT update has no prior selector")
                _verify_selected_release(install_root, previous)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                _reject_inconsistent_update_replay(data_root, pending_path, payload)
                return False, type(exc).__name__
            committed = True
        else:
            prior_previous = _load_optional_selector(previous_path, root_authority=True)
            _write_selector_record(previous_path, current)
            try:
                _write_selector(install_root / "current.json", manifest)
            except Exception:
                if prior_previous is None:
                    previous_path.unlink(missing_ok=True)
                else:
                    _write_selector_record(previous_path, prior_previous)
                raise
            committed = True
            previous = current
        committed = True
        try:
            _append_history(
                data_root,
                {
                    "operation_id": payload["operation_id"],
                    "previous_version": previous["version"],
                    "success": True,
                    "version": manifest.version,
                },
            )
            pending_path.unlink(missing_ok=True)
        except (OSError, ValueError, json.JSONDecodeError):
            # current.json is the commit point.  Leave the pending request for
            # an idempotent replay instead of reporting an active build failed.
            return True, manifest.version
        return True, manifest.version
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError) as exc:
        if committed:
            return True, str(payload["version"] if payload is not None else "committed")
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


def write_alt_rollback_request(
    install_root: Path, data_root: Path, crashed_version: str
) -> Path:
    """Request only the root-authorized previous selector for a crashed ALT release."""
    install_root, data_root = Path(install_root), Path(data_root)
    _prepare_updates_dir(data_root)
    current = _load_selector(install_root / "current.json", root_authority=True)
    previous = _load_selector(
        install_root / PREVIOUS_SELECTOR_NAME, root_authority=True
    )
    if current["version"] != crashed_version or previous["version"] == crashed_version:
        raise ValueError("ALT rollback identities are stale")
    payload = {
        "crashed_source_revision": current["source_revision"],
        "crashed_version": current["version"],
        "rollback_source_revision": previous["source_revision"],
        "rollback_version": previous["version"],
        "schema_version": ROLLBACK_REQUEST_SCHEMA,
    }
    request = data_root / "updates" / ROLLBACK_REQUEST_NAME
    with _pinned_updates_dir(data_root) as (updates, updates_fd):
        _write_update_json(updates, updates_fd, ROLLBACK_REQUEST_NAME, payload)
    return request


def apply_alt_rollback(install_root: Path, data_root: Path) -> tuple[bool, str]:
    """Apply one fixed, root-mediated ALT rollback request."""
    install_root, data_root = Path(install_root), Path(data_root)
    request = data_root / "updates" / ROLLBACK_REQUEST_NAME
    committed = False
    try:
        with _pinned_updates_dir(data_root) as (updates, updates_fd):
            payload = _load_rollback_request(
                data_root, request, updates=updates, updates_fd=updates_fd
            )
            current = _load_selector(install_root / "current.json", root_authority=True)
            previous = _load_selector(
                install_root / PREVIOUS_SELECTOR_NAME, root_authority=True
            )
            crashed = {
                "schema_version": 1,
                "source_revision": payload["crashed_source_revision"],
                "version": payload["crashed_version"],
            }
            rollback = {
                "schema_version": 1,
                "source_revision": payload["rollback_source_revision"],
                "version": payload["rollback_version"],
            }
            authorized = {
                "crashed_source_revision": crashed["source_revision"],
                "crashed_version": crashed["version"],
                "rollback_source_revision": previous["source_revision"],
                "rollback_version": previous["version"],
                "schema_version": ROLLBACK_REQUEST_SCHEMA,
            }
            if payload != authorized or previous != rollback:
                raise ValueError("ALT rollback request is not root-authorized")
            _verify_selected_release(install_root, previous)
            if current == crashed:
                _write_selector_record(install_root / "current.json", previous)
                committed = True
            elif current == rollback:
                # Replay after selector commit and before marker/request cleanup.
                committed = True
            else:
                raise ValueError("ALT rollback current selector is unauthorized")
            try:
                _write_update_json(
                    updates,
                    updates_fd,
                    "last_failed_launch.json",
                    {
                        "crashed_version": crashed["version"],
                        "reason": "startup_crash_rollback",
                        "rollback_version": previous["version"],
                    },
                )
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                # Keep the request as a durable recovery record.  A path-unit
                # replay recognizes current==rollback and finishes the commit.
                return False, type(exc).__name__
            _unlink_update_leaf(updates, updates_fd, ROLLBACK_REQUEST_NAME)
        try:
            (install_root / PREVIOUS_SELECTOR_NAME).unlink()
        except OSError:
            pass
        return True, str(previous["version"])
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        if not committed:
            _archive_failed_rollback_request(data_root, request)
        return False, type(exc).__name__


def _load_rollback_request(
    data_root: Path,
    request: Path,
    *,
    updates: Path,
    updates_fd: int | None,
) -> dict[str, Any]:
    expected = data_root / "updates" / ROLLBACK_REQUEST_NAME
    if request != expected:
        raise ValueError("invalid ALT rollback request path")
    details, raw = _read_update_leaf(updates, updates_fd, ROLLBACK_REQUEST_NAME)
    if not stat.S_ISREG(details.st_mode):
        raise ValueError("invalid ALT rollback request file")
    if details.st_size <= 0 or details.st_size > 1024:
        raise ValueError("invalid ALT rollback request size")
    if os.name != "nt":
        data_details = data_root.stat()
        if (
            details.st_uid != data_details.st_uid
            or details.st_gid != data_details.st_gid
            or stat.S_IMODE(details.st_mode) != 0o600
        ):
            raise ValueError("invalid ALT rollback request ownership")
    payload = _load_json_no_duplicates(raw.decode("utf-8"))
    required = {
        "crashed_source_revision",
        "crashed_version",
        "rollback_source_revision",
        "rollback_version",
        "schema_version",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("invalid ALT rollback request schema")
    if (
        payload["schema_version"] != ROLLBACK_REQUEST_SCHEMA
        or not isinstance(payload["crashed_version"], str)
        or not _SEMVER.fullmatch(payload["crashed_version"])
        or not isinstance(payload["rollback_version"], str)
        or not _SEMVER.fullmatch(payload["rollback_version"])
        or payload["crashed_version"] == payload["rollback_version"]
        or not isinstance(payload["crashed_source_revision"], str)
        or not _REVISION.fullmatch(payload["crashed_source_revision"])
        or not isinstance(payload["rollback_source_revision"], str)
        or not _REVISION.fullmatch(payload["rollback_source_revision"])
    ):
        raise ValueError("invalid ALT rollback request values")
    return payload


def _load_pending(data_root: Path, pending_path: Path) -> dict[str, Any]:
    expected_path = data_root / "updates" / "pending_alt_update.json"
    if (
        pending_path != expected_path
        or not pending_path.is_file()
        or pending_path.is_symlink()
    ):
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


def _load_selector(path: Path, *, root_authority: bool = False) -> dict[str, Any]:
    _validate_regular_file_metadata(
        path, expected_mode=0o644, root_authority=root_authority
    )
    selector = _load_json_no_duplicates(path.read_text(encoding="utf-8"))
    return _load_selector_payload(selector)


def _load_optional_selector(
    path: Path, *, root_authority: bool = False
) -> dict[str, Any] | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return _load_selector(path, root_authority=root_authority)


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
        if actual != manifest.files:
            raise ValueError("ALT manifest does not match archive")
        _validate_release_shape(set(actual))
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


def _validate_release_shape(files: set[str]) -> None:
    legacy = {"launcher", "pc_agent/pc_agent"}.issubset(files) and all(
        name == "launcher" or name.startswith("pc_agent/") for name in files
    )
    headless = "endpoint-agent/endpoint-agent" in files and all(
        name.startswith("endpoint-agent/") for name in files
    )
    if legacy == headless:
        raise ValueError("unexpected ALT archive payload")


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
    _write_selector_record(path, _selector_for_manifest(manifest))


def _selector_for_manifest(manifest: _Manifest) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source_revision": manifest.source_revision,
        "version": manifest.version,
    }


def _write_selector_record(path: Path, selector: dict[str, Any]) -> None:
    validated = _load_selector_payload(selector)
    _write_json_atomic(path, validated, mode=0o644)


def _write_json_atomic(path: Path, payload: dict[str, Any], *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            view = memoryview(serialized)
            while view:
                view = view[os.write(descriptor, view) :]
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        temporary.replace(path)
        try:
            _fsync_directory(path.parent)
        except OSError:
            # The atomic replace is already the observable commit point.  Do
            # not report an active selector/request as failed solely because a
            # post-commit directory durability flush was unavailable.
            pass
    finally:
        temporary.unlink(missing_ok=True)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _load_selector_payload(selector: Any) -> dict[str, Any]:
    if (
        not isinstance(selector, dict)
        or set(selector) != {"schema_version", "source_revision", "version"}
        or selector["schema_version"] != 1
        or not isinstance(selector["version"], str)
        or not _SEMVER.fullmatch(selector["version"])
        or not isinstance(selector["source_revision"], str)
        or not _REVISION.fullmatch(selector["source_revision"])
    ):
        raise ValueError("invalid ALT selector")
    return selector


def _verify_selected_release(install_root: Path, selector: dict[str, Any]) -> None:
    selector = _load_selector_payload(selector)
    release = install_root / "versions" / selector["version"]
    manifest_path = release / "manifest.json"
    _validate_directory_metadata(release, expected_mode=0o755, root_authority=True)
    _validate_regular_file_metadata(
        manifest_path, expected_mode=0o644, root_authority=True
    )
    manifest = _parse_manifest(
        manifest_path.read_bytes(), expected_version=selector["version"]
    )
    if manifest.source_revision != selector["source_revision"]:
        raise ValueError("selected ALT revision does not match selector")
    _verify_existing_release(release, manifest)


def _make_release_directories_traversable(release_root: Path) -> None:
    """ALT code runs as the service account while release trees stay root-owned."""
    for directory, _, _ in os.walk(release_root):
        os.chmod(directory, 0o755)


def _verify_existing_release(release_root: Path, expected: _Manifest) -> None:
    """Accept a previous immutable release only when it exactly matches the bundle."""
    _validate_release_shape(set(expected.files))
    _validate_directory_metadata(release_root, expected_mode=0o755, root_authority=True)
    manifest_path = release_root / "manifest.json"
    _validate_regular_file_metadata(
        manifest_path, expected_mode=0o644, root_authority=True
    )
    existing = _parse_manifest(
        manifest_path.read_bytes(), expected_version=expected.version
    )
    if existing != expected:
        raise ValueError("existing ALT manifest does not match bundle")

    expected_files = {"manifest.json", *expected.files}
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for path in release_root.rglob("*"):
        relative = path.relative_to(release_root).as_posix()
        if path.is_symlink():
            raise ValueError("unsafe existing ALT release entry")
        if path.is_dir():
            _validate_directory_metadata(path, expected_mode=0o755, root_authority=True)
            actual_directories.add(relative)
            continue
        if not path.is_file() or relative not in expected_files:
            raise ValueError("unexpected existing ALT release entry")
        actual_files.add(relative)
        if relative == "manifest.json":
            continue
        _validate_regular_file_metadata(
            path, expected_mode=expected.files[relative][1], root_authority=True
        )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        expected_digest, _ = expected.files[relative]
        if digest != expected_digest:
            raise ValueError("existing ALT release file does not match bundle")
    if actual_files != expected_files:
        raise ValueError("incomplete existing ALT release")
    expected_directories = {
        PurePosixPath(name).parent.as_posix()
        for name in expected_files
        if PurePosixPath(name).parent.as_posix() != "."
    }
    # Include every ancestor, not only each file's immediate parent.
    expected_directories = {
        PurePosixPath(*PurePosixPath(directory).parts[:index]).as_posix()
        for directory in expected_directories
        for index in range(1, len(PurePosixPath(directory).parts) + 1)
    }
    if actual_directories != expected_directories:
        raise ValueError("unexpected existing ALT release directory")


def _validate_regular_file_metadata(
    path: Path, *, expected_mode: int, root_authority: bool
) -> os.stat_result:
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode):
        raise ValueError("unsafe ALT regular file")
    _validate_posix_metadata(
        details, expected_mode=expected_mode, root_authority=root_authority
    )
    return details


def _validate_directory_metadata(
    path: Path, *, expected_mode: int, root_authority: bool
) -> os.stat_result:
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode):
        raise ValueError("unsafe ALT directory")
    _validate_posix_metadata(
        details, expected_mode=expected_mode, root_authority=root_authority
    )
    return details


def _validate_posix_metadata(
    details: os.stat_result, *, expected_mode: int, root_authority: bool
) -> None:
    if os.name == "nt":
        return
    if stat.S_IMODE(details.st_mode) != expected_mode:
        raise ValueError("unsafe ALT filesystem mode")
    # Direct unit tests may call the worker function without privilege.  The
    # production CLI requires euid 0; in that root context enforce root:root.
    if (
        root_authority
        and os.geteuid() == 0
        and (details.st_uid != 0 or details.st_gid != 0)
    ):
        raise ValueError("unsafe ALT root authority ownership")


def _append_history(data_root: Path, entry: dict[str, object]) -> None:
    path = data_root / "updates" / "update_history.json"
    try:
        history = (
            _load_json_no_duplicates(path.read_text(encoding="utf-8"))
            if path.exists()
            else []
        )
    except (OSError, ValueError, json.JSONDecodeError):
        history = []
    if not isinstance(history, list):
        history = []
    operation_id = entry.get("operation_id")
    if operation_id is not None:
        history = [
            item
            for item in history
            if not isinstance(item, dict) or item.get("operation_id") != operation_id
        ]
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps([*history[-99:], entry]), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def _archive_failed_pending(data_root: Path, pending_path: Path) -> None:
    expected = data_root / "updates" / "pending_alt_update.json"
    if (
        pending_path != expected
        or not pending_path.exists()
        or pending_path.is_symlink()
    ):
        return
    try:
        pending_path.replace(expected.with_name("last_failed_alt_update.json"))
    except OSError:
        return


def _archive_failed_rollback_request(data_root: Path, request: Path) -> None:
    expected = data_root / "updates" / ROLLBACK_REQUEST_NAME
    if request != expected:
        return
    try:
        with _pinned_updates_dir(data_root) as (updates, updates_fd):
            _quarantine_update_leaf(updates, updates_fd, ROLLBACK_REQUEST_NAME)
            _quarantine_update_leaf(updates, updates_fd, FAILED_ROLLBACK_REQUEST_NAME)
            _write_update_json(
                updates,
                updates_fd,
                FAILED_ROLLBACK_REQUEST_NAME,
                {"reason": "invalid_alt_rollback_request"},
            )
    except (OSError, ValueError):
        return


def _reject_inconsistent_update_replay(
    data_root: Path, pending_path: Path, payload: dict[str, Any]
) -> None:
    expected = data_root / "updates" / "pending_alt_update.json"
    if pending_path != expected:
        raise ValueError("invalid inconsistent ALT pending path")
    with _pinned_updates_dir(data_root) as (updates, updates_fd):
        _quarantine_update_leaf(updates, updates_fd, "pending_alt_update.json")
        _quarantine_update_leaf(updates, updates_fd, "last_failed_alt_update.json")
        _write_update_json(
            updates,
            updates_fd,
            "last_failed_alt_update.json",
            {
                "operation_id": payload["operation_id"],
                "reason": "invalid_committed_alt_update_replay",
                "version": payload["version"],
            },
        )


@contextmanager
def _pinned_updates_dir(data_root: Path) -> Iterator[tuple[Path, int | None]]:
    updates = _validate_updates_dir(data_root)
    if os.name == "nt":
        yield updates, None
        return
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    data_fd = os.open(data_root, flags)
    updates_fd: int | None = None
    try:
        data_details = os.fstat(data_fd)
        updates_fd = os.open("updates", flags, dir_fd=data_fd)
        updates_details = os.fstat(updates_fd)
        if (
            updates_details.st_uid != data_details.st_uid
            or updates_details.st_gid != data_details.st_gid
            or stat.S_IMODE(updates_details.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError("unsafe ALT pinned updates directory")
        yield updates, updates_fd
    finally:
        if updates_fd is not None:
            os.close(updates_fd)
        os.close(data_fd)


def _read_update_leaf(
    updates: Path, updates_fd: int | None, name: str
) -> tuple[os.stat_result, bytes]:
    if updates_fd is None:
        path = updates / name
        details = path.lstat()
        return details, path.read_bytes()
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=updates_fd
    )
    try:
        details = os.fstat(descriptor)
        chunks: list[bytes] = []
        remaining = 1025
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return details, b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_update_json(
    updates: Path,
    updates_fd: int | None,
    name: str,
    payload: dict[str, Any],
) -> None:
    if updates_fd is None:
        _write_json_atomic(updates / name, payload, mode=0o600)
        return
    serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    temporary = f".{name}.{uuid.uuid4().hex}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=updates_fd,
        )
        view = memoryview(serialized)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(
            temporary,
            name,
            src_dir_fd=updates_fd,
            dst_dir_fd=updates_fd,
        )
        _best_effort_fsync(updates_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=updates_fd)
        except FileNotFoundError:
            pass


def _unlink_update_leaf(updates: Path, updates_fd: int | None, name: str) -> None:
    if updates_fd is None:
        (updates / name).unlink()
    else:
        os.unlink(name, dir_fd=updates_fd)
        _best_effort_fsync(updates_fd)


def _quarantine_update_leaf(updates: Path, updates_fd: int | None, name: str) -> None:
    quarantine = f".rejected-{name}.{uuid.uuid4().hex}"
    if updates_fd is None:
        source = updates / name
        try:
            source.lstat()
        except FileNotFoundError:
            return
        source.replace(updates / quarantine)
        return
    try:
        os.stat(name, dir_fd=updates_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    os.replace(name, quarantine, src_dir_fd=updates_fd, dst_dir_fd=updates_fd)
    _best_effort_fsync(updates_fd)


def _best_effort_fsync(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError:
        # The preceding rename/unlink is already visible and determines replay
        # behavior; retaining that result is safer than misreporting its state.
        pass


def _prepare_updates_dir(data_root: Path) -> Path:
    data_root = Path(data_root)
    data_details = data_root.lstat()
    if not stat.S_ISDIR(data_details.st_mode):
        raise ValueError("unsafe ALT data root")
    updates = data_root / "updates"
    try:
        updates.mkdir(mode=0o750)
    except FileExistsError:
        pass
    return _validate_updates_dir(data_root)


def _validate_updates_dir(data_root: Path) -> Path:
    data_root = Path(data_root)
    data_details = data_root.lstat()
    updates = data_root / "updates"
    updates_details = updates.lstat()
    if not stat.S_ISDIR(data_details.st_mode) or not stat.S_ISDIR(
        updates_details.st_mode
    ):
        raise ValueError("unsafe ALT updates directory")
    if os.name != "nt" and (
        updates_details.st_uid != data_details.st_uid
        or updates_details.st_gid != data_details.st_gid
        or stat.S_IMODE(updates_details.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError("unsafe ALT updates directory metadata")
    return updates


def _load_json_no_duplicates(value: str) -> Any:
    def reject_duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    return json.loads(value, object_pairs_hook=reject_duplicates)
