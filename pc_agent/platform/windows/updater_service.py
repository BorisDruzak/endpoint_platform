"""Offline, demand-start privileged updater for the Windows Endpoint Agent.

This process deliberately owns no listener and imports no HTTP client.  The
running agent reports its post-restart startup confirmation; this worker only
waits through the injected local confirmation boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any, Protocol

from .acl import EXPECTED_PRINCIPALS
from .service_control import SERVICE_NAME, UPDATER_SERVICE_NAME
from .update_paths import UPDATE_EXECUTABLE_NAME, WindowsUpdatePaths


_PENDING_FIELDS = frozenset(
    {
        "archive_type", "artifact_path", "channel", "operation_id",
        "requested_by", "requested_reason", "sha256", "size", "target", "version",
    }
)
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
STARTUP_DEADLINE_SECONDS = 120
UPDATER_START_PRINCIPALS = ("SYSTEM", "Administrators", "NT SERVICE\\EndpointAgent")


class UpdatePathSecurity(Protocol):
    def assert_update_path(self, path: Path) -> None: ...


class AgentService(Protocol):
    def stop(self) -> None: ...
    def start(self) -> None: ...
    def crashed_early(self) -> bool: ...


class ReleaseVerifier(Protocol):
    def verify(self, executable: Path) -> bool: ...


class StartupConfirmation(Protocol):
    def wait_for_startup(self, *, version: str, deadline_seconds: int) -> bool: ...


class PyWin32EndpointAgentService:
    """Fixed-name SCM control; callers cannot select another service."""

    def stop(self) -> None:
        self._modules().StopService(SERVICE_NAME)

    def start(self) -> None:
        self._modules().StartService(SERVICE_NAME)

    def crashed_early(self) -> bool:
        serviceutil = self._modules()
        status = serviceutil.QueryServiceStatus(SERVICE_NAME)
        return status[1] == serviceutil.win32service.SERVICE_STOPPED

    @staticmethod
    def _modules():
        try:
            import win32serviceutil  # type: ignore[import-not-found]
        except ImportError as error:
            raise RuntimeError("pywin32 is required to control EndpointAgent") from error
        return win32serviceutil


class SubprocessReleaseVerifier:
    """Run only the fixed candidate executable with its fixed verify argument."""

    def verify(self, executable: Path) -> bool:
        try:
            return subprocess.run(
                [str(executable), "--verify"], cwd=str(executable.parent),
                timeout=90, capture_output=True, check=False,
            ).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False


class FileStartupConfirmation:
    """Read the agent-written local confirmation after its server-side handshake.

    The confirmation producer belongs to EndpointAgent, which is the sole
    network client.  Keeping this worker file-only prevents a privileged
    second HTTP credential surface.
    """

    def __init__(self, paths: WindowsUpdatePaths) -> None:
        self._path = paths.updates_root / "startup-confirmation.json"

    def wait_for_startup(self, *, version: str, deadline_seconds: int) -> bool:
        deadline = time.monotonic() + deadline_seconds
        while time.monotonic() < deadline:
            try:
                _reject_reparse_path(self._path)
                payload = json.loads(self._path.read_text(encoding="utf-8"))
                if payload == {"status": "confirmed", "version": version}:
                    return True
            except (OSError, ValueError, json.JSONDecodeError):
                pass
            time.sleep(0.25)
        return False


@dataclass(frozen=True, slots=True)
class PendingUpdate:
    version: str
    artifact_path: Path
    archive_type: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class UpdateResult:
    status: str
    message: str = ""


class PyWin32UpdatePathSecurity:
    """Validate reparse, owner, and DACL identity without non-Windows imports."""

    def assert_update_path(self, path: Path) -> None:
        _reject_reparse_path(path)
        if os.name != "nt":
            raise ValueError("Windows owner and ACL inspection requires Windows")
        try:
            import win32security  # type: ignore[import-not-found]
        except ImportError as error:
            raise ValueError("pywin32 is required for Windows update ACL inspection") from error
        try:
            descriptor = win32security.GetNamedSecurityInfo(
                str(path), win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
            )
            owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
            dacl = descriptor.GetSecurityDescriptorDacl()
            if dacl is None or owner != "S-1-5-18":
                raise ValueError("wrong owner or ACL on update path")
            allowed = {
                win32security.ConvertSidToStringSid(dacl.GetAce(index)[2])
                for index in range(dacl.GetAceCount())
                if dacl.GetAce(index)[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE
            }
            # Reuse Task 11's exact SID identity policy, including the virtual
            # updater identity that writes the request leaf.
            expected = {"S-1-5-18", "S-1-5-32-544"}
            for principal in EXPECTED_PRINCIPALS[2:]:
                sid, _domain, _kind = win32security.LookupAccountName(None, principal)
                expected.add(win32security.ConvertSidToStringSid(sid))
            if not allowed or not allowed.issubset(expected):
                raise ValueError("wrong owner or ACL on update path")
        except ValueError:
            raise
        except Exception as error:
            raise ValueError("could not inspect update owner or ACL") from error


class PendingUpdateValidator:
    """Parse one strictly shaped pending request before any service operation."""

    def __init__(self, paths: WindowsUpdatePaths, security: UpdatePathSecurity | None = None) -> None:
        self._paths = paths
        self._security = security or PyWin32UpdatePathSecurity()

    def load(self) -> PendingUpdate:
        pending = self._paths.pending_path
        _assert_within(self._paths.updates_root, pending, "pending")
        _reject_reparse_chain(self._paths.updates_root, pending)
        self._security.assert_update_path(self._paths.updates_root)
        self._security.assert_update_path(pending)
        try:
            raw = pending.read_bytes()
        except OSError as error:
            raise ValueError("pending update is unreadable") from error
        if len(raw) > 16 * 1024:
            raise ValueError("pending update exceeds size limit")
        try:
            payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ValueError("invalid pending update JSON") from error
        if not isinstance(payload, dict) or set(payload) != _PENDING_FIELDS:
            raise ValueError("unknown or missing pending update fields")
        update = self._validate_payload(payload)
        self._assert_no_version_collision(update)
        return update

    def _validate_payload(self, payload: dict[str, Any]) -> PendingUpdate:
        if (
            payload["archive_type"] != "zip"
            or payload["target"] != "windows_amd64"
            or payload["channel"] not in {"stable", "canary"}
            or not isinstance(payload["version"], str)
            or not _SEMVER.fullmatch(payload["version"])
            or not isinstance(payload["sha256"], str)
            or not _SHA256.fullmatch(payload["sha256"])
            or not isinstance(payload["size"], int)
            or payload["size"] <= 0
        ):
            raise ValueError("invalid pending update fields")
        artifact_raw = payload["artifact_path"]
        if not isinstance(artifact_raw, str) or not artifact_raw:
            raise ValueError("invalid artifact path")
        artifact = Path(artifact_raw)
        _assert_within(self._paths.downloads_root, artifact, "artifact")
        _reject_reparse_chain(self._paths.downloads_root, artifact)
        if not artifact.is_file():
            raise ValueError("artifact is missing")
        details = artifact.stat()
        if details.st_size != payload["size"]:
            raise ValueError("artifact size mismatch")
        digest = _hash_file(artifact)
        if digest != payload["sha256"]:
            raise ValueError("artifact hash mismatch")
        return PendingUpdate(payload["version"], artifact, "zip", digest, details.st_size)

    def _assert_no_version_collision(self, update: PendingUpdate) -> None:
        target = self._paths.versions_root / update.version
        if not target.exists() and not target.is_symlink():
            return
        _reject_reparse_path(target)
        marker = target / ".endpoint-update.json"
        try:
            recorded = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError("target version collision") from error
        if recorded != {"sha256": update.sha256, "size": update.size, "version": update.version}:
            raise ValueError("target version collision with different bytes")


class WindowsUpdater:
    """Apply only a validated candidate and roll its selector back on bad startup."""

    def __init__(
        self, paths: WindowsUpdatePaths | None = None, *, acl: UpdatePathSecurity | None = None,
        service: AgentService | None = None, verifier: ReleaseVerifier | None = None,
        confirmation: StartupConfirmation | None = None,
        deadline_seconds: int = STARTUP_DEADLINE_SECONDS,
    ) -> None:
        self._paths = paths or WindowsUpdatePaths.production()
        self._validator = PendingUpdateValidator(self._paths, acl)
        self._service = service or PyWin32EndpointAgentService()
        self._verifier = verifier or SubprocessReleaseVerifier()
        self._confirmation = confirmation or FileStartupConfirmation(self._paths)
        self._deadline_seconds = deadline_seconds

    def run_once(self) -> UpdateResult:
        previous: str | None = None
        staging: Path | None = None
        service_stopped = False
        try:
            pending = self._validator.load()
            previous = _load_current(self._paths.current_path)
            self._service.stop()
            service_stopped = True
            staging = self._extract_to_staging(pending)
            executable = staging / UPDATE_EXECUTABLE_NAME
            if not executable.is_file() or not self._verifier.verify(executable):
                raise ValueError("new version verification failed")
            target = self._publish(staging, pending)
            _write_json_atomic(self._paths.previous_path, {"version": previous})
            _write_json_atomic(self._paths.current_path, {"version": pending.version})
            self._service.start()
            if self._service.crashed_early() or not self._confirmation.wait_for_startup(
                version=pending.version, deadline_seconds=self._deadline_seconds
            ):
                return self._rollback(previous, "startup confirmation failed")
            self._paths.pending_path.unlink()
            return UpdateResult("applied", str(target))
        except (OSError, ValueError, zipfile.BadZipFile) as error:
            if service_stopped and previous is not None:
                # Every failure after the controlled stop restores the known
                # selector before restarting the old agent.
                try:
                    _write_json_atomic(self._paths.current_path, {"version": previous})
                    self._service.start()
                except Exception:
                    pass
            return UpdateResult("rejected", str(error))
        finally:
            if staging is not None and staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

    def _extract_to_staging(self, pending: PendingUpdate) -> Path:
        staging_parent = self._paths.versions_root / "_staging"
        staging = staging_parent / uuid.uuid4().hex
        staging.mkdir(parents=True, exist_ok=False)
        try:
            with zipfile.ZipFile(pending.artifact_path) as archive:
                for member in archive.infolist():
                    _extract_zip_member(archive, member, staging)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return staging

    def _publish(self, staging: Path, pending: PendingUpdate) -> Path:
        target = self._paths.versions_root / pending.version
        if target.exists() or target.is_symlink():
            # Validator already proved identical provenance.  A replay can use
            # this immutable release without replacing it.
            shutil.rmtree(staging, ignore_errors=True)
            return target
        _write_json_atomic(staging / ".endpoint-update.json", {
            "sha256": pending.sha256, "size": pending.size, "version": pending.version,
        })
        os.replace(staging, target)
        return target

    def _rollback(self, previous: str, reason: str) -> UpdateResult:
        _write_json_atomic(self._paths.current_path, {"version": previous})
        self._service.start()
        return UpdateResult("rolled_back", reason)


def _no_duplicate_keys(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_reparse_path(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise ValueError("update path is missing") from error
    attributes = getattr(details, "st_file_attributes", 0)
    if path.is_symlink() or attributes & 0x400:
        raise ValueError("reparse point traversal is forbidden")


def _reject_reparse_chain(root: Path, leaf: Path) -> None:
    _assert_within(root, leaf, "update")
    current = root
    _reject_reparse_path(current)
    for part in leaf.relative_to(root).parts:
        current = current / part
        _reject_reparse_path(current)


def _assert_within(root: Path, path: Path, label: str) -> None:
    # Do lexical containment first.  resolve() is intentionally not used before
    # every component was checked for a Windows reparse point.
    try:
        path.absolute().relative_to(root.absolute())
    except ValueError as error:
        raise ValueError(f"{label} path is outside its fixed root") from error


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _extract_zip_member(archive: zipfile.ZipFile, member: zipfile.ZipInfo, staging: Path) -> None:
    name = member.filename.replace("\\", "/")
    candidate = PureWindowsPath(name)
    if not name or candidate.is_absolute() or ".." in candidate.parts or name.startswith("/"):
        raise ValueError("unsafe archive member")
    # Unix symlinks are represented in the upper mode bits even inside zip.
    if stat.S_IFMT(member.external_attr >> 16) == stat.S_IFLNK:
        raise ValueError("symlink archive member is forbidden")
    destination = staging.joinpath(*candidate.parts)
    _assert_within(staging, destination, "archive")
    if member.is_dir():
        destination.mkdir(parents=True, exist_ok=True)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    with archive.open(member) as source, destination.open("xb") as output:
        shutil.copyfileobj(source, output)


def _load_current(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("current selector is unreadable") from error
    version = payload.get("version") if isinstance(payload, dict) else None
    if not isinstance(version, str) or not _SEMVER.fullmatch(version):
        raise ValueError("current selector is invalid")
    return version


def _write_json_atomic(path: Path, payload: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


__all__ = [
    "AgentService", "FileStartupConfirmation", "PendingUpdate", "PendingUpdateValidator",
    "PyWin32EndpointAgentService", "PyWin32UpdatePathSecurity", "ReleaseVerifier",
    "STARTUP_DEADLINE_SECONDS", "StartupConfirmation", "SubprocessReleaseVerifier", "UPDATER_SERVICE_NAME",
    "UPDATER_START_PRINCIPALS", "UpdateResult", "UpdatePathSecurity", "WindowsUpdater",
]
