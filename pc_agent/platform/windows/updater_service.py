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
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Any, Protocol

from pc_agent.gateway_update_runtime import _is_eligible_recommendation

from .acl import EXPECTED_PRINCIPALS
from .service_control import SERVICE_NAME, UPDATER_SERVICE_NAME
from .update_paths import UPDATE_EXECUTABLE_NAME, WindowsUpdatePaths


_PENDING_FIELDS = frozenset(
    {
        "archive_type", "artifact_path", "channel", "operation_id",
        "received_at", "requested_by", "requested_reason", "sha256", "size", "target", "version",
    }
)
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ERROR_SERVICE_NOT_ACTIVE = 1062
STARTUP_DEADLINE_SECONDS = 120
UPDATER_START_PRINCIPALS = ("SYSTEM", "Administrators", "NT SERVICE\\EndpointAgent")
TERMINAL_OUTCOME_FILENAME = "terminal-outcome.json"


class UpdatePathSecurity(Protocol):
    def assert_update_path(self, path: Path) -> None: ...


class AgentService(Protocol):
    def stop(self) -> None: ...
    def start(self) -> None: ...
    def wait_stopped(self) -> bool: ...
    def crashed_early(self) -> bool: ...


class ReleaseVerifier(Protocol):
    def verify(self, executable: Path) -> bool: ...


class StartupConfirmation(Protocol):
    def is_confirmed(self, *, version: str, operation_id: str, attempt_id: str, not_before: datetime) -> bool: ...


class PyWin32EndpointAgentService:
    """Fixed-name SCM control; callers cannot select another service."""

    def stop(self) -> None:
        self._modules().StopService(SERVICE_NAME)

    def start(self) -> None:
        self._modules().StartService(SERVICE_NAME)

    def wait_stopped(self) -> bool:
        serviceutil = self._modules()
        try:
            serviceutil.WaitForServiceStatus(SERVICE_NAME, serviceutil.win32service.SERVICE_STOPPED, 30)
            return True
        except Exception:
            return False

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
    """Run the fixed candidate verifier against the fixed enrolled local state."""

    def __init__(self, paths: WindowsUpdatePaths) -> None:
        self._data_root = paths.updates_root.parent
        self._install_root = paths.install_root
        self._ca_file = self._data_root / "endpoint-ca.crt"

    def verify(self, executable: Path) -> bool:
        try:
            return subprocess.run(
                [
                    str(executable), "--verify", "--data-dir", str(self._data_root),
                    "--install-root", str(self._install_root), "--ca-file", str(self._ca_file),
                ],
                cwd=str(executable.parent),
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

    def is_confirmed(self, *, version: str, operation_id: str, attempt_id: str, not_before: datetime) -> bool:
        try:
            _reject_reparse_path(self._path)
            payload = json.loads(self._path.read_text(encoding="utf-8"))
            confirmed_at = datetime.fromisoformat(payload["confirmed_at"])
            if confirmed_at.tzinfo is None:
                return False
            return payload == {
                "attempt_id": attempt_id, "confirmed_at": payload["confirmed_at"], "operation_id": operation_id,
                "status": "confirmed", "version": version,
            } and confirmed_at >= not_before
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return False


@dataclass(frozen=True, slots=True)
class PendingUpdate:
    version: str
    artifact_path: Path
    archive_type: str
    sha256: str
    size: int
    operation_id: str
    received_at: datetime
    requested_reason: str


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
            import ntsecuritycon  # type: ignore[import-not-found]
            import win32security  # type: ignore[import-not-found]
        except ImportError as error:
            raise ValueError("pywin32 is required for Windows update ACL inspection") from error
        try:
            descriptor = win32security.GetNamedSecurityInfo(
                str(path), win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
            )
            owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
            if owner not in {"S-1-5-18", "S-1-5-19"}:
                raise ValueError("wrong owner or ACL on update path")
            _validate_strict_update_dacl(
                descriptor,
                win32security,
                ntsecuritycon,
                allow_child_inheritance=path.is_dir(),
            )
        except ValueError:
            raise
        except Exception as error:
            raise ValueError("could not inspect update owner or ACL") from error


def _validate_strict_update_dacl(
    descriptor, win32security, rights=None, *, allow_child_inheritance: bool = False,
) -> None:
    """Require Task 11's protected DACL, including only a directory's child ACEs."""
    control, _revision = descriptor.GetSecurityDescriptorControl()
    if not control & win32security.SE_DACL_PROTECTED:
        raise ValueError("wrong owner or ACL on update path")
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None or dacl.GetAceCount() != 4:
        raise ValueError("wrong owner or ACL on update path")
    expected_sids = {"S-1-5-18", "S-1-5-32-544"}
    for principal in EXPECTED_PRINCIPALS[2:]:
        sid, _domain, _kind = win32security.LookupAccountName(None, principal)
        expected_sids.add(win32security.ConvertSidToStringSid(sid))
    rights = win32security if rights is None else rights
    expected_masks = {
        "S-1-5-18": rights.FILE_ALL_ACCESS,
        "S-1-5-32-544": rights.FILE_ALL_ACCESS,
    }
    limited = (
        rights.FILE_GENERIC_READ | rights.FILE_GENERIC_WRITE | rights.DELETE
    )
    for sid in expected_sids - set(expected_masks):
        expected_masks[sid] = limited
    actual: dict[str, int] = {}
    expected_flags = 0
    if allow_child_inheritance:
        expected_flags = (
            win32security.OBJECT_INHERIT_ACE
            | win32security.CONTAINER_INHERIT_ACE
        )
    for index in range(dacl.GetAceCount()):
        header, mask, sid = dacl.GetAce(index)
        ace_type, ace_flags = header
        if (
            ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE
            or ace_flags != expected_flags
        ):
            raise ValueError("wrong owner or ACL on update path")
        sid_text = win32security.ConvertSidToStringSid(sid)
        if sid_text in actual:
            raise ValueError("wrong owner or ACL on update path")
        actual[sid_text] = mask
    if actual != expected_masks:
        raise ValueError("wrong owner or ACL on update path")


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
        return self._validate_payload(payload)

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
            or isinstance(payload["size"], bool)
            or payload["size"] <= 0
            or not isinstance(payload["requested_reason"], str)
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
        try:
            received_at = datetime.fromisoformat(payload["received_at"])
            if received_at.tzinfo is None or not isinstance(payload["operation_id"], str):
                raise ValueError
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("invalid received_at or operation_id") from error
        return PendingUpdate(
            payload["version"], artifact, "zip", digest, details.st_size,
            payload["operation_id"], received_at, payload["requested_reason"],
        )


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
        self._verifier = verifier or SubprocessReleaseVerifier(self._paths)
        self._confirmation = confirmation or FileStartupConfirmation(self._paths)
        self._deadline_seconds = deadline_seconds
        self._attempt_id: str | None = None

    def run_once(self) -> UpdateResult:
        previous: str | None = None
        pending: PendingUpdate | None = None
        staging: Path | None = None
        service_stopped = False
        try:
            pending = self._validator.load()
            previous = _load_current(self._paths.current_path)
            if not _is_eligible_recommendation(
                pending.version, previous, pending.requested_reason
            ):
                raise ValueError("candidate version is not eligible from current selector")
            try:
                self._service.stop()
            except Exception as error:
                if not _is_service_not_active(error):
                    raise
            service_stopped = True
            if not self._service.wait_stopped():
                raise ValueError("EndpointAgent did not stop")
            staging = self._extract_to_staging(pending)
            executable = staging / UPDATE_EXECUTABLE_NAME
            if not executable.is_file() or not self._verifier.verify(executable):
                raise ValueError("new version verification failed")
            target = self._publish(staging, pending)
            _write_json_atomic(self._paths.previous_path, {"version": previous})
            _write_json_atomic(self._paths.current_path, {"version": pending.version})
            self._attempt_id = _write_startup_attempt(self._paths, pending)
            try:
                self._service.start()
            except Exception:
                _clear_startup_attempt(self._paths)
                raise
            if not self._wait_for_candidate_confirmation(pending):
                return self._rollback(pending, previous, "startup confirmation failed")
            self._paths.pending_path.unlink()
            _clear_startup_attempt(self._paths)
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
            if pending is not None and previous is not None:
                _write_terminal_outcome(
                    self._paths,
                    operation_id=pending.operation_id,
                    status="failed",
                    reported_version=previous,
                    safe_code="launcher_apply_failed",
                )
            return UpdateResult("rejected", str(error))
        finally:
            if staging is not None and staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

    def _extract_to_staging(self, pending: PendingUpdate) -> Path:
        staging_parent = self._paths.versions_root / "_staging"
        staging = staging_parent / uuid.uuid4().hex
        staging.mkdir(parents=True, exist_ok=False)
        artifact_copy: Path | None = None
        try:
            artifact_copy = _pin_artifact(pending, staging_parent)
            with zipfile.ZipFile(artifact_copy) as archive:
                for member in archive.infolist():
                    _extract_zip_member(archive, member, staging)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        finally:
            if artifact_copy is not None:
                artifact_copy.unlink(missing_ok=True)
        return staging

    def _publish(self, staging: Path, pending: PendingUpdate) -> Path:
        target = self._paths.versions_root / pending.version
        if target.exists() or target.is_symlink():
            _reject_reparse_path(target)
            if _release_manifest(target) != _release_manifest(staging):
                raise ValueError("target version collision with different bytes")
            shutil.rmtree(staging, ignore_errors=True)
            return target
        _write_json_atomic(staging / ".endpoint-update.json", {
            "sha256": pending.sha256, "size": pending.size, "version": pending.version,
        })
        os.replace(staging, target)
        return target

    def _rollback(
        self, pending: PendingUpdate, previous: str, reason: str
    ) -> UpdateResult:
        try:
            self._service.stop()
        except Exception as error:
            # StopService reports ERROR_SERVICE_NOT_ACTIVE for an early crash;
            # that is already the desired stopped state.
            if not _is_service_not_active(error):
                return UpdateResult("rejected", "candidate stop failed for rollback")
            stopped = True
        else:
            try:
                stopped = self._service.wait_stopped()
            except Exception:
                return UpdateResult("rejected", "candidate stop state is unknown")
            if not stopped:
                return UpdateResult("rejected", "candidate did not stop for rollback")
        _write_json_atomic(self._paths.current_path, {"version": previous})
        _clear_startup_attempt(self._paths)
        self._service.start()
        _write_terminal_outcome(
            self._paths,
            operation_id=pending.operation_id,
            status="rolled_back",
            reported_version=previous,
            safe_code="launcher_rolled_back",
        )
        return UpdateResult("rolled_back", reason)

    def _wait_for_candidate_confirmation(self, pending: PendingUpdate) -> bool:
        deadline = __import__("time").monotonic() + self._deadline_seconds
        while __import__("time").monotonic() < deadline:
            if self._service.crashed_early():
                return False
            if self._confirmation.is_confirmed(
                version=pending.version, operation_id=pending.operation_id, attempt_id=self._attempt_id or "", not_before=pending.received_at
            ):
                return True
            __import__("time").sleep(0.25)
        return False


def _pin_artifact(pending: PendingUpdate, destination_parent: Path) -> Path:
    """Copy from one opened, revalidated descriptor; extraction never reopens input path."""
    _reject_reparse_path(pending.artifact_path)
    before = pending.artifact_path.stat()
    descriptor = os.open(pending.artifact_path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    copied = destination_parent / f".artifact-{uuid.uuid4().hex}.zip"
    try:
        opened = os.fstat(descriptor)
        if (opened.st_size != pending.size or opened.st_size != before.st_size or _hash_descriptor(descriptor) != pending.sha256):
            raise ValueError("artifact changed before extraction")
        os.lseek(descriptor, 0, os.SEEK_SET)
        with copied.open("xb") as output:
            while block := os.read(descriptor, 1024 * 1024):
                output.write(block)
        if _hash_file(copied) != pending.sha256 or copied.stat().st_size != pending.size:
            raise ValueError("artifact copy verification failed")
        return copied
    except Exception:
        copied.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def _hash_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    while block := os.read(descriptor, 1024 * 1024):
        digest.update(block)
    return digest.hexdigest()


def _release_manifest(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.is_file() and path.name != ".endpoint-update.json":
            result[path.relative_to(root).as_posix()] = _hash_file(path)
    return result


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
        with temporary.open("x", encoding="utf-8") as output:
            output.write(json.dumps(payload, separators=(",", ":")))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _flush_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _flush_directory(path: Path) -> None:
    """Persist atomic-rename metadata before starting a marker consumer."""
    if os.name == "nt":
        try:
            import win32con  # type: ignore[import-not-found]
            import win32file  # type: ignore[import-not-found]
        except ImportError as error:
            raise OSError("pywin32 is required for Windows directory durability") from error
        handle = win32file.CreateFile(
            str(path),
            win32con.GENERIC_READ | win32con.GENERIC_WRITE,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        try:
            win32file.FlushFileBuffers(handle)
        finally:
            handle.Close()
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_startup_attempt(paths: WindowsUpdatePaths, pending: PendingUpdate) -> str:
    attempt_id = uuid.uuid4().hex
    _write_json_atomic(
        paths.updates_root / "startup-attempt.json",
        {"attempt_id": attempt_id, "operation_id": pending.operation_id, "version": pending.version},
    )
    return attempt_id


def _clear_startup_attempt(paths: WindowsUpdatePaths) -> None:
    (paths.updates_root / "startup-attempt.json").unlink(missing_ok=True)


def _write_terminal_outcome(
    paths: WindowsUpdatePaths,
    *,
    operation_id: str,
    status: str,
    reported_version: str,
    safe_code: str,
) -> None:
    """Leave a bounded outcome for EndpointAgent to report after WSS reconnects."""
    _write_json_atomic(
        paths.updates_root / TERMINAL_OUTCOME_FILENAME,
        {
            "operation_id": operation_id,
            "reported_version": reported_version,
            "safe_code": safe_code,
            "status": status,
        },
    )


def _is_service_not_active(error: Exception) -> bool:
    winerror = getattr(error, "winerror", None)
    return (
        isinstance(winerror, int)
        and not isinstance(winerror, bool)
        and winerror == _ERROR_SERVICE_NOT_ACTIVE
    )


def run_windows_updater_service() -> int:
    """Host the MSI-registered demand-start ``EndpointAgentUpdater`` service."""
    try:
        import servicemanager  # type: ignore[import-not-found]
        import win32serviceutil  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("pywin32 is required for EndpointAgentUpdater") from error

    class EndpointAgentUpdaterWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = UPDATER_SERVICE_NAME
        _svc_display_name_ = "Endpoint Agent Updater"
        _svc_description_ = "Demand-start offline Endpoint Agent update worker"

        def SvcDoRun(self) -> None:
            result = WindowsUpdater().run_once()
            if result.status not in {"applied", "rolled_back"}:
                # Let PythonService.service_main translate the exception into
                # its native service-specific terminal failure.  The native
                # host owns the sole SERVICE_STOPPED report after SvcRun exits.
                raise RuntimeError(
                    "EndpointAgentUpdater worker failed with "
                    f"status {result.status!r}: {result.message}"
                )

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(EndpointAgentUpdaterWindowsService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0


__all__ = [
    "AgentService", "FileStartupConfirmation", "PendingUpdate", "PendingUpdateValidator",
    "PyWin32EndpointAgentService", "PyWin32UpdatePathSecurity", "ReleaseVerifier",
    "STARTUP_DEADLINE_SECONDS", "StartupConfirmation", "SubprocessReleaseVerifier", "UPDATER_SERVICE_NAME",
    "UPDATER_START_PRINCIPALS", "UpdateResult", "UpdatePathSecurity", "WindowsUpdater", "run_windows_updater_service",
]
