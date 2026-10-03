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
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Protocol

from pc_agent.update_eligibility import _is_eligible_recommendation

from .acl import EXPECTED_PRINCIPALS, PyWin32AclAdapter, WindowsAclError, preserve_state_file_permissions, assert_state_file_permissions_match
from .durable_state import durable_unlink, flush_directory, write_bytes_atomic, write_json_atomic, publish_prepared
from .disk_readiness import allocation_required_bytes, apply_required_bytes, is_disk_full, require_disk_space
from .service_control import SERVICE_NAME, UPDATER_SERVICE_NAME
from .update_paths import UPDATE_EXECUTABLE_NAME, WindowsUpdatePaths
from .update_transaction import update_transaction, UpdateInProgress


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
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")
_ERROR_SERVICE_NOT_ACTIVE = 1062
STARTUP_DEADLINE_SECONDS = 600
UPDATER_START_PRINCIPALS = ("SYSTEM", "Administrators", "NT SERVICE\\EndpointAgent")
TERMINAL_OUTCOME_FILENAME = "terminal-outcome.json"
BUNDLE_MANIFEST_FILENAME = "endpoint-update-manifest.json"
MAX_PENDING_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024


class UpdatePathSecurity(Protocol):
    def assert_update_path(self, path: Path) -> None: ...


class AgentService(Protocol):
    def stop(self) -> None: ...
    def start(self) -> None: ...
    def wait_stopped(self) -> bool: ...
    def crashed_early(self) -> bool: ...


class ReleaseVerifier(Protocol):
    def verify(self, executable: Path, expected_version: str) -> bool: ...


class StartupConfirmation(Protocol):
    def is_confirmed(self, *, version: str, operation_id: str, attempt_id: str, not_before: datetime) -> bool: ...


class TrayStatusPublisher(Protocol):
    """Narrow local projection boundary; this worker never receives network state."""

    def publish(
        self,
        *,
        agent_state: str,
        endpoint_state: str,
        update_state: str,
        reason_code: str | None = None,
    ) -> None: ...


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

    def verify(self, executable: Path, expected_version: str) -> bool:
        try:
            version = subprocess.run(
                [str(executable), "--print-version"],
                cwd=str(executable.parent),
                timeout=30, capture_output=True, text=True, check=False,
            )
            if version.returncode != 0 or version.stdout.strip() != expected_version:
                return False
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
class BundleManifest:
    version: str
    source_revision: str


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
            or payload["size"] > MAX_PENDING_ARCHIVE_BYTES
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
        tray_status_writer: TrayStatusPublisher | None = None,
        deadline_seconds: int = STARTUP_DEADLINE_SECONDS,
    ) -> None:
        self._paths = paths or WindowsUpdatePaths.production()
        self._validator = PendingUpdateValidator(self._paths, acl)
        self._service = service or PyWin32EndpointAgentService()
        self._verifier = verifier or SubprocessReleaseVerifier(self._paths)
        self._confirmation = confirmation or FileStartupConfirmation(self._paths)
        self._tray_status_writer = tray_status_writer
        self._deadline_seconds = deadline_seconds
        self._attempt_id: str | None = None
        self._transition: dict[str, object] | None = None
        self._proof_confirmed = False

    def run_once(self) -> UpdateResult:
        transaction = ExitStack()
        try:
            transaction.enter_context(update_transaction(self._paths))
        except UpdateInProgress:
            return UpdateResult("update_in_progress", "UPDATE_IN_PROGRESS")
        # A snapshot is required only across unlocked extraction/proof phases.
        # Errors while ownership remains held recover without opening a new race.
        held = True
        authority = None

        def release_for_work(pending):
            nonlocal held, authority
            authority = self._authority_snapshot(pending)
            transaction.close()
            held = False

        def reacquire():
            nonlocal held
            transaction.enter_context(update_transaction(self._paths))
            held = True
            try:
                return self._authority_snapshot(pending) == authority
            except (OSError, ValueError, WindowsAclError):
                return False

        previous: str | None = None
        previous_selector: dict[str, object] | None = None
        pending: PendingUpdate | None = None
        staging: Path | None = None
        service_stopped = False
        candidate_confirmed = False
        self._proof_confirmed = False
        self._transition = None
        try:
            self._transition = _load_selector_transition(self._paths)
            if self._transition is not None and self._transition["status"] == "accepted":
                # Acceptance was durably recorded before pending/proof deletion;
                # cleanup no longer depends on a retained archive or proof leaf.
                if _load_selector(self._paths.current_path) != self._transition["candidate"]:
                    raise ValueError("accepted selector transition does not match current")
                self._complete_accepted()
                return UpdateResult("applied", "accepted transition cleanup completed")
            if self._transition is not None and not self._paths.pending_path.exists():
                expected = bytes.fromhex(self._transition["previous_bytes"])
                _reject_reparse_chain(self._paths.install_root, self._paths.current_path)
                if self._paths.current_path.read_bytes() != expected:
                    raise ValueError("unconfirmed transition is missing pending identity")
                # A terminal-report cleanup may already have deleted pending.
                # Exact old bytes permit barrier cleanup, never candidate acceptance.
                flush_directory(self._paths.install_root)
                self._clear_transition()
                return UpdateResult("rejected", "known-good transition cleanup completed")
            try:
                pending = self._validator.load()
            except (OSError, ValueError) as error:
                _quarantine_invalid_pending(self._paths, self._validator._security)
                return UpdateResult("rejected", str(error))
            if self._transition is not None:
                recovered = self._reconcile_transition(pending)
                if recovered is not None:
                    return recovered
            previous_selector = _load_selector(self._paths.current_path)
            previous = _selector_version(previous_selector)
            if not _is_eligible_recommendation(
                pending.version, previous, pending.requested_reason
            ):
                raise ValueError("candidate version is not eligible from current selector")
            self._publish_tray_status(
                previous,
                agent_state="starting",
                endpoint_state="unknown",
                update_state="applying",
            )
            # Pending is durable authority while costly extraction runs unlocked.
            release_for_work(pending)
            staging = self._extract_to_staging(pending)
            bundle = _load_bundle_manifest(staging, pending)
            executable = staging / UPDATE_EXECUTABLE_NAME
            if not executable.is_file() or not self._verifier.verify(executable, pending.version):
                raise ValueError("new version verification failed")
            if not reacquire():
                return UpdateResult("rejected", "update identity changed during staging")
            target = self._publish(staging, pending)
            # Existing core/retention occupies space already. Reserve only the
            # new selector/journal allocations on each of their target volumes.
            require_disk_space(self._paths.install_root, allocation_required_bytes(24 * 1024))
            require_disk_space(self._paths.updates_root, allocation_required_bytes(8192))
            _write_json_atomic(self._paths.previous_path, previous_selector,
                trusted_root=self._paths.install_root, template=self._paths.current_path)
            # The old core cannot confirm this attempt: proof requires pending,
            # selected and compiled versions to agree. A retry uses a fresh id.
            self._attempt_id = _write_startup_attempt(self._paths, pending)
            candidate_selector = {
                "schema_version": 1, "source_revision": bundle.source_revision, "version": pending.version,
            }
            self._prepare_transition(pending, candidate_selector)
            try:
                self._service.stop()
            except Exception as error:
                if not _is_service_not_active(error):
                    raise
            service_stopped = True
            if not self._service.wait_stopped():
                raise ValueError("EndpointAgent did not stop")
            _write_json_atomic(self._paths.current_path, candidate_selector, trusted_root=self._paths.install_root)
            self._service.start()
            # Candidate WSS/HTTP owners must run while proof is awaited.
            release_for_work(pending)
            confirmed = self._wait_for_candidate_confirmation(pending)
            if not reacquire():
                return UpdateResult("rejected", "update identity changed during confirmation")
            if not confirmed:
                result = self._rollback(
                    pending, previous, previous_selector, "startup confirmation failed"
                )
                self._publish_tray_status(
                    previous,
                    agent_state="error",
                    endpoint_state="unknown",
                    update_state="failed",
                    reason_code="UPDATE_ROLLBACK",
                )
                return result
            candidate_confirmed = True
            self._mark_accepted()
            self._complete_accepted()
            return UpdateResult("applied", str(target))
        except UpdateInProgress:
            return UpdateResult("update_in_progress", "UPDATE_IN_PROGRESS")
        except (OSError, ValueError, WindowsAclError, zipfile.BadZipFile) as error:
            # Extraction errors also mutate terminal state under the boundary.
            if not held:
                try:
                    if not reacquire():
                        return UpdateResult("rejected", "update identity changed during unlocked work")
                except UpdateInProgress:
                    return UpdateResult("update_in_progress", "UPDATE_IN_PROGRESS")
            if candidate_confirmed or self._proof_confirmed:
                # Acceptance already has operation-bound WSS proof. A failed
                # lifecycle cleanup must not switch a still-running candidate
                # to the previous selector or create a contradictory failure.
                return UpdateResult("rejected", "confirmed candidate cleanup pending")
            if self._transition is not None and self._transition["status"] == "accepted":
                return UpdateResult("rejected", "accepted transition cleanup pending")
            disk_full = is_disk_full(error)
            if not disk_full and pending is not None and previous is not None:
                self._record_terminal_outcome(
                    operation_id=pending.operation_id,
                    status="failed",
                    reported_version=previous,
                    safe_code="launcher_apply_failed",
                )
            if service_stopped and previous_selector is not None:
                # Every failure after the controlled stop restores the known
                # selector before restarting the old agent.
                try:
                    self._restore_prepared()
                    self._service.start()
                except Exception:
                    # A file fsync/allocation failure may leave the old selector
                    # unchanged. It is safe to restart only after checking it.
                    try:
                        if _load_selector(self._paths.current_path) == previous_selector:
                            self._service.start()
                    except Exception:
                        pass
            if not disk_full and self._transition is not None:
                try:
                    if _load_selector(self._paths.current_path) == previous_selector:
                        flush_directory(self._paths.install_root)
                        self._clear_transition()
                except (OSError, ValueError, WindowsAclError):
                    pass
            if pending is not None and previous is not None:
                self._publish_tray_status(
                    previous,
                    agent_state="error",
                    endpoint_state="unknown",
                    update_state="failed",
                    reason_code="UPDATE_APPLY",
                )
            if disk_full:
                return UpdateResult("disk_insufficient", "DISK_INSUFFICIENT")
            return UpdateResult("rejected", str(error))
        finally:
            transaction.close()
            if staging is not None and staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

    def _record_terminal_outcome(self, **outcome) -> None:
        try:
            _write_terminal_outcome(self._paths, **outcome)
        except (OSError, WindowsAclError):
            # Journal exhaustion must not strand the known-good service stopped.
            # Remove/quarantine the stale handoff before restarting when possible;
            # reporting may be unavailable until filesystem health is restored.
            _quarantine_invalid_pending(self._paths, self._validator._security)

    def _write_transition(self) -> None:
        write_json_atomic(self._paths.transition_path, self._transition,
            trusted_root=self._paths.install_root, max_bytes=16 * 1024,
            protect=lambda temporary: preserve_state_file_permissions(self._paths.current_path, temporary))

    def _authority_snapshot(self, pending: PendingUpdate) -> tuple[object, ...]:
        """Read operation, selector, transition and attempt under the transaction."""
        actual_pending = self._validator.load()
        if actual_pending != pending:
            raise ValueError("pending operation changed")
        attempt_path = self._paths.updates_root / "startup-attempt.json"
        attempt = None
        if attempt_path.exists() or attempt_path.is_symlink():
            _reject_reparse_chain(self._paths.updates_root, attempt_path)
            self._validator._security.assert_update_path(attempt_path)
            with attempt_path.open("rb") as source:
                attempt = source.read(4097)
            if len(attempt) > 4096:
                raise ValueError("startup attempt exceeds bound")
        return (actual_pending, _load_selector(self._paths.current_path),
                _load_selector_transition(self._paths), attempt)

    def _prepare_transition(self, pending: PendingUpdate, candidate: dict[str, object]) -> None:
        _reject_reparse_chain(self._paths.install_root, self._paths.current_path)
        with self._paths.current_path.open("rb") as current:
            previous_bytes = current.read(4097)
        if not 0 < len(previous_bytes) <= 4096:
            raise ValueError("known-good selector exceeds restore bound")
        _validate_selector(json.loads(previous_bytes, object_pairs_hook=_no_duplicate_keys))
        write_bytes_atomic(self._paths.restore_path, previous_bytes, trusted_root=self._paths.install_root,
            max_bytes=4096, protect=lambda temporary: preserve_state_file_permissions(self._paths.current_path, temporary))
        self._transition = {
            "schema_version": 1, "status": "prepared", "previous_bytes": previous_bytes.hex(), "candidate": candidate,
            "operation_id": pending.operation_id, "attempt_id": self._attempt_id,
            "artifact_sha256": pending.sha256, "artifact_size": pending.size,
            "received_at": pending.received_at.isoformat(), "requested_reason": pending.requested_reason,
        }
        self._write_transition()

    def _matches_transition(self, pending) -> bool:
        transition = self._transition
        try:
            same_time = datetime.fromisoformat(pending.get("received_at", "")) == datetime.fromisoformat(transition["received_at"])
        except (ValueError, TypeError):
            return False
        if not same_time or type(pending.get("size")) is not int:
            return False
        return all(pending.get(key) == value for key, value in {
            "version": transition["candidate"]["version"], "operation_id": transition["operation_id"],
            "sha256": transition["artifact_sha256"], "size": transition["artifact_size"],
            "requested_reason": transition["requested_reason"],
        }.items())

    def _clear_transition(self) -> None:
        durable_unlink(self._paths.restore_path, trusted_root=self._paths.install_root, missing_ok=True)
        durable_unlink(self._paths.transition_path, trusted_root=self._paths.install_root, missing_ok=True)
        self._transition = None

    def _restore_prepared(self) -> None:
        if self._transition is None:
            raise ValueError("known-good restoration is not prepared")
        expected = bytes.fromhex(self._transition["previous_bytes"])
        _reject_reparse_chain(self._paths.install_root, self._paths.current_path)
        if self._paths.current_path.read_bytes() == expected:
            # A previous replacement may be visible despite failed metadata fsync.
            flush_directory(self._paths.install_root)
            return
        publish_prepared(self._paths.restore_path, self._paths.current_path,
            expected_bytes=expected, trusted_root=self._paths.install_root, max_bytes=4096,
            validate=lambda source: assert_state_file_permissions_match(self._paths.current_path, source))

    def _mark_accepted(self) -> None:
        accepted = dict(self._transition)
        accepted["status"] = "accepted"
        # Keep memory prepared until the protected acceptance record is durable.
        previous_transition = self._transition
        self._transition = accepted
        try:
            self._write_transition()
        except (OSError, ValueError, WindowsAclError):
            self._transition = previous_transition
            raise

    def _complete_accepted(self) -> None:
        # Visible accepted state or prior cleanup deletion is not durable success
        # until its interrupted directory barrier has completed on retry.
        flush_directory(self._paths.install_root)
        if self._paths.pending_path.exists():
            _reject_reparse_chain(self._paths.updates_root, self._paths.pending_path)
            with self._paths.pending_path.open("rb") as pending:
                payload = json.loads(pending.read(16 * 1024 + 1), object_pairs_hook=_no_duplicate_keys)
            if not isinstance(payload, dict) or not self._matches_transition(payload):
                raise ValueError("accepted transition pending identity differs")
            self._validator._security.assert_update_path(self._paths.pending_path)
        durable_unlink(self._paths.pending_path, trusted_root=self._paths.updates_root, missing_ok=True)
        _clear_startup_attempt(self._paths)
        self._clear_transition()

    def _reconcile_transition(self, pending: PendingUpdate) -> UpdateResult | None:
        if not self._matches_transition({"version": pending.version, "operation_id": pending.operation_id,
            "sha256": pending.sha256, "size": pending.size, "received_at": pending.received_at.isoformat(),
            "requested_reason": pending.requested_reason}):
            raise ValueError("selector transition pending identity differs")
        current = _load_selector(self._paths.current_path)
        previous = _validate_selector(json.loads(bytes.fromhex(self._transition["previous_bytes"])))
        attempt_path = self._paths.updates_root / "startup-attempt.json"
        _reject_reparse_chain(self._paths.updates_root, attempt_path)
        self._validator._security.assert_update_path(attempt_path)
        with attempt_path.open("rb") as attempt_file:
            attempt = json.loads(attempt_file.read(4097), object_pairs_hook=_no_duplicate_keys)
        if attempt != {"attempt_id": self._transition["attempt_id"], "operation_id": pending.operation_id, "version": pending.version}:
            raise ValueError("selector transition startup attempt differs")
        self._attempt_id = self._transition["attempt_id"]
        if current == previous:
            try:
                self._restore_prepared()
            finally:
                # A failed metadata barrier must not strand the exact known-good core.
                if self._paths.current_path.read_bytes() == bytes.fromhex(self._transition["previous_bytes"]):
                    self._start_known_good()
            self._clear_transition()
            return None
        if current != self._transition["candidate"]:
            raise ValueError("selector transition candidate differs")
        target = self._paths.versions_root / pending.version
        _reject_reparse_chain(self._paths.versions_root, target)
        for index, child in enumerate(target.rglob("*")):
            if index >= MAX_ARCHIVE_MEMBERS:
                raise ValueError("recovery payload member count exceeds limit")
            _reject_reparse_path(child)
        receipt = json.loads((target / ".endpoint-update.json").read_text(encoding="utf-8"))
        bundle = _load_bundle_manifest(target, pending)
        if (receipt != {"version": pending.version, "sha256": pending.sha256, "size": pending.size}
            or bundle.source_revision != current["source_revision"]):
            raise ValueError("selector transition published payload differs")
        if self._confirmation.is_confirmed(version=pending.version, operation_id=pending.operation_id,
            attempt_id=self._attempt_id, not_before=pending.received_at):
            self._proof_confirmed = True
            self._mark_accepted()
            self._complete_accepted()
            return UpdateResult("applied", "proven transition cleanup completed")
        try:
            self._service.stop()
        except Exception as error:
            if not _is_service_not_active(error):
                return UpdateResult("rejected", "interrupted candidate stop failed")
        if not self._service.wait_stopped():
            raise ValueError("interrupted candidate did not stop")
        try:
            self._restore_prepared()
        finally:
            # Only exact known-good bytes justify restart on a failed metadata flush.
            if self._paths.current_path.read_bytes() == bytes.fromhex(self._transition["previous_bytes"]):
                self._start_known_good()
        self._clear_transition()
        return None

    def _start_known_good(self) -> None:
        try:
            self._service.start()
        except Exception as error:
            if getattr(error, "winerror", None) != 1056:
                raise

    def _publish_tray_status(
        self,
        version: str,
        *,
        agent_state: str,
        endpoint_state: str,
        update_state: str,
        reason_code: str | None = None,
    ) -> None:
        """Best-effort only: a tray write cannot change update safety semantics."""
        writer = self._tray_status_writer
        if writer is None:
            try:
                from .tray_status import TrayStatusWriter

                writer = TrayStatusWriter(self._paths.updates_root.parent, version)
                self._tray_status_writer = writer
            except Exception:
                return
        try:
            writer.publish(
                agent_state=agent_state,
                endpoint_state=endpoint_state,
                update_state=update_state,
                reason_code=reason_code,
            )
        except Exception:
            return

    def _extract_to_staging(self, pending: PendingUpdate) -> Path:
        staging_parent = self._paths.versions_root / "_staging"
        _reject_reparse_path(pending.artifact_path)
        with pending.artifact_path.open("rb") as source:
            if os.fstat(source.fileno()).st_size != pending.size or _hash_descriptor(source.fileno()) != pending.sha256:
                raise ValueError("artifact changed before extraction")
            source.seek(0)
            with zipfile.ZipFile(source) as archive:
                expanded = _validate_archive_limits(archive.infolist())
        require_disk_space(staging_parent, apply_required_bytes(pending.size, expanded))
        staging = staging_parent / uuid.uuid4().hex
        staging.mkdir(parents=True, exist_ok=False)
        artifact_copy: Path | None = None
        try:
            artifact_copy = _pin_artifact(pending, staging_parent)
            with zipfile.ZipFile(artifact_copy) as archive:
                members = archive.infolist()
                pinned_expanded = _validate_archive_limits(members)
                if pinned_expanded != expanded:
                    raise ValueError("artifact changed before extraction")
                for member in members:
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
            for child in target.rglob("*"):
                _reject_reparse_path(child)
            bundle_path = target / BUNDLE_MANIFEST_FILENAME
            if bundle_path.exists():
                try:
                    receipt = json.loads(
                        (target / ".endpoint-update.json").read_text(encoding="utf-8"),
                        object_pairs_hook=_no_duplicate_keys,
                    )
                except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    receipt = None
                matches = (
                    receipt == {
                        "sha256": pending.sha256,
                        "size": pending.size,
                        "version": pending.version,
                    }
                    and _release_manifest(target) == _release_manifest(staging)
                )
            else:
                # MSI and retained MSI ownership cannot become ZIP ownership
                # merely because the payload bytes happen to match.
                matches = False
            if not matches:
                raise ValueError("target version collision with different bytes")
            # A prior rename can be visible even though its parent flush
            # failed. Reuse is success only after finishing that same barrier.
            flush_directory(target.parent)
            shutil.rmtree(staging, ignore_errors=True)
            return target
        _write_json_atomic(staging / ".endpoint-update.json", {
            "sha256": pending.sha256, "size": pending.size, "version": pending.version,
        }, trusted_root=self._paths.install_root, template=self._paths.current_path)
        os.replace(staging, target)
        flush_directory(target.parent)
        return target

    def _rollback(
        self, pending: PendingUpdate, previous: str,
        previous_selector: dict[str, object], reason: str,
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
        self._restore_prepared()
        self._clear_transition()
        _clear_startup_attempt(self._paths)
        self._record_terminal_outcome(
            operation_id=pending.operation_id,
            status="rolled_back",
            reported_version=previous,
            safe_code="launcher_rolled_back",
        )
        self._service.start()
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
            output.flush()
            os.fsync(output.fileno())
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


def _validate_archive_limits(members: list[zipfile.ZipInfo]) -> int:
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise ValueError("archive member count exceeds limit")
    extracted_size = 0
    for member in members:
        if type(member.file_size) is not int or member.file_size < 0:
            raise ValueError("archive member size is invalid")
        extracted_size += member.file_size
        if extracted_size > MAX_EXTRACTED_BYTES:
            raise ValueError("archive extracted size exceeds limit")
    return extracted_size


def _load_bundle_manifest(root: Path, pending: PendingUpdate) -> BundleManifest:
    """Require a complete, hash-bound runtime inventory from the signed ZIP."""
    manifest_path = root / BUNDLE_MANIFEST_FILENAME
    try:
        payload = json.loads(
            manifest_path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("update bundle manifest is invalid") from error
    if (
        not isinstance(payload, dict)
        or set(payload) != {"files", "schema_version", "source_revision", "version"}
        or payload.get("schema_version") != 1
        or payload.get("version") != pending.version
        or not isinstance(payload.get("source_revision"), str)
        or not _SOURCE_REVISION.fullmatch(payload["source_revision"])
        or not isinstance(payload.get("files"), list)
        or not payload["files"]
    ):
        raise ValueError("update bundle manifest is invalid")
    listed: dict[str, str] = {}
    for item in payload["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise ValueError("update bundle manifest is invalid")
        path = item.get("path")
        digest = item.get("sha256")
        size = item.get("size")
        if (
            not isinstance(path, str)
            or not _is_safe_bundle_path(path)
            or path in listed
            or not isinstance(digest, str)
            or not _SHA256.fullmatch(digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            raise ValueError("update bundle manifest is invalid")
        candidate = root.joinpath(*PureWindowsPath(path).parts)
        if not candidate.is_file() or candidate.stat().st_size != size:
            raise ValueError("update bundle manifest file mismatch")
        if _hash_file(candidate) != digest:
            raise ValueError("update bundle manifest file mismatch")
        listed[path] = digest
    if UPDATE_EXECUTABLE_NAME not in listed:
        raise ValueError("update bundle has no agent executable")
    actual = _release_manifest(root, excluded={BUNDLE_MANIFEST_FILENAME, ".endpoint-update.json"})
    if actual != listed:
        raise ValueError("update bundle manifest inventory mismatch")
    return BundleManifest(pending.version, payload["source_revision"])


def _is_safe_bundle_path(path: str) -> bool:
    candidate = PureWindowsPath(path)
    return (
        path == path.replace("\\", "/")
        and bool(path)
        and not candidate.is_absolute()
        and ".." not in candidate.parts
        and not path.startswith("/")
    )


def _release_manifest(
    root: Path, *, excluded: set[str] | None = None
) -> dict[str, str]:
    excluded = excluded or {".endpoint-update.json"}
    result: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.is_file() and path.name not in excluded:
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
        output.flush()
        os.fsync(output.fileno())


def _load_selector_transition(paths: WindowsUpdatePaths) -> dict[str, object] | None:
    path = paths.transition_path
    if not path.exists() and not path.is_symlink():
        return None
    _reject_reparse_chain(paths.install_root, path)
    assert_state_file_permissions_match(paths.current_path, path)
    details = path.stat()
    if details.st_nlink != 1 or not 0 < details.st_size <= 16 * 1024:
        raise ValueError("selector transition size or identity is invalid")
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        if (details.st_dev, details.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("selector transition identity changed")
        raw = source.read(16 * 1024 + 1)
    payload = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version", "status", "previous_bytes", "candidate", "operation_id", "attempt_id",
        "artifact_sha256", "artifact_size", "received_at", "requested_reason",
    }:
        raise ValueError("selector transition fields are invalid")
    if (type(payload["schema_version"]) is not int or payload["schema_version"] != 1
        or not isinstance(payload["status"], str) or payload["status"] not in {"prepared", "accepted"}
        or not isinstance(payload["previous_bytes"], str) or not 0 < len(payload["previous_bytes"]) <= 8192
        or not re.fullmatch(r"[0-9a-f]+", payload["previous_bytes"])
        or not isinstance(payload["attempt_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", payload["attempt_id"])
        or not isinstance(payload["operation_id"], str) or not 0 < len(payload["operation_id"]) <= 256
        or not isinstance(payload["artifact_sha256"], str) or not _SHA256.fullmatch(payload["artifact_sha256"])
        or type(payload["artifact_size"]) is not int or not 0 < payload["artifact_size"] <= MAX_PENDING_ARCHIVE_BYTES
        or not isinstance(payload["requested_reason"], str) or len(payload["requested_reason"]) > 512
        or not isinstance(payload["received_at"], str) or len(payload["received_at"]) > 64
        or datetime.fromisoformat(payload["received_at"]).tzinfo is None):
        raise ValueError("selector transition identity is invalid")
    previous = _validate_selector(json.loads(bytes.fromhex(payload["previous_bytes"]), object_pairs_hook=_no_duplicate_keys))
    candidate = _validate_selector(payload["candidate"])
    if set(candidate) != {"schema_version", "source_revision", "version"}:
        raise ValueError("selector transition candidate identity is incomplete")
    if not _is_eligible_recommendation(candidate["version"], previous["version"], payload["requested_reason"]):
        raise ValueError("selector transition has no eligible known-good origin")
    return payload


def _load_selector(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("current selector is unreadable") from error
    return _validate_selector(payload)


def _validate_selector(payload) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("current selector is invalid")
    if set(payload) == {"version"}:
        version = payload["version"]
    elif set(payload) == {"schema_version", "source_revision", "version"}:
        if (
            payload.get("schema_version") != 1
            or not isinstance(payload.get("source_revision"), str)
            or not _SOURCE_REVISION.fullmatch(payload["source_revision"])
        ):
            raise ValueError("current selector is invalid")
        version = payload["version"]
    else:
        raise ValueError("current selector is invalid")
    if not isinstance(version, str) or not _SEMVER.fullmatch(version):
        raise ValueError("current selector is invalid")
    return payload


def _selector_version(selector: dict[str, object]) -> str:
    version = selector.get("version")
    if not isinstance(version, str) or not _SEMVER.fullmatch(version):
        raise ValueError("current selector is invalid")
    return version


def _load_current(path: Path) -> str:
    """Compatibility accessor for callers that need only the selector version."""
    return _selector_version(_load_selector(path))


def _write_json_atomic(
    path: Path, payload: dict[str, object], *, trusted_root: Path,
    template: Path | None = None, protect: Callable[[Path], None] | None = None,
) -> None:
    """Select the owner's ACL policy; the shared primitive owns durability."""
    if protect is None:
        source = path if path.exists() else template
        if source is None:
            raise ValueError("state permission template is missing")
        protect = lambda temporary: preserve_state_file_permissions(source, temporary)
    write_json_atomic(path, payload, trusted_root=trusted_root, max_bytes=4096, protect=protect)


def _write_startup_attempt(paths: WindowsUpdatePaths, pending: PendingUpdate) -> str:
    attempt_id = uuid.uuid4().hex
    _write_json_atomic(
        paths.updates_root / "startup-attempt.json",
        {"attempt_id": attempt_id, "operation_id": pending.operation_id, "version": pending.version},
        trusted_root=paths.updates_root, protect=PyWin32AclAdapter().protect_update_path,
    )
    return attempt_id


def _clear_startup_attempt(paths: WindowsUpdatePaths) -> None:
    durable_unlink(paths.updates_root / "startup-attempt.json", trusted_root=paths.updates_root, missing_ok=True)


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
        trusted_root=paths.updates_root, protect=PyWin32AclAdapter().protect_update_path,
    )


def _quarantine_invalid_pending(paths: WindowsUpdatePaths, security: UpdatePathSecurity) -> None:
    """Move one malformed local handoff away from the active fixed leaf.

    No network report is possible because an invalid document has no trusted
    operation id.  A unique same-directory publication preserves forensic bytes
    without leaving the agent in an infinite `pending` state.
    """
    pending = paths.pending_path
    try:
        _assert_within(paths.updates_root, pending, "pending")
        security.assert_update_path(paths.updates_root)
        details = pending.lstat()
    except (OSError, ValueError):
        return
    if pending.is_symlink() or getattr(details, "st_file_attributes", 0) & 0x400:
        # The shared lifecycle primitive deliberately refuses a reparse leaf.
        # Keep unsafe state for operator repair rather than deleting a target.
        return
    destination = paths.updates_root / f"rejected-pending-{uuid.uuid4().hex}.json"
    try:
        if details.st_size > 16 * 1024:
            return
        write_bytes_atomic(destination, pending.read_bytes(), trusted_root=paths.updates_root,
            max_bytes=16 * 1024, protect=PyWin32AclAdapter().protect_update_path)
        durable_unlink(pending, trusted_root=paths.updates_root)
    except (OSError, ValueError, WindowsAclError):
        # Preserve the original handoff if it cannot be moved safely.  The
        # agent will retry only the fixed updater on its next poll.
        return


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
