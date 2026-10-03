"""HTTPS update staging owned by the unprivileged Windows agent service."""

from __future__ import annotations

import json
import os
import re
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

import aiohttp

from pc_agent.gateway_update_runtime import _is_eligible_recommendation
from pc_agent.update_adapter import EndpointRecommendation, _is_operation_id
from pc_agent.transport.base import GatewayCredentialRejected, GatewayTerminalError

from .update_paths import WindowsUpdatePaths
from .update_transaction import update_transaction, UpdateInProgress, _read_state
from .durable_state import durable_unlink, write_json_atomic
from .disk_readiness import download_required_bytes, is_disk_full, require_disk_space


_TERMINAL_OUTCOME_FIELDS = {
    "operation_id", "reported_version", "safe_code", "status"
}
_TERMINAL_OUTCOME_CODES = {
    "failed": "launcher_apply_failed",
    "rolled_back": "launcher_rolled_back",
}
_TERMINAL_OUTCOME_FILENAME = "terminal-outcome.json"
_PENDING_FIELDS = {
    "archive_type", "artifact_path", "channel", "operation_id", "received_at",
    "requested_by", "requested_reason", "sha256", "size", "target", "version",
}
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True, slots=True)
class WindowsOnlineUpdateResult:
    status: str
    authenticated_check: bool = False


@dataclass(slots=True)
class _RecommendationCheck:
    """Per-call provenance; local journals and report ACKs cannot set it."""

    authenticated: bool = False


class WindowsUpdatePathAcl:
    """Apply the fixed updater DACL to agent-created update handoff paths."""

    def protect_update_path(self, path: Path) -> None: ...


class WindowsOnlineUpdateRuntime:
    """Stage verified Windows ZIPs without granting the updater any network role."""

    def __init__(
        self,
        *,
        adapter: object,
        paths: WindowsUpdatePaths,
        acl: WindowsUpdatePathAcl,
        download: Callable[[EndpointRecommendation, Path], Awaitable[tuple[str, int]]],
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._adapter = adapter
        self._paths = paths
        self._acl = acl
        self._download = download
        self._now = now

    async def run_once(self) -> WindowsOnlineUpdateResult:
        check = _RecommendationCheck()
        try:
            result = await self._run_once(check)
        except UpdateInProgress:
            result = WindowsOnlineUpdateResult("update_in_progress")
        except OSError as error:
            if is_disk_full(error):
                result = WindowsOnlineUpdateResult("disk_insufficient")
            else:
                raise
        return replace(result, authenticated_check=check.authenticated)

    async def _run_once(self, check: _RecommendationCheck) -> WindowsOnlineUpdateResult:
        pending = None
        with update_transaction(self._paths, timeout_ms=0):
            current = _load_current_version(self._paths.current_path)
            if self._paths.transition_path.exists() or self._paths.transition_path.is_symlink():
                # A canonical operation journal makes an interrupted offline worker
                # reachable without treating selection as acceptance. SCM start is
                # idempotent while an active worker still waits for Gateway proof.
                from .updater_service import _load_selector_transition, _load_selector
                transition = _load_selector_transition(self._paths)
                selected = _load_selector(self._paths.current_path)
                if transition["status"] == "accepted":
                    if selected != transition["candidate"]:
                        raise ValueError("Windows accepted recovery selector differs")
                    return WindowsOnlineUpdateResult("recovery_pending")
                if not self._paths.pending_path.exists() and selected == json.loads(bytes.fromhex(transition["previous_bytes"])):
                    return WindowsOnlineUpdateResult("recovery_pending")
                pending = _read_state(self._paths.pending_path, 16384)
                attempt = _read_state(self._paths.updates_root / "startup-attempt.json", 4096)
                if (not isinstance(pending, dict) or type(pending.get("size")) is not int
                    or any(pending.get(key) != value for key, value in {
                        "version": transition["candidate"]["version"], "operation_id": transition["operation_id"],
                        "sha256": transition["artifact_sha256"], "size": transition["artifact_size"],
                        "requested_reason": transition["requested_reason"],
                    }.items())
                    or datetime.fromisoformat(pending.get("received_at", "")) != datetime.fromisoformat(transition["received_at"])
                    or attempt != {"attempt_id": transition["attempt_id"], "operation_id": transition["operation_id"],
                        "version": transition["candidate"]["version"]}
                    or selected not in (transition["candidate"], json.loads(bytes.fromhex(transition["previous_bytes"])))):
                    raise ValueError("Windows recovery transition identity differs")
                return WindowsOnlineUpdateResult("recovery_pending")
            if (self._paths.updates_root / _TERMINAL_OUTCOME_FILENAME).exists():
                return WindowsOnlineUpdateResult("report_pending")
            if self._paths.pending_path.exists():
                try:
                    pending = _read_state(self._paths.pending_path, 16384)
                    if (
                        not isinstance(pending, dict)
                        or not isinstance(pending.get("operation_id"), str)
                        or not _is_operation_id(pending["operation_id"])
                        or not isinstance(pending.get("version"), str)
                    ):
                        raise ValueError
                except (OSError, ValueError, TypeError):
                    raise ValueError("Windows pending update is invalid") from None
                attempt_path = self._paths.updates_root / "startup-attempt.json"
                if attempt_path.exists():
                    try:
                        attempt = _read_state(attempt_path, 4096)
                        if (
                            pending["version"] == current == attempt["version"]
                            and pending["operation_id"] == attempt["operation_id"]
                            and isinstance(attempt["attempt_id"], str)
                        ):
                            # The privileged worker is already applying this update
                            # and waiting for this candidate's post-WSS proof.
                            return WindowsOnlineUpdateResult("verifying")
                    except (OSError, ValueError, KeyError, TypeError):
                        raise ValueError("Windows update startup attempt is invalid") from None
                if not _is_eligible_recommendation(pending["version"], current, pending.get("requested_reason")):
                    raise ValueError("Windows pending update version is invalid")
        if pending is not None:
            if not await self._adapter.record_scheduled_handoff(
                pending["operation_id"], assigned_version=pending["version"], rollback_version=current,
            ):
                return WindowsOnlineUpdateResult("request_ack_pending")
            return WindowsOnlineUpdateResult("pending")
        result = await self._adapter.fetch_recommendation(
            platform="windows_amd64", channel="canary"
        )
        check.authenticated = (
            result.source == "endpoint" and not result.unavailable and not result.safe_error
        )
        recommendation = result.recommendation
        if recommendation is None:
            return WindowsOnlineUpdateResult(
                "unavailable" if result.unavailable or result.safe_error else "idle"
            )
        if (
            recommendation.archive_type != "zip"
            or not _is_eligible_recommendation(
                recommendation.version, current, recommendation.reason
            )
        ):
            return WindowsOnlineUpdateResult("idle")
        if not await self._adapter.acknowledge(recommendation.operation_id, "requested"):
            return WindowsOnlineUpdateResult("request_ack_pending")

        with update_transaction(self._paths, timeout_ms=0):
            require_disk_space(self._paths.downloads_root, download_required_bytes(recommendation.size))
            self._paths.updates_root.mkdir(parents=True, exist_ok=True)
            self._acl.protect_update_path(self._paths.updates_root)
            self._paths.downloads_root.mkdir(parents=True, exist_ok=True)
            self._acl.protect_update_path(self._paths.downloads_root)
        artifact = self._paths.downloads_root / (
            f"build-{recommendation.version}-{recommendation.operation_id}.zip"
        )
        try:
            actual_hash, actual_size = await self._download(recommendation, artifact)
        except (aiohttp.ClientConnectorCertificateError, aiohttp.ClientConnectorSSLError, ssl.SSLError) as error:
            artifact.unlink(missing_ok=True)
            raise GatewayTerminalError("Endpoint update artifact TLS trust failed") from error
        except (GatewayCredentialRejected, GatewayTerminalError):
            artifact.unlink(missing_ok=True)
            raise
        except OSError as error:
            artifact.unlink(missing_ok=True)
            if is_disk_full(error):
                return WindowsOnlineUpdateResult("disk_insufficient")
            return WindowsOnlineUpdateResult("download_rejected")
        except Exception:
            artifact.unlink(missing_ok=True)
            return WindowsOnlineUpdateResult("download_rejected")
        if actual_hash != recommendation.sha256 or actual_size != recommendation.size:
            artifact.unlink(missing_ok=True)
            return WindowsOnlineUpdateResult("download_rejected")
        self._acl.protect_update_path(artifact)
        # Injected downloaders obey the same durability gate as the HTTP owner.
        with artifact.open("r+b") as downloaded:
            os.fsync(downloaded.fileno())
        # Persist operation metadata and acknowledge scheduled before publishing
        # the SCM request; a process crash must never strand terminal reporting.
        if not await self._adapter.record_scheduled_handoff(
            recommendation.operation_id,
            assigned_version=recommendation.version,
            rollback_version=current,
        ):
            return WindowsOnlineUpdateResult("request_ack_pending")
        with update_transaction(self._paths, timeout_ms=0):
            if (self._paths.pending_path.exists() or self._paths.transition_path.exists()
                or (self._paths.updates_root / _TERMINAL_OUTCOME_FILENAME).exists()):
                return WindowsOnlineUpdateResult("update_in_progress")
            changed = _load_current_version(self._paths.current_path) != current
            if not changed:
                write_json_atomic(
                    self._paths.pending_path,
                    {
                        "archive_type": "zip",
                        "artifact_path": str(artifact),
                        "channel": recommendation.channel,
                        "operation_id": recommendation.operation_id,
                        "received_at": self._now().astimezone(UTC).isoformat(),
                        "requested_by": "gateway",
                        "requested_reason": recommendation.reason or "scheduled_rollout",
                        "sha256": actual_hash,
                        "size": actual_size,
                        "target": "windows_amd64",
                        "version": recommendation.version,
                    },
                    trusted_root=self._paths.updates_root,
                    max_bytes=16 * 1024,
                    protect=self._acl.protect_update_path,
                )
        if changed:
            await self._adapter.report_terminal(recommendation.operation_id, status="failed",
                reported_version=_load_current_version(self._paths.current_path), safe_code="launcher_apply_failed")
            return WindowsOnlineUpdateResult("update_in_progress")
        return WindowsOnlineUpdateResult("scheduled")

    async def report_startup_outcome(self) -> bool:
        try:
            return await self._report_startup_outcome()
        except UpdateInProgress:
            return False

    async def _report_startup_outcome(self) -> bool:
        """Report a durable updater outcome or a post-handshake applied proof."""
        outcome_path = self._paths.updates_root / _TERMINAL_OUTCOME_FILENAME
        attempt_path = self._paths.updates_root / "startup-attempt.json"
        outcome = None
        # Capture all cleanup authority coherently before releasing for HTTP.
        with update_transaction(self._paths, timeout_ms=0):
            if self._paths.transition_path.exists() or self._paths.transition_path.is_symlink():
                # The worker finishes/reconciles this operation's selector metadata
                # before an HTTP ACK/report can consume its lifecycle state.
                return False
            try:
                current = _load_current_version(self._paths.current_path)
            except ValueError:
                return False
            if outcome_path.exists():
                try:
                    outcome = _read_state(outcome_path, 4096)
                    status = outcome.get("status") if isinstance(outcome, dict) else None
                    safe_code = outcome.get("safe_code") if isinstance(outcome, dict) else None
                    if (
                        not isinstance(outcome, dict)
                        or set(outcome) != _TERMINAL_OUTCOME_FIELDS
                        or not isinstance(outcome.get("operation_id"), str)
                        or outcome.get("reported_version") != current
                        or status not in _TERMINAL_OUTCOME_CODES
                        or safe_code != _TERMINAL_OUTCOME_CODES[status]
                    ):
                        return False
                except (OSError, ValueError, TypeError):
                    return False
                pending_before = None
                pending = None
                if self._paths.pending_path.exists() or self._paths.pending_path.is_symlink():
                    try:
                        pending_before = _read_state(self._paths.pending_path, 16384, return_bytes=True)
                        pending = json.loads(pending_before)
                        if (not isinstance(pending, dict)
                            or set(pending) != _PENDING_FIELDS
                            or pending.get("operation_id") != outcome["operation_id"]
                            or not isinstance(pending.get("version"), str)):
                            return False
                    except (OSError, ValueError, TypeError):
                        return False
                attempt_before = None
                if attempt_path.exists() or attempt_path.is_symlink():
                    try:
                        # Same 4096-byte bound as the offline attempt writer.
                        attempt_before = _read_state(attempt_path, 4096, return_bytes=True)
                        attempt = json.loads(attempt_before)
                        if (not isinstance(attempt, dict)
                            or set(attempt) != {"operation_id", "version", "attempt_id"}
                            or not isinstance(attempt.get("attempt_id"), str)
                            or re.fullmatch(r"[0-9a-f]{32}", attempt["attempt_id"]) is None
                            or not isinstance(pending, dict)
                            or attempt.get("operation_id") != outcome["operation_id"]
                            or pending.get("operation_id") != outcome["operation_id"]
                            or not isinstance(attempt.get("version"), str)
                            or attempt["version"] != pending.get("version")):
                            return False
                    except (OSError, ValueError, TypeError):
                        return False
        if outcome is not None:
            scheduled = await self._adapter.retry_scheduled_acknowledgement(outcome["operation_id"])
            if not scheduled and status == "rolled_back":
                return False
            delivered = await self._adapter.report_terminal(
                outcome["operation_id"],
                status=status,
                reported_version=current,
                safe_code=safe_code,
            )
            if delivered:
                # Keep the outcome as retry authority until pending deletion
                # and its metadata flush complete. The adapter report key is
                # durable, so reconnect/retry cannot duplicate terminal reports.
                with update_transaction(self._paths, timeout_ms=0):
                    if (self._paths.transition_path.exists()
                        or _load_current_version(self._paths.current_path) != current
                        or not outcome_path.exists()
                        or _read_state(outcome_path, 4096) != outcome):
                        return False
                    pending_after = (_read_state(self._paths.pending_path, 16384, return_bytes=True)
                        if self._paths.pending_path.exists() or self._paths.pending_path.is_symlink() else None)
                    if pending_after != pending_before:
                        return False
                    attempt_after = (_read_state(attempt_path, 4096, return_bytes=True)
                        if attempt_path.exists() or attempt_path.is_symlink() else None)
                    if attempt_after != attempt_before:
                        return False
                    # The attempt uses DIRECTORY_ACL (Agent/Updater modify).
                    # Keep pending/outcome retry authority until it is retired.
                    durable_unlink(attempt_path, trusted_root=self._paths.updates_root, missing_ok=True)
                    durable_unlink(self._paths.pending_path, trusted_root=self._paths.updates_root, missing_ok=True)
                    durable_unlink(outcome_path, trusted_root=self._paths.updates_root, missing_ok=True)
            return delivered
        with update_transaction(self._paths, timeout_ms=0):
            if outcome_path.exists() or self._paths.transition_path.exists():
                return False
            if self._paths.updates_root.exists():
                # Finish metadata for an outcome already removed by an interrupted
                # cleanup before considering a separate applied proof.
                durable_unlink(outcome_path, trusted_root=self._paths.updates_root, missing_ok=True)
        try:
            proof = _read_state(self._paths.updates_root / "startup-confirmation.json", 4096)
            if (
                not isinstance(proof, dict)
                or set(proof)
                != {"attempt_id", "confirmed_at", "operation_id", "status", "version"}
                or not isinstance(proof.get("attempt_id"), str)
                or not isinstance(proof.get("operation_id"), str)
                or proof.get("status") != "confirmed"
                or not isinstance(proof.get("version"), str)
                or proof["version"] != current
                or datetime.fromisoformat(str(proof.get("confirmed_at"))).tzinfo is None
            ):
                return False
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return False
        if not await self._adapter.retry_scheduled_acknowledgement(proof["operation_id"]):
            return False
        return await self._adapter.report_terminal(
            proof["operation_id"],
            status="applied",
            reported_version=current,
            safe_code="post_restart_handshake_confirmed",
        )


def _load_current_version(path: Path) -> str:
    try:
        payload = _read_state(path, 4096)
    except (OSError, ValueError) as error:
        raise ValueError("Windows current selector is unreadable") from error
    if not isinstance(payload, dict):
        raise ValueError("Windows current selector is invalid")
    if set(payload) == {"version"}:
        version = payload["version"]
    elif set(payload) == {"schema_version", "source_revision", "version"}:
        if (
            payload.get("schema_version") != 1
            or not isinstance(payload.get("source_revision"), str)
            or not _SOURCE_REVISION.fullmatch(payload["source_revision"])
        ):
            raise ValueError("Windows current selector is invalid")
        version = payload["version"]
    else:
        raise ValueError("Windows current selector is invalid")
    if not isinstance(version, str):
        raise ValueError("Windows current selector is invalid")
    return version


__all__ = [
    "WindowsOnlineUpdateResult",
    "WindowsOnlineUpdateRuntime",
    "WindowsUpdatePathAcl",
]
