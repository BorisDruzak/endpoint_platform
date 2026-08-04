"""HTTPS update staging owned by the unprivileged Windows agent service."""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pc_agent.gateway_update_runtime import _is_eligible_recommendation
from pc_agent.update_adapter import EndpointRecommendation

from .update_paths import WindowsUpdatePaths


_TERMINAL_OUTCOME_FIELDS = {
    "operation_id", "reported_version", "safe_code", "status"
}
_TERMINAL_OUTCOME_CODES = {
    "failed": "launcher_apply_failed",
    "rolled_back": "launcher_rolled_back",
}
_TERMINAL_OUTCOME_FILENAME = "terminal-outcome.json"


@dataclass(frozen=True, slots=True)
class WindowsOnlineUpdateResult:
    status: str


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
        current = _load_current_version(self._paths.current_path)
        if self._paths.pending_path.exists():
            return WindowsOnlineUpdateResult("pending")
        result = await self._adapter.fetch_recommendation(
            platform="windows_amd64", channel="canary"
        )
        recommendation = result.recommendation
        if recommendation is None:
            return WindowsOnlineUpdateResult(
                "unavailable" if result.unavailable else "idle"
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

        self._paths.updates_root.mkdir(parents=True, exist_ok=True)
        self._acl.protect_update_path(self._paths.updates_root)
        self._paths.downloads_root.mkdir(parents=True, exist_ok=True)
        self._acl.protect_update_path(self._paths.downloads_root)
        artifact = self._paths.downloads_root / (
            f"build-{recommendation.version}-{recommendation.operation_id}.zip"
        )
        try:
            actual_hash, actual_size = await self._download(recommendation, artifact)
        except Exception:
            artifact.unlink(missing_ok=True)
            return WindowsOnlineUpdateResult("download_rejected")
        if actual_hash != recommendation.sha256 or actual_size != recommendation.size:
            artifact.unlink(missing_ok=True)
            return WindowsOnlineUpdateResult("download_rejected")
        self._acl.protect_update_path(artifact)
        _write_json_atomically(
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
        )
        self._acl.protect_update_path(self._paths.pending_path)
        await self._adapter.record_scheduled_handoff(
            recommendation.operation_id,
            assigned_version=recommendation.version,
            rollback_version=current,
        )
        return WindowsOnlineUpdateResult("scheduled")

    async def report_startup_outcome(self) -> bool:
        """Report a durable updater outcome or a post-handshake applied proof."""
        try:
            current = _load_current_version(self._paths.current_path)
        except ValueError:
            return False
        outcome_path = self._paths.updates_root / _TERMINAL_OUTCOME_FILENAME
        if outcome_path.exists():
            try:
                outcome = json.loads(outcome_path.read_text(encoding="utf-8"))
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
            except (OSError, TypeError, json.JSONDecodeError):
                return False
            delivered = await self._adapter.report_terminal(
                outcome["operation_id"],
                status=status,
                reported_version=current,
                safe_code=safe_code,
            )
            if delivered:
                outcome_path.unlink(missing_ok=True)
                self._paths.pending_path.unlink(missing_ok=True)
            return delivered
        try:
            proof = json.loads(
                (self._paths.updates_root / "startup-confirmation.json").read_text(
                    encoding="utf-8"
                )
            )
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
        return await self._adapter.report_terminal(
            proof["operation_id"],
            status="applied",
            reported_version=current,
            safe_code="post_restart_handshake_confirmed",
        )


def _load_current_version(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Windows current selector is unreadable") from error
    if not isinstance(payload, dict) or set(payload) != {"version"}:
        raise ValueError("Windows current selector is invalid")
    version = payload.get("version")
    if not isinstance(version, str):
        raise ValueError("Windows current selector is invalid")
    return version


def _write_json_atomically(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, separators=(",", ":"), sort_keys=True),
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


__all__ = [
    "WindowsOnlineUpdateResult",
    "WindowsOnlineUpdateRuntime",
    "WindowsUpdatePathAcl",
]
