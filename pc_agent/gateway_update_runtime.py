"""TLS-Gateway-native update handoff for immutable ALT agent bundles."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from pc_agent.update_adapter import EndpointRecommendation


_SEMVER = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_OPERATION_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


@dataclass(frozen=True)
class GatewayUpdateRunResult:
    """One safe Gateway update polling outcome."""

    status: str


class GatewayUpdateRuntime:
    """Stage only strictly newer Endpoint canary releases for the ALT launcher."""

    def __init__(
        self,
        *,
        adapter: object,
        data_root: Path,
        current_version: str,
        download: Callable[
            [EndpointRecommendation, Path], Awaitable[tuple[str, int]]
        ],
    ) -> None:
        self._adapter = adapter
        self._data_root = Path(data_root)
        self._current_version = current_version
        self._download = download

    async def run_once(self) -> GatewayUpdateRunResult:
        recommendation_result = await self._adapter.fetch_recommendation(
            platform="linux_amd64", channel="canary"
        )
        recommendation = recommendation_result.recommendation
        if recommendation is None:
            return GatewayUpdateRunResult(
                "unavailable" if recommendation_result.unavailable else "idle"
            )
        if not _is_strictly_newer(recommendation.version, self._current_version):
            return GatewayUpdateRunResult("idle")
        if not await self._adapter.acknowledge(recommendation.operation_id, "requested"):
            return GatewayUpdateRunResult("request_ack_pending")

        downloads_dir = self._data_root / "updates" / "downloads"
        downloads_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = downloads_dir / (
            f"build-{recommendation.version}-{recommendation.operation_id}."
            f"{_archive_extension(recommendation.archive_type)}"
        )
        sha256, size = await self._download(recommendation, artifact_path)
        if sha256 != recommendation.sha256 or size != recommendation.size:
            try:
                artifact_path.unlink(missing_ok=True)
            except OSError:
                pass
            return GatewayUpdateRunResult("download_rejected")

        pending_path = self._data_root / "updates" / "pending_alt_update.json"
        _write_json_atomically(
            pending_path,
            {
                "archive_type": recommendation.archive_type,
                "artifact_path": str(artifact_path),
                "channel": recommendation.channel,
                "operation_id": recommendation.operation_id,
                "requested_by": "gateway",
                "requested_reason": recommendation.reason,
                "sha256": sha256,
                "size": size,
                "target": recommendation.platform,
                "version": recommendation.version,
            },
        )
        await self._adapter.record_scheduled_handoff(
            recommendation.operation_id,
            assigned_version=recommendation.version,
            rollback_version=self._current_version,
        )
        return GatewayUpdateRunResult("scheduled")

    async def report_startup_outcome(self) -> bool:
        """Report one launcher-derived terminal state after a durable restart."""
        history = _load_history(self._data_root / "updates" / "update_history.json")
        outcome = _startup_outcome(
            history=history,
            current_version=self._current_version,
            failed_marker=_load_object(
                self._data_root / "updates" / "last_failed_launch.json"
            ),
        )
        if outcome is None:
            return False
        operation_id, status, reported_version, safe_code = outcome
        if not await self._adapter.retry_scheduled_acknowledgement(operation_id):
            return False
        return await self._adapter.report_terminal(
            operation_id,
            status=status,
            reported_version=reported_version,
            safe_code=safe_code,
        )


def _archive_extension(archive_type: str) -> str:
    return "tar.gz" if archive_type in {"tar.gz", "tgz"} else "zip"


def _write_json_atomically(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def _is_strictly_newer(candidate: str, installed: str) -> bool:
    candidate_parts = _parse_semver(candidate)
    installed_parts = _parse_semver(installed)
    if candidate_parts is None or installed_parts is None:
        return False
    if candidate_parts[:3] != installed_parts[:3]:
        return candidate_parts[:3] > installed_parts[:3]
    return _compare_prerelease(candidate_parts[3], installed_parts[3]) > 0


def _parse_semver(value: str) -> tuple[int, int, int, tuple[str, ...] | None] | None:
    match = _SEMVER.fullmatch(value)
    if match is None:
        return None
    prerelease = match.group("pre")
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        tuple(prerelease.split(".")) if prerelease else None,
    )


def _compare_prerelease(
    candidate: tuple[str, ...] | None, installed: tuple[str, ...] | None
) -> int:
    if candidate is None:
        return 0 if installed is None else 1
    if installed is None:
        return -1
    for left, right in zip(candidate, installed):
        if left == right:
            continue
        if left.isdigit() and right.isdigit():
            return 1 if int(left) > int(right) else -1
        if left.isdigit():
            return -1
        if right.isdigit():
            return 1
        return 1 if left > right else -1
    if len(candidate) == len(installed):
        return 0
    return 1 if len(candidate) > len(installed) else -1


def _load_object(path: Path) -> dict[str, object] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _load_history(path: Path) -> list[dict[str, object]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


def _startup_outcome(
    *,
    history: list[dict[str, object]],
    current_version: str,
    failed_marker: dict[str, object] | None,
) -> tuple[str, str, str, str] | None:
    if failed_marker and failed_marker.get("reason") == "startup_crash_rollback":
        crashed_version = failed_marker.get("crashed_version")
        rollback_version = failed_marker.get("rollback_version")
        if (
            isinstance(crashed_version, str)
            and isinstance(rollback_version, str)
            and rollback_version == current_version
        ):
            record = _latest_operation(history, version=crashed_version, success=True)
            if record is not None:
                return (
                    record,
                    "rolled_back",
                    rollback_version,
                    "launcher_rolled_back",
                )
    operation_id = _latest_operation(history, version=current_version, success=True)
    if operation_id is not None:
        return operation_id, "applied", current_version, "post_restart_handshake_confirmed"
    failed = _latest_failure(history)
    if failed is not None:
        operation_id, version = failed
        return operation_id, "failed", version, "launcher_apply_failed"
    return None


def _latest_operation(
    history: list[dict[str, object]], *, version: str, success: bool
) -> str | None:
    for entry in reversed(history):
        operation_id = entry.get("operation_id")
        if (
            entry.get("version") == version
            and entry.get("success") is success
            and isinstance(operation_id, str)
            and _OPERATION_ID.fullmatch(operation_id)
        ):
            return operation_id
    return None


def _latest_failure(history: list[dict[str, object]]) -> tuple[str, str] | None:
    for entry in reversed(history):
        operation_id = entry.get("operation_id")
        version = entry.get("version")
        if (
            entry.get("success") is False
            and isinstance(operation_id, str)
            and _OPERATION_ID.fullmatch(operation_id)
            and isinstance(version, str)
            and _SEMVER.fullmatch(version)
        ):
            return operation_id, version
    return None
