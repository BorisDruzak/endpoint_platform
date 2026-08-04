"""Online staging contract for the unprivileged Windows agent service."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pc_agent.update_adapter import EndpointRecommendation, RecommendationResult


_OPERATION_ID = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"


class _Adapter:
    def __init__(self, recommendation: EndpointRecommendation) -> None:
        self._recommendation = recommendation
        self.calls: list[tuple[str, str]] = []

    async def fetch_recommendation(self, *, platform: str, channel: str):
        self.calls.append((platform, channel))
        return RecommendationResult("endpoint", self._recommendation, False, None)

    async def acknowledge(self, operation_id: str, status: str) -> bool:
        self.calls.append((operation_id, status))
        return True

    async def record_scheduled_handoff(
        self, operation_id: str, *, assigned_version: str, rollback_version: str
    ) -> bool:
        self.calls.append((operation_id, f"scheduled:{assigned_version}:{rollback_version}"))
        return True

    async def report_terminal(
        self, operation_id: str, *, status: str, reported_version: str, safe_code: str
    ) -> bool:
        self.calls.append((operation_id, f"{status}:{reported_version}:{safe_code}"))
        return True


class _Acl:
    def __init__(self) -> None:
        self.protected: list[Path] = []

    def protect_update_path(self, path: Path) -> None:
        self.protected.append(path)


@pytest.mark.asyncio
async def test_windows_agent_stages_a_verified_pending_update_for_the_fixed_updater(
    tmp_path: Path,
) -> None:
    """Only a verified same-platform ZIP may request the fixed LocalSystem worker."""
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    payload = b"verified Windows artifact"
    recommendation = EndpointRecommendation(
        operation_id=_OPERATION_ID,
        version="3.2.2",
        platform="windows_amd64",
        channel="canary",
        artifact_url="https://endpoint.sosnadmin.local/agent/v1/updates/artifacts/windows.zip",
        artifact_name="endpoint-agent-windows.zip",
        archive_type="zip",
        sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
        reason="scheduled_rollout",
    )
    paths = WindowsUpdatePaths(
        tmp_path / "install", tmp_path / "data" / "updates" / "pending_update.json"
    )
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.1"}', encoding="utf-8")
    acl = _Acl()

    async def download(item: EndpointRecommendation, destination: Path) -> tuple[str, int]:
        assert item is recommendation
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        return hashlib.sha256(payload).hexdigest(), len(payload)

    adapter = _Adapter(recommendation)
    runtime = WindowsOnlineUpdateRuntime(
        adapter=adapter,
        paths=paths,
        acl=acl,
        download=download,
        now=lambda: datetime(2026, 8, 3, tzinfo=UTC),
    )

    assert (await runtime.run_once()).status == "scheduled"
    pending = json.loads(paths.pending_path.read_text(encoding="utf-8"))
    assert pending == {
        "archive_type": "zip",
        "artifact_path": str(
            paths.downloads_root / "build-3.2.2-caa31a48-bf2f-4f1c-8b77-d1be77e12b4e.zip"
        ),
        "channel": "canary",
        "operation_id": _OPERATION_ID,
        "received_at": "2026-08-03T00:00:00+00:00",
        "requested_by": "gateway",
        "requested_reason": "scheduled_rollout",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "target": "windows_amd64",
        "version": "3.2.2",
    }
    assert acl.protected == [
        paths.updates_root,
        paths.downloads_root,
        paths.downloads_root / "build-3.2.2-caa31a48-bf2f-4f1c-8b77-d1be77e12b4e.zip",
        pending_path := paths.pending_path,
    ]
    assert pending_path.is_file()
    assert adapter.calls == [
        ("windows_amd64", "canary"),
        (_OPERATION_ID, "requested"),
        (_OPERATION_ID, "scheduled:3.2.2:3.2.1"),
    ]


@pytest.mark.asyncio
async def test_windows_agent_reports_applied_only_from_a_post_handshake_proof(
    tmp_path: Path,
) -> None:
    """The controller receives an applied terminal report only after WSS proof exists."""
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    paths = WindowsUpdatePaths(
        tmp_path / "install", tmp_path / "data" / "updates" / "pending_update.json"
    )
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.3"}', encoding="utf-8")
    paths.updates_root.mkdir(parents=True)
    (paths.updates_root / "startup-confirmation.json").write_text(
        json.dumps(
            {
                "attempt_id": "a" * 32,
                "confirmed_at": "2026-08-03T00:00:00+00:00",
                "operation_id": _OPERATION_ID,
                "status": "confirmed",
                "version": "3.2.3",
            }
        ),
        encoding="utf-8",
    )
    adapter = _Adapter(
        EndpointRecommendation(
            operation_id=_OPERATION_ID, version="3.2.4", platform="windows_amd64",
            channel="canary", artifact_url="https://endpoint.sosnadmin.local/update.zip",
            artifact_name="endpoint-agent-windows.zip", archive_type="zip", sha256="0" * 64,
            size=1, reason="scheduled_rollout",
        )
    )
    runtime = WindowsOnlineUpdateRuntime(
        adapter=adapter, paths=paths, acl=_Acl(),
        download=lambda *_: pytest.fail("startup reporting must not download"),
    )

    assert await runtime.report_startup_outcome() is True
    assert adapter.calls == [
        (_OPERATION_ID, "applied:3.2.3:post_restart_handshake_confirmed"),
    ]


@pytest.mark.asyncio
async def test_windows_agent_reports_a_durable_updater_failure_after_wss(
    tmp_path: Path,
) -> None:
    """A rejected offline handoff becomes terminal only after the agent reconnects."""
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    paths = WindowsUpdatePaths(
        tmp_path / "install", tmp_path / "data" / "updates" / "pending_update.json"
    )
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.5"}', encoding="utf-8")
    paths.updates_root.mkdir(parents=True)
    paths.pending_path.write_text('{"stale":"handoff"}', encoding="utf-8")
    (paths.updates_root / "terminal-outcome.json").write_text(
        json.dumps(
            {
                "operation_id": _OPERATION_ID,
                "reported_version": "3.2.5",
                "safe_code": "launcher_apply_failed",
                "status": "failed",
            }
        ),
        encoding="utf-8",
    )
    adapter = _Adapter(
        EndpointRecommendation(
            operation_id=_OPERATION_ID, version="3.2.6", platform="windows_amd64",
            channel="canary", artifact_url="https://endpoint.sosnadmin.local/update.zip",
            artifact_name="endpoint-agent-windows.zip", archive_type="zip", sha256="0" * 64,
            size=1, reason="scheduled_rollout",
        )
    )
    runtime = WindowsOnlineUpdateRuntime(
        adapter=adapter, paths=paths, acl=_Acl(),
        download=lambda *_: pytest.fail("terminal reporting must not download"),
    )

    assert await runtime.report_startup_outcome() is True
    assert adapter.calls == [(_OPERATION_ID, "failed:3.2.5:launcher_apply_failed")]
    assert not paths.pending_path.exists()
    assert not (paths.updates_root / "terminal-outcome.json").exists()
