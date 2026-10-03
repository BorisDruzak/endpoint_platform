"""Online staging contract for the unprivileged Windows agent service."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pc_agent.update_adapter import EndpointRecommendation, RecommendationResult

pytestmark = pytest.mark.usefixtures("protected_update_state_root")


@pytest.fixture(autouse=True)
def provision_online_test_data_root(tmp_path):
    # Production enrollment provisions this root before the first transaction.
    # POSIX source tests must satisfy the same precondition as Windows fixtures.
    (tmp_path / "data").mkdir(exist_ok=True)


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

    async def retry_scheduled_acknowledgement(self, operation_id: str) -> bool:
        self.calls.append((operation_id, "scheduled_retry"))
        return True


class _Acl:
    def __init__(self) -> None:
        self.protected: list[Path] = []

    def protect_update_path(self, path: Path) -> None:
        self.protected.append(path)


@pytest.mark.asyncio
async def test_transition_reconciliation_precedes_applied_http_report(tmp_path, monkeypatch):
    from pc_agent.platform.windows import startup_confirmation
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.tests.windows.test_updater_service import _interrupted_transition
    paths, _ = _interrupted_transition(tmp_path)
    monkeypatch.setattr(startup_confirmation, "AGENT_VERSION", "3.2.0")
    assert startup_confirmation.StartupProofWriter(paths).record_after_server_handshake()
    adapter = _Adapter(None)
    runtime = WindowsOnlineUpdateRuntime(adapter=adapter, paths=paths, acl=_Acl(), download=None)
    assert await runtime.report_startup_outcome() is False
    assert adapter.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["capacity", "download", "artifact_fsync", "pending_journal"])
async def test_disk_full_download_has_no_handoff_and_can_retry(tmp_path, monkeypatch, failure):
    import errno
    import os
    import shutil
    from types import SimpleNamespace
    from pc_agent.platform.windows import durable_state, online_update_runtime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    payload = b"artifact"
    recommendation = EndpointRecommendation(operation_id=_OPERATION_ID, version="3.2.2", platform="windows_amd64",
        channel="canary", artifact_url="https://endpoint.sosnadmin.local/artifact", artifact_name="artifact.zip",
        archive_type="zip", sha256=hashlib.sha256(payload).hexdigest(), size=len(payload), reason="scheduled_rollout")
    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data" / "updates" / "pending_update.json")
    paths.install_root.mkdir()
    paths.current_path.write_text('{"version":"3.2.1"}')
    calls = []
    async def download(_, path):
        calls.append("download")
        path.write_bytes(payload)
        if failure == "download" and len(calls) == 1:
            raise OSError(errno.ENOSPC, "private/path")
        return recommendation.sha256, len(payload)
    adapter = _Adapter(recommendation)
    runtime = online_update_runtime.WindowsOnlineUpdateRuntime(adapter=adapter, paths=paths, acl=_Acl(), download=download)
    def full(*_, **__):
        raise OSError(errno.ENOSPC, "private/path")
    with monkeypatch.context() as patch:
        if failure == "capacity":
            patch.setattr(shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
        elif failure == "artifact_fsync":
            patch.setattr(os, "fsync", full)
        elif failure == "pending_journal":
            patch.setattr(online_update_runtime, "write_json_atomic", full)
        result = await runtime.run_once()
        assert result.status == "disk_insufficient"
        assert result.authenticated_check is True
    assert not paths.pending_path.exists()
    assert json.loads(paths.current_path.read_text()) == {"version":"3.2.1"}
    if failure == "capacity":
        assert calls == []
    if failure in {"capacity", "download", "artifact_fsync"}:
        assert not any("scheduled:" in status for _, status in adapter.calls)
    assert (await runtime.run_once()).status == "scheduled"


@pytest.mark.asyncio
@pytest.mark.parametrize("source,unavailable,safe_error,authenticated", [
    ("endpoint", False, None, True), ("endpoint", True, None, False),
    ("endpoint", False, "invalid_contract", False),
    ("legacy", False, None, False), ("none", False, None, False),
])
async def test_recommendation_success_provenance_requires_endpoint_and_no_error(tmp_path, source, unavailable, safe_error, authenticated):
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.current_path.write_text('{"version":"3.2.1"}')
    class Adapter(_Adapter):
        async def fetch_recommendation(self, **_):
            return RecommendationResult(source, None, unavailable, safe_error)
    runtime = WindowsOnlineUpdateRuntime(adapter=Adapter(None), paths=paths, acl=_Acl(), download=None)
    result = await runtime.run_once()
    assert result.authenticated_check is authenticated


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["idle", "request_ack_pending", "download_rejected", "scheduled", "update_in_progress", "local_update_in_progress"])
async def test_authenticated_fetch_provenance_survives_modeled_later_outcomes(tmp_path, monkeypatch, outcome):
    from contextlib import contextmanager
    from pc_agent.platform.windows import online_update_runtime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    from pc_agent.platform.windows.update_transaction import UpdateInProgress
    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.current_path.write_text('{"version":"3.2.1"}')
    payload = b"artifact"
    item = EndpointRecommendation(_OPERATION_ID, "3.2.2", "windows_amd64", "canary",
        "https://endpoint.example.test/build.zip", "build.zip", "zip", hashlib.sha256(payload).hexdigest(), len(payload), "scheduled_rollout")
    if outcome == "idle":
        from dataclasses import replace
        item = replace(item, archive_type="tar.gz")
    class Adapter(_Adapter):
        async def acknowledge(self, *_):
            return outcome != "request_ack_pending"
    async def download(_, path):
        if outcome == "download_rejected":
            raise RuntimeError("injected download failure")
        path.write_bytes(payload)
        return item.sha256, len(payload)
    if outcome in {"update_in_progress", "local_update_in_progress"}:
        original = online_update_runtime.update_transaction
        count = 0
        @contextmanager
        def transaction(*args, **kwargs):
            nonlocal count
            count += 1
            if count == (1 if outcome == "local_update_in_progress" else 2):
                raise UpdateInProgress()
            with original(*args, **kwargs):
                yield
        monkeypatch.setattr(online_update_runtime, "update_transaction", transaction)
    runtime = online_update_runtime.WindowsOnlineUpdateRuntime(adapter=Adapter(item), paths=paths, acl=_Acl(), download=download)
    result = await runtime.run_once()
    assert result.status == ("update_in_progress" if outcome == "local_update_in_progress" else outcome)
    assert result.authenticated_check is (outcome != "local_update_in_progress")


@pytest.mark.asyncio
@pytest.mark.parametrize("local_status", ["pending", "request_ack_pending", "verifying", "report_pending"])
async def test_local_recovery_and_ack_only_do_not_claim_recommendation_success(tmp_path, local_status):
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.updates_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.1"}')
    paths.pending_path.write_text(json.dumps({"operation_id": _OPERATION_ID, "version": "3.2.2"}))
    class Adapter(_Adapter):
        async def fetch_recommendation(self, **_):
            pytest.fail("local result cannot fetch recommendation")
        async def record_scheduled_handoff(self, *_, **__):
            return local_status != "request_ack_pending"
    if local_status == "verifying":
        paths.current_path.write_text('{"version":"3.2.2"}')
        (paths.updates_root / "startup-attempt.json").write_text(json.dumps({
            "operation_id": _OPERATION_ID, "version": "3.2.2", "attempt_id": "attempt"}))
    if local_status == "report_pending":
        (paths.updates_root / "terminal-outcome.json").write_text('{}')
    result = await WindowsOnlineUpdateRuntime(adapter=Adapter(None), paths=paths, acl=_Acl(), download=None).run_once()
    assert result.status == local_status
    assert result.authenticated_check is False


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["file_flush", "replace", "directory_flush"])
async def test_pending_publication_failure_requires_verified_handoff_on_restart(tmp_path, monkeypatch, failure):
    from pc_agent.platform.windows import durable_state
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data" / "updates" / "pending_update.json")
    paths.install_root.mkdir()
    paths.current_path.write_text('{"version":"3.2.1"}')
    payload = b"verified archive"
    recommendation = EndpointRecommendation(_OPERATION_ID, "3.2.2", "windows_amd64", "canary",
        "https://endpoint.example.test/build.zip", "build.zip", "zip", hashlib.sha256(payload).hexdigest(), len(payload), "scheduled_rollout")
    class Acl(_Acl):
        def protect_update_path(self, path):
            if path.name.startswith(".pending_update"):
                assert path.read_bytes() == b""
                assert not paths.pending_path.exists()
            super().protect_update_path(path)
    async def download(item, path):
        path.write_bytes(payload)
        return item.sha256, item.size
    adapter = _Adapter(recommendation)
    runtime = WindowsOnlineUpdateRuntime(adapter=adapter, paths=paths, acl=Acl(), download=download)
    def fault(*args, **kwargs):
        raise OSError("injected")
    with monkeypatch.context() as patch:
        target, attribute = (durable_state, "flush_directory") if failure == "directory_flush" else (durable_state.os, "fsync" if failure == "file_flush" else "replace")
        patch.setattr(target, attribute, fault)
        with pytest.raises(OSError, match="injected"):
            await runtime.run_once()
    assert json.loads(paths.current_path.read_text())["version"] == "3.2.1"
    assert not (paths.updates_root / "startup-confirmation.json").exists()
    adapter.calls.clear()
    if failure == "directory_flush":
        assert (await runtime.run_once()).status == "pending"
        assert adapter.calls == [(_OPERATION_ID, "scheduled:3.2.2:3.2.1")]
    else:
        assert not paths.pending_path.exists()
        assert (await runtime.run_once()).status == "scheduled"


@pytest.mark.asyncio
@pytest.mark.parametrize("filename", ["pending_update.json", "terminal-outcome.json"])
async def test_terminal_cleanup_flush_failure_retries_without_false_applied_proof(tmp_path, monkeypatch, filename):
    from pc_agent.platform.windows import durable_state
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data" / "updates" / "pending_update.json")
    paths.install_root.mkdir()
    paths.updates_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.1"}')
    paths.pending_path.write_text('{}')
    outcome = paths.updates_root / "terminal-outcome.json"
    outcome.write_text(json.dumps({"operation_id": _OPERATION_ID, "reported_version": "3.2.1", "safe_code": "launcher_rolled_back", "status": "rolled_back"}))
    adapter = _Adapter(None)
    runtime = WindowsOnlineUpdateRuntime(adapter=adapter, paths=paths, acl=_Acl(), download=None)
    original = durable_state.flush_directory
    flushed = []
    def flush(path):
        flushed.append(Path(path))
        if not (paths.updates_root / filename).exists():
            raise OSError("delete metadata failed")
        original(path)
    with monkeypatch.context() as patch:
        patch.setattr(durable_state, "flush_directory", flush)
        with pytest.raises(OSError, match="delete metadata"):
            await runtime.report_startup_outcome()
    assert flushed
    assert not (paths.updates_root / "startup-confirmation.json").exists()
    if filename == "pending_update.json":
        assert outcome.exists()
        assert await runtime.report_startup_outcome()
        assert not outcome.exists()
    else:
        assert not await runtime.report_startup_outcome()
    assert all("applied:" not in call[1] for call in adapter.calls)


@pytest.mark.asyncio
async def test_terminal_cleanup_retry_uses_durable_adapter_report_key_without_second_post(tmp_path, monkeypatch):
    from pc_agent.platform.windows import durable_state
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    from pc_agent.update_adapter import EndpointUpdateAdapter
    from pc_agent.tests.test_update_adapter import _Response
    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data" / "updates" / "pending_update.json")
    paths.install_root.mkdir()
    paths.updates_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.1"}')
    paths.pending_path.write_text('{}')
    outcome = paths.updates_root / "terminal-outcome.json"
    outcome.write_text(json.dumps({"operation_id": _OPERATION_ID, "reported_version": "3.2.1", "safe_code": "launcher_rolled_back", "status": "rolled_back"}))
    class Session:
        def __init__(self):
            self.posts = []
        def post(self, url, *, headers, json):
            self.posts.append(json)
            return _Response(200 if url.endswith("reports") else 204, "")
    session = Session()
    def owner():
        return EndpointUpdateAdapter(api_url="https://endpoint.example.test", bearer_token=lambda: "test", session=session, data_root=paths.updates_root.parent)
    first = owner()
    assert await first.record_scheduled_handoff(_OPERATION_ID, assigned_version="3.2.2", rollback_version="3.2.1")
    runtime = WindowsOnlineUpdateRuntime(adapter=first, paths=paths, acl=_Acl(), download=None)
    original = durable_state.flush_directory
    def flush(path):
        if not paths.pending_path.exists():
            raise OSError("cleanup metadata failed")
        original(path)
    with monkeypatch.context() as patch:
        patch.setattr(durable_state, "flush_directory", flush)
        with pytest.raises(OSError, match="cleanup metadata"):
            await runtime.report_startup_outcome()
    assert outcome.exists()
    restarted = WindowsOnlineUpdateRuntime(adapter=owner(), paths=paths, acl=_Acl(), download=None)
    assert await restarted.report_startup_outcome()
    assert len(session.posts) == 2  # one scheduled ACK and one terminal report
    journal = json.loads((paths.updates_root / "endpoint_update_reports.json").read_text())
    assert journal[0]["report_key"] == session.posts[1]["report_key"]
    assert journal[0]["delivered_at"] is not None
    assert not outcome.exists()


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
    paths.current_path.write_text(json.dumps({
        "schema_version": 1,
        "source_revision": "a" * 40,
        "version": "3.2.1",
    }), encoding="utf-8")
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
    assert acl.protected[:3] == [
        paths.updates_root,
        paths.downloads_root,
        paths.downloads_root / "build-3.2.2-caa31a48-bf2f-4f1c-8b77-d1be77e12b4e.zip",
    ]
    assert len(acl.protected) == 4
    assert acl.protected[-1].name.startswith(".pending_update.json.")
    assert acl.protected[-1].suffix == ".tmp"
    assert paths.pending_path.is_file()
    assert adapter.calls == [
        ("windows_amd64", "canary"),
        (_OPERATION_ID, "requested"),
        (_OPERATION_ID, "scheduled:3.2.2:3.2.1"),
    ]

    # A restart between pending publication and journal persistence must repair
    # the durable scheduled handoff before the supervisor can start SCM.
    adapter.calls.clear()
    assert (await runtime.run_once()).status == "pending"
    assert adapter.calls == [(_OPERATION_ID, "scheduled:3.2.2:3.2.1")]

    async def unavailable_handoff(*args, **kwargs):
        return False

    adapter.record_scheduled_handoff = unavailable_handoff
    assert (await runtime.run_once()).status == "request_ack_pending"


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
        (_OPERATION_ID, "scheduled_retry"),
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
    assert adapter.calls == [(_OPERATION_ID, "scheduled_retry"), (_OPERATION_ID, "failed:3.2.5:launcher_apply_failed")]
    assert not paths.pending_path.exists()
    assert not (paths.updates_root / "terminal-outcome.json").exists()

@pytest.mark.asyncio
async def test_terminal_report_cleanup_preserves_new_pending_from_other_owner(tmp_path):
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths=WindowsUpdatePaths(tmp_path/'install',tmp_path/'data'/'updates'/'pending_update.json')
    paths.install_root.mkdir();paths.updates_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.79"}')
    outcome=paths.updates_root/'terminal-outcome.json'
    outcome.write_text(json.dumps(dict(operation_id=_OPERATION_ID,reported_version='3.2.79',status='failed',safe_code='launcher_apply_failed')))
    paths.pending_path.write_text(json.dumps(dict(operation_id=_OPERATION_ID,version='3.2.80')))
    next_pending={'operation_id':'b'*32,'version':'3.2.82'}
    class Adapter(_Adapter):
        async def report_terminal(self,*_,**__):
            # Another owner completed the old cleanup while this HTTP was in flight.
            outcome.unlink()
            paths.pending_path.write_text(json.dumps(next_pending))
            return True
    runtime=WindowsOnlineUpdateRuntime(adapter=Adapter(None),paths=paths,acl=_Acl(),download=None)
    assert not await runtime.report_startup_outcome()
    assert json.loads(paths.pending_path.read_text())==next_pending


@pytest.mark.asyncio
async def test_terminal_report_snapshot_does_not_borrow_newer_pending(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from pc_agent.platform.windows import online_update_runtime as online
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.updates_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.79"}')
    outcome = paths.updates_root / "terminal-outcome.json"
    outcome.write_text(json.dumps(dict(operation_id=_OPERATION_ID, reported_version="3.2.79", status="failed", safe_code="launcher_apply_failed")))
    paths.pending_path.write_text(json.dumps(dict(operation_id=_OPERATION_ID, version="3.2.80")))
    newer = {"operation_id": "b" * 32, "version": "3.2.82"}
    original = online.update_transaction
    first = True

    @contextmanager
    def interleaved(*args, **kwargs):
        nonlocal first
        if first:
            first = False
            with original(*args, **kwargs):
                outcome.unlink()
                paths.pending_path.write_text(json.dumps(newer))
        with original(*args, **kwargs):
            yield

    monkeypatch.setattr(online, "update_transaction", interleaved)
    adapter = _Adapter(None)
    runtime = WindowsOnlineUpdateRuntime(adapter=adapter, paths=paths, acl=_Acl(), download=None)
    assert not await runtime.report_startup_outcome()
    assert json.loads(paths.pending_path.read_text()) == newer
    assert adapter.calls == []
