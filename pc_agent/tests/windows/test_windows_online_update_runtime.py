"""Online staging contract for the unprivileged Windows agent service."""

from __future__ import annotations

import hashlib
import json
import os
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


@pytest.mark.asyncio
@pytest.mark.parametrize("state", [
    "abandoned", "pending", "changed_bytes", "changed_size", "hardlinked", "conflicting_evidence",
])
async def test_restart_reclaims_only_archive_with_unconsumed_publication_record(
    tmp_path, monkeypatch, state,
):
    from pc_agent.platform.windows import online_update_runtime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    class Interrupted(BaseException):
        pass

    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.current_path.write_text('{"version":"3.2.1"}')
    payload = b"verified archive"
    item = EndpointRecommendation(
        _OPERATION_ID, "3.2.2", "windows_amd64", "canary",
        "https://endpoint.example.test/build.zip", "build.zip", "zip",
        hashlib.sha256(payload).hexdigest(), len(payload), "scheduled_rollout",
    )

    async def download(_, destination):
        destination.write_bytes(payload)
        return item.sha256, item.size

    archives = []
    original_flush = online_update_runtime.flush_directory

    def interrupt_after_archive(directory):
        original_flush(directory)
        if directory == paths.downloads_root:
            archives.extend(directory.glob("build-*.zip"))
            if archives:
                raise Interrupted

    first = online_update_runtime.WindowsOnlineUpdateRuntime(
        adapter=_Adapter(item), paths=paths, acl=_Acl(), download=download,
    )
    with monkeypatch.context() as patch:
        patch.setattr(online_update_runtime, "flush_directory", interrupt_after_archive)
        with pytest.raises(Interrupted):
            await first.run_once()
    archive, = archives
    assert archive.read_bytes() == payload
    assert not paths.pending_path.exists()
    if state == "pending":
        pending = _pending_payload()
        pending.update(artifact_path=str(archive), size=len(payload), sha256=item.sha256)
        paths.pending_path.write_text(json.dumps(pending))
    original = payload
    if state in {"changed_bytes", "changed_size", "conflicting_evidence"}:
        original = b"x" if state == "changed_size" else b"x" * len(payload)
        archive.write_bytes(original)
    if state == "hardlinked":
        os.link(archive, archive.with_name("hardlinked-control.zip"))
    historical = paths.downloads_root / "build-3.1.9-241fe64c-9639-47ca-b2c5-c36b36b11f9a.zip"
    historical.write_bytes(payload)
    prepared = paths.updates_root / "prepared-core-download.json"
    prepared_bytes = prepared.read_bytes()
    if state == "conflicting_evidence":
        retained = paths.updates_root / f"rejected-prepared-{hashlib.sha256(prepared_bytes).hexdigest()}.json"
        retained.write_bytes(b"{}")

    fresh = online_update_runtime.WindowsOnlineUpdateRuntime(
        adapter=_Adapter(None), paths=paths, acl=_Acl(), download=None,
    )
    if state in {"hardlinked", "conflicting_evidence"}:
        message = "cannot be verified" if state == "hardlinked" else "Retained Core download evidence differs"
        with pytest.raises(ValueError, match=message):
            await fresh.run_once()
        assert archive.read_bytes() == original
        assert prepared.read_bytes() == prepared_bytes
        assert not paths.pending_path.exists()
        if state == "hardlinked":
            assert archive.with_name("hardlinked-control.zip").read_bytes() == original
            assert not list(paths.updates_root.glob("rejected-prepared-*.json"))
        else:
            assert retained.read_bytes() == b"{}"
        return
    result = await fresh.run_once()
    assert result.status == ("pending" if state == "pending" else "idle")
    if state in {"changed_bytes", "changed_size"}:
        assert result.authenticated_check
        assert archive.read_bytes() == original
        rejected, = paths.updates_root.glob("rejected-prepared-*.json")
        assert rejected.read_bytes() == prepared_bytes
        assert not prepared.exists()
        retry = online_update_runtime.WindowsOnlineUpdateRuntime(
            adapter=_Adapter(item), paths=paths, acl=_Acl(), download=download,
        )
        assert (await retry.run_once()).status == "scheduled"
        publication = json.loads(paths.pending_path.read_bytes())
        replacement = Path(publication["artifact_path"])
        assert replacement != archive and replacement.read_bytes() == payload
        assert archive.read_bytes() == original
        assert rejected.read_bytes() == prepared_bytes
    assert archive.exists() is (state != "abandoned")
    assert prepared.exists() is (state == "pending")
    assert historical.read_bytes() == payload


@pytest.mark.asyncio
@pytest.mark.parametrize("recommendation", ["idle", "assigned"])
async def test_interrupted_download_is_reclaimed_on_next_check(tmp_path, monkeypatch, recommendation):
    import os
    import shutil
    import subprocess
    import sys
    from types import SimpleNamespace
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.current_path.write_text('{"version":"3.2.1"}')
    paths.downloads_root.mkdir(parents=True)
    staging = paths.downloads_root / (".core-transfer-" + "a" * 32 + ".staging")
    partial = paths.downloads_root / ("." + staging.name + "." + "b" * 32 + ".tmp")
    linked = paths.downloads_root / (".core-transfer-" + "c" * 32 + ".staging")
    historical = paths.downloads_root / (".core-download-" + "d" * 32 + ".staging")
    canonical = paths.downloads_root / f"build-3.2.9-{_OPERATION_ID}.zip"
    child = '''
import os
import sys
from pathlib import Path
from pc_agent.platform.windows.update_download_retention import own_core_download
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

paths = WindowsUpdatePaths(Path(sys.argv[1]), Path(sys.argv[2]))
with own_core_download(paths):
    for name in sys.argv[3:]:
        (paths.downloads_root / name).write_bytes(b"interrupted transfer")
    os._exit(0)
'''
    subprocess.run(
        [sys.executable, "-c", child, str(paths.install_root), str(paths.pending_path), staging.name, partial.name],
        check=True, timeout=15,
    )
    assert staging.exists() and partial.exists()
    for path in (historical, canonical):
        path.write_bytes(b"previous bytes")
    os.link(canonical, linked)
    payload = b"verified archive"
    item = EndpointRecommendation(
        _OPERATION_ID, "3.2.2", "windows_amd64", "canary",
        "https://endpoint.example.test/build.zip", "build.zip", "zip",
        hashlib.sha256(payload).hexdigest(), len(payload), "scheduled_rollout",
    )

    def free_space(_):
        enough = not staging.exists() and not partial.exists()
        return SimpleNamespace(free=1024**3 if enough else 0)

    monkeypatch.setattr(shutil, "disk_usage", free_space)

    async def download(_, destination):
        destination.write_bytes(payload)
        return item.sha256, item.size

    adapter = _Adapter(item if recommendation == "assigned" else None)
    runtime = WindowsOnlineUpdateRuntime(adapter=adapter, paths=paths, acl=_Acl(), download=download)
    assert (await runtime.run_once()).status == ("scheduled" if recommendation == "assigned" else "idle")
    assert not staging.exists() and not partial.exists()
    for path in (canonical, linked, historical):
        assert path.read_bytes() == b"previous bytes"


@pytest.mark.asyncio
@pytest.mark.parametrize("recommendation", ["idle", "assigned"])
async def test_overlapping_checks_preserve_active_download(tmp_path, recommendation):
    import asyncio
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.current_path.write_text('{"version":"3.2.1"}')
    payload = b"verified archive"
    item = EndpointRecommendation(
        _OPERATION_ID, "3.2.2", "windows_amd64", "canary",
        "https://endpoint.example.test/build.zip", "build.zip", "zip",
        hashlib.sha256(payload).hexdigest(), len(payload), "scheduled_rollout",
    )
    started, release = asyncio.Event(), asyncio.Event()

    async def active_download(_, destination):
        destination.write_bytes(payload)
        started.set()
        await release.wait()
        assert destination.read_bytes() == payload
        return item.sha256, item.size

    async def competing_download(*_):
        pytest.fail("a second downloader entered the active transfer")

    first = WindowsOnlineUpdateRuntime(adapter=_Adapter(item), paths=paths, acl=_Acl(), download=active_download)
    adapter = _Adapter(item if recommendation == "assigned" else None)
    second = WindowsOnlineUpdateRuntime(adapter=adapter, paths=paths, acl=_Acl(), download=competing_download)
    active = asyncio.create_task(first.run_once())
    try:
        await asyncio.wait_for(started.wait(), timeout=5)
        assert (await second.run_once()).status == ("update_in_progress" if recommendation == "assigned" else "idle")
    finally:
        release.set()
        assert (await active).status == "scheduled"


@pytest.mark.asyncio
@pytest.mark.parametrize("interruption", ["ack", "selector", "competing_pending", "startup_attempt"])
async def test_unpublished_download_does_not_leave_an_operation_archive(tmp_path, interruption):
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.current_path.write_text('{"version":"3.2.1"}')
    payload = b"verified archive"
    competing_archive = paths.downloads_root / f"build-3.2.2-{_OPERATION_ID}.zip"
    competing_bytes = b"archive published by another owner"
    item = EndpointRecommendation(
        _OPERATION_ID, "3.2.2", "windows_amd64", "canary",
        "https://endpoint.example.test/build.zip", "build.zip", "zip",
        hashlib.sha256(payload).hexdigest(), len(payload), "scheduled_rollout",
    )

    class Adapter(_Adapter):
        async def record_scheduled_handoff(self, *_, **__):
            if interruption == "selector":
                paths.current_path.write_text('{"version":"3.2.9"}')
            if interruption == "competing_pending":
                competing_archive.write_bytes(competing_bytes)
                paths.pending_path.write_text(json.dumps(_pending_payload()))
            if interruption == "startup_attempt":
                (paths.updates_root / "startup-attempt.json").write_text('{"operation_id":"other"}')
            return interruption != "ack"

    async def download(_, path):
        path.write_bytes(payload)
        return item.sha256, item.size

    runtime = WindowsOnlineUpdateRuntime(adapter=Adapter(item), paths=paths, acl=_Acl(), download=download)
    result = await runtime.run_once()
    assert result.status == ("request_ack_pending" if interruption == "ack" else "update_in_progress")
    if interruption == "competing_pending":
        assert list(paths.downloads_root.iterdir()) == [competing_archive]
        assert competing_archive.read_bytes() == competing_bytes
        assert paths.pending_path.exists()
    else:
        assert not list(paths.downloads_root.iterdir())
        assert not paths.pending_path.exists()
        if interruption == "startup_attempt":
            assert (paths.updates_root / "startup-attempt.json").read_text() == '{"operation_id":"other"}'


def _pending_payload(operation_id: str = _OPERATION_ID, version: str = "3.2.2") -> dict:
    return {
        "archive_type": "zip",
        "artifact_path": "C:/ProgramData/Endpoint Platform/Agent/updates/artifact.zip",
        "channel": "canary",
        "operation_id": operation_id,
        "received_at": "2026-08-03T00:00:00+00:00",
        "requested_by": "gateway",
        "requested_reason": "scheduled_rollout",
        "sha256": "a" * 64,
        "size": 1,
        "target": "windows_amd64",
        "version": version,
    }


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

    def prepare_core_update_directories(self, updates, *, existing_only=False):
        downloads = updates / "downloads"
        if existing_only:
            return updates.is_dir() and downloads.is_dir()
        for path in (updates, downloads):
            path.mkdir(parents=True, exist_ok=True)
            self.protect_update_path(path)
        return True

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
            patch.setattr(online_update_runtime, "write_bytes_atomic", full)
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
@pytest.mark.parametrize("failure", ["file_flush", "replace", "archive_directory_flush", "directory_flush"])
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
            if path.name.startswith(".prepared-core-download"):
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
        if failure == "archive_directory_flush":
            from pc_agent.platform.windows import online_update_runtime
            flush = online_update_runtime.flush_directory
            failed = False

            def fail_first_archive_flush(directory):
                nonlocal failed
                if directory == paths.downloads_root and not failed:
                    failed = True
                    fault()
                return flush(directory)

            patch.setattr(online_update_runtime, "flush_directory", fail_first_archive_flush)
        elif failure == "directory_flush":
            flush = durable_state.flush_directory

            def fail_after_pending_replace(directory):
                if paths.pending_path.exists():
                    fault()
                return flush(directory)

            patch.setattr(durable_state, "flush_directory", fail_after_pending_replace)
        elif failure == "file_flush":
            patch.setattr(durable_state.os, "fsync", fault)
        else:
            replace = durable_state.os.replace

            def fail_pending_replace(source, destination):
                if destination == paths.pending_path:
                    fault()
                return replace(source, destination)

            patch.setattr(durable_state.os, "replace", fail_pending_replace)
        with pytest.raises(OSError, match="injected"):
            await runtime.run_once()
    assert json.loads(paths.current_path.read_text())["version"] == "3.2.1"
    assert not (paths.updates_root / "startup-confirmation.json").exists()
    adapter.calls.clear()
    if failure == "directory_flush":
        published = Path(json.loads(paths.pending_path.read_text())["artifact_path"])
        assert published.read_bytes() == payload
        assert (await runtime.run_once()).status == "pending"
        assert adapter.calls == [(_OPERATION_ID, "scheduled:3.2.2:3.2.1")]
    else:
        assert not paths.pending_path.exists()
        assert not list(paths.downloads_root.iterdir())
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
    paths.pending_path.write_text(json.dumps(_pending_payload()))
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
@pytest.mark.usefixtures("journal_test_directory")
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
    paths.pending_path.write_text(json.dumps(_pending_payload()))
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
        "artifact_path": str(Path(pending["artifact_path"])),
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
    assert acl.protected[:2] == [paths.updates_root, paths.downloads_root]
    assert len(acl.protected) == 4
    assert acl.protected[2].parent == paths.downloads_root
    assert acl.protected[2].name.startswith(".core-transfer-")
    assert acl.protected[2].suffix == ".staging"
    assert not acl.protected[2].exists()
    published = Path(pending["artifact_path"])
    assert published.parent == paths.downloads_root
    nonce = acl.protected[2].stem.removeprefix(".core-transfer-")
    assert published.name == f"build-3.2.2-{_OPERATION_ID}-{nonce}.zip"
    assert published.read_bytes() == payload
    assert acl.protected[-1].name.startswith(".prepared-core-download.json.")
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
@pytest.mark.parametrize("changed", [False, True])
async def test_windows_agent_reports_a_durable_updater_failure_after_wss(
    tmp_path: Path, changed: bool,
) -> None:
    """A rejected offline handoff becomes terminal only after the agent reconnects."""
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    paths = WindowsUpdatePaths(
        tmp_path / "install", tmp_path / "data" / "updates" / "pending_update.json"
    )
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.5"}', encoding="utf-8")
    paths.downloads_root.mkdir(parents=True)
    artifact = paths.downloads_root / f"build-3.2.6-{_OPERATION_ID}.zip"
    artifact.write_bytes(b"wrong" if changed else b"cache")
    neighbor = paths.downloads_root / "unowned.zip"
    neighbor.write_bytes(b"cache")
    pending = _pending_payload(version="3.2.6")
    pending.update(artifact_path=str(artifact), size=5, sha256=hashlib.sha256(b"cache").hexdigest())
    paths.pending_path.write_text(json.dumps(pending), encoding="utf-8")
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
    assert artifact.exists() is changed
    assert neighbor.read_bytes() == b"cache"


@pytest.mark.asyncio
@pytest.mark.parametrize("pending_payload", ["foreign", "corrupt"])
async def test_terminal_report_rejects_foreign_pending_without_attempt_before_http(tmp_path, pending_payload):
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.updates_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.79"}')
    foreign = (json.dumps(_pending_payload(operation_id="b" * 32, version="3.2.82"))
               if pending_payload == "foreign" else '{"operation_id":')
    paths.pending_path.write_text(foreign)
    outcome = paths.updates_root / "terminal-outcome.json"
    outcome.write_text(json.dumps({"operation_id": _OPERATION_ID, "reported_version": "3.2.79", "safe_code": "launcher_apply_failed", "status": "failed"}))
    adapter = _Adapter(None)
    runtime = WindowsOnlineUpdateRuntime(adapter=adapter, paths=paths, acl=_Acl(), download=None)

    assert await runtime.report_startup_outcome() is False
    assert adapter.calls == []
    assert paths.pending_path.read_text() == foreign
    assert outcome.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("pending_present", [True, False])
async def test_terminal_report_retries_with_matching_or_absent_pending(tmp_path, pending_present):
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.updates_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.79"}')
    if pending_present:
        paths.pending_path.write_text(json.dumps(_pending_payload(version="3.2.80")))
    outcome = paths.updates_root / "terminal-outcome.json"
    outcome.write_text(json.dumps({"operation_id": _OPERATION_ID, "reported_version": "3.2.79", "safe_code": "launcher_apply_failed", "status": "failed"}))
    adapter = _Adapter(None)
    runtime = WindowsOnlineUpdateRuntime(adapter=adapter, paths=paths, acl=_Acl(), download=None)

    assert await runtime.report_startup_outcome() is True
    assert adapter.calls == [(_OPERATION_ID, "scheduled_retry"), (_OPERATION_ID, "failed:3.2.79:launcher_apply_failed")]
    assert not paths.pending_path.exists()
    assert not outcome.exists()


@pytest.mark.asyncio
async def test_terminal_report_rejects_attempt_without_pending_before_http(tmp_path):
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.updates_root.mkdir(parents=True)
    current_bytes = b'{"version":"3.2.79"}'
    paths.current_path.write_bytes(current_bytes)
    attempt = paths.updates_root / "startup-attempt.json"
    attempt_bytes = json.dumps({
        "operation_id": _OPERATION_ID, "version": "3.2.80", "attempt_id": "a" * 32,
    }).encode()
    attempt.write_bytes(attempt_bytes)
    outcome = paths.updates_root / "terminal-outcome.json"
    outcome_bytes = json.dumps({
        "operation_id": _OPERATION_ID, "reported_version": "3.2.79",
        "safe_code": "launcher_apply_failed", "status": "failed",
    }).encode()
    outcome.write_bytes(outcome_bytes)
    adapter = _Adapter(None)
    runtime = WindowsOnlineUpdateRuntime(adapter=adapter, paths=paths, acl=_Acl(), download=None)

    assert await runtime.report_startup_outcome() is False
    assert adapter.calls == []
    assert paths.current_path.read_bytes() == current_bytes
    assert attempt.read_bytes() == attempt_bytes
    assert outcome.read_bytes() == outcome_bytes
    assert not paths.pending_path.exists()


@pytest.mark.asyncio
async def test_terminal_report_cleanup_preserves_new_pending_from_other_owner(tmp_path):
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths=WindowsUpdatePaths(tmp_path/'install',tmp_path/'data'/'updates'/'pending_update.json')
    paths.install_root.mkdir();paths.updates_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.79"}')
    outcome=paths.updates_root/'terminal-outcome.json'
    outcome.write_text(json.dumps(dict(operation_id=_OPERATION_ID,reported_version='3.2.79',status='failed',safe_code='launcher_apply_failed')))
    paths.pending_path.write_text(json.dumps(_pending_payload(version='3.2.80')))
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
    paths.pending_path.write_text(json.dumps(_pending_payload(version="3.2.80")))
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


def _ota_directory_policy(tmp_path, monkeypatch, layout):
    from dataclasses import dataclass
    from types import SimpleNamespace

    rights = pytest.importorskip("ntsecuritycon")
    native = pytest.importorskip("win32security")
    from pc_agent.platform.windows import acl as windows_acl
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data" / "updates" / "pending_update.json")
    paths.install_root.mkdir()
    paths.current_path.write_bytes(b'{"version":"3.2.1"}')
    data_root = paths.updates_root.parent
    data_root.mkdir(exist_ok=True)
    updates, downloads = paths.updates_root, paths.downloads_root
    if layout not in {"new-directories", "journal-only"}:
        updates.mkdir()
        if layout not in {"partial-updates", "partial-updates-msi-parent", "system-inherited", "wrong-mask", "wrong-inheritance", "wrong-owner"}:
            downloads.mkdir()
    if layout == "unexpected-descendant":
        downloads.rmdir()
        downloads.write_text("wrong object kind")
    if layout == "reparse":
        import subprocess

        downloads.rmdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        subprocess.run(["cmd", "/c", "mklink", "/J", str(downloads), str(outside)], check=True, capture_output=True)

    system, local = "S-1-5-18", "S-1-5-19"
    ids = (system, "S-1-5-32-544", "service", "updater")
    modify = rights.FILE_GENERIC_READ | rights.FILE_GENERIC_WRITE | rights.DELETE
    write_delete = rights.FILE_GENERIC_WRITE | rights.DELETE
    explicit = native.OBJECT_INHERIT_ACE | native.CONTAINER_INHERIT_ACE
    inherited = explicit | native.INHERITED_ACE

    @dataclass
    class Descriptor:
        owner: str
        protected: bool
        flags: int
        updater_mask: int
        service_mask: int = modify

        def GetSecurityDescriptorOwner(self):
            return self.owner

        def GetSecurityDescriptorControl(self):
            return native.SE_DACL_PROTECTED if self.protected else 0, 1

        def GetSecurityDescriptorDacl(self):
            aces = [((native.ACCESS_ALLOWED_ACE_TYPE, self.flags), mask, sid) for sid, mask in zip(
                ids, (rights.FILE_ALL_ACCESS, rights.FILE_ALL_ACCESS, self.service_mask, self.updater_mask)
            )]
            return SimpleNamespace(GetAceCount=lambda: len(aces), GetAce=lambda index: aces[index])

    parent_mask = modify if layout == "partial-updates-msi-parent" else write_delete
    modeled = {data_root: Descriptor(system, True, explicit, parent_mask)}
    if updates.exists():
        modeled[updates] = Descriptor(system, True, explicit, modify)
    if downloads.is_dir():
        modeled[downloads] = Descriptor(system, True, explicit, modify)
    partial_root = Descriptor(local, False, inherited, parent_mask)
    if layout in {"partial-updates", "partial-updates-msi-parent", "system-inherited", "wrong-mask", "wrong-inheritance", "wrong-owner"}:
        modeled[updates] = partial_root
    if layout == "partial-downloads":
        modeled[downloads] = Descriptor(local, False, inherited, modify)
    if layout == "system-inherited":
        partial_root.owner = system
    if layout == "wrong-mask":
        partial_root.updater_mask = modify
    if layout == "wrong-inheritance":
        partial_root.flags = native.INHERITED_ACE
    if layout == "wrong-owner":
        partial_root.owner = "unrelated"

    def read(path, *_):
        path = Path(path)
        if path not in modeled:
            assert path.is_dir()
            parent = modeled[path.parent]
            modeled[path] = Descriptor(local, False, inherited, parent.updater_mask)
        return modeled[path]

    def parent_authority(path, *_):
        assert path == data_root
        if layout == "untrusted-parent":
            raise windows_acl.WindowsAclError("untrusted data root")

    writes = []
    reader = SimpleNamespace(
        GetNamedSecurityInfo=read, ConvertSidToStringSid=lambda sid: sid,
        LookupAccountName=lambda _, principal: (
            "service" if principal == windows_acl.SERVICE_PRINCIPAL else "updater", None, None
        ),
        **{name: getattr(native, name) for name in (
            "SE_FILE_OBJECT", "OWNER_SECURITY_INFORMATION", "GROUP_SECURITY_INFORMATION", "DACL_SECURITY_INFORMATION",
            "SE_DACL_PROTECTED", "ACCESS_ALLOWED_ACE_TYPE", "OBJECT_INHERIT_ACE",
            "CONTAINER_INHERIT_ACE", "INHERITED_ACE",
        )},
    )
    monkeypatch.setattr(windows_acl, "_assert_machine_data_parent_authority", parent_authority)
    monkeypatch.setattr(windows_acl, "_assert_trusted_owner", lambda *_: None)
    monkeypatch.setattr(windows_acl, "_machine_data_service_sid", lambda principal: reader.LookupAccountName(None, principal)[0])

    class Acl(windows_acl.PyWin32AclAdapter):
        def _modules(self):
            return reader, rights

        def protect_update_path(self, path):
            writes.append(path.name)

        def _protect_core_update_directory(self, path, parent, security, acl_rights):
            assert windows_acl._core_update_descriptor_mode(read(path), security, acl_rights, parent) == "inherited"
            writes.append(path.name)
            modeled[path] = Descriptor(local, True, explicit, modify)

    return paths, Acl, writes


def _ota_fixture_artifact():
    payload = b"bounded scratch fixture"
    item = EndpointRecommendation(
        _OPERATION_ID, "3.2.2", "windows_amd64", "canary",
        "https://endpoint.example.test/build.zip", "build.zip", "zip", hashlib.sha256(payload).hexdigest(),
        len(payload), "scheduled_rollout",
    )
    return payload, item


@pytest.mark.asyncio
@pytest.mark.parametrize(("layout", "protected_names"), [
    ("system-canonical", []),
    ("partial-updates", ["updates", "downloads"]),
    ("partial-updates-msi-parent", ["updates", "downloads"]),
    ("partial-downloads", ["downloads"]),
    ("new-directories", ["updates", "downloads"]),
    ("system-inherited", None),
    ("wrong-mask", None),
    ("wrong-inheritance", None),
    ("wrong-owner", None),
    ("unexpected-descendant", None),
    ("untrusted-parent", None),
    ("reparse", None),
])
async def test_stock_ota_validates_existing_directory_dacl_before_get(tmp_path, monkeypatch, layout, protected_names):
    from pc_agent.platform.windows.acl import WindowsAclError
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime

    paths, Acl, writes = _ota_directory_policy(tmp_path, monkeypatch, layout)
    updates = paths.updates_root
    payload, item = _ota_fixture_artifact()
    transfer = []

    async def download(_, path):
        transfer.append(path)
        path.write_bytes(payload)
        return item.sha256, item.size

    adapter = _Adapter(item)
    runtime = WindowsOnlineUpdateRuntime(adapter=adapter, paths=paths, acl=Acl(), download=download)
    if protected_names is None:
        with pytest.raises((WindowsAclError, ValueError)):
            await runtime.run_once()
        assert writes == [] and transfer == []
        assert not paths.pending_path.exists() and not (updates / ".core-download.lock").exists()
    else:
        result = await runtime.run_once()
        assert result.status == "scheduled"
        assert [name for name in writes if name in {"updates", "downloads"}] == protected_names
        assert len(transfer) == 1 and len(writes) == len(protected_names) + 2
        assert paths.pending_path.exists()
        assert json.loads(paths.pending_path.read_bytes())["operation_id"] == item.operation_id


def _ota_journal_adapter(monkeypatch, Acl, data_root, payload, item):
    from pc_agent.tests.test_update_adapter import _Response, _valid_payload
    from pc_agent.update_adapter import EndpointUpdateAdapter

    origin = "https://endpoint.example.test"
    recommendation = dict(json.loads(_valid_payload()), operation_id=item.operation_id,
                          version=item.version, artifact_url=item.artifact_url,
                          artifact_name=item.artifact_name, size=item.size, sha256=item.sha256)
    calls = []

    class Session:
        def get(self, url, **_):
            if url == item.artifact_url:
                calls.append("artifact")
                return ArtifactResponse(payload)
            assert url.startswith(origin + "/agent/v1/updates/recommendation?")
            calls.append("recommendation")
            return _Response(200, json.dumps(recommendation))

        def post(self, url, *, json, **_):
            prefix = f"{origin}/agent/v1/updates/{item.operation_id}/"
            assert url in {prefix + "ack", prefix + "reports"}
            calls.append(json["status"])
            return _Response(204 if url.endswith("/ack") else 200, "")

    class ArtifactResponse(_Response):
        def __init__(self, contents):
            super().__init__(200, "")
            self.content = self
            self.contents = contents

        async def iter_chunked(self, _):
            yield self.contents

        def raise_for_status(self):
            pass

    def forbid_directory_write(*_):
        pytest.fail("journal attempted unconditional WRITE_DAC on updates")

    monkeypatch.setattr(Acl, "protect_directory", forbid_directory_write)
    monkeypatch.setattr("pc_agent.update_adapter.PyWin32AclAdapter", Acl)
    session = Session()
    adapter = EndpointUpdateAdapter(api_url=origin, bearer_token=lambda: "fixture",
                                    session=session, data_root=data_root, strict_recovery=True)
    return adapter, session, origin, calls


@pytest.mark.asyncio
async def test_stock_ota_journals_publish_pending_and_terminal_with_canonical_directories(tmp_path, monkeypatch):
    from pc_agent.endpoint_gateway import _download_gateway_artifact
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime

    paths, Acl, writes = _ota_directory_policy(tmp_path, monkeypatch, "system-canonical")
    updates = paths.updates_root
    payload, item = _ota_fixture_artifact()
    adapter, session, origin, calls = _ota_journal_adapter(monkeypatch, Acl, updates.parent, payload, item)

    def download(item, path):
        return _download_gateway_artifact(session, item, path, endpoint_origin=origin,
                                          credential_source=lambda: "fixture")

    runtime = WindowsOnlineUpdateRuntime(adapter=adapter, paths=paths, acl=Acl(), download=download)
    assert (await runtime.run_once()).status == "scheduled"
    pending = json.loads(paths.pending_path.read_bytes())
    assert pending["operation_id"] == item.operation_id
    assert Path(pending["artifact_path"]).read_bytes() == payload
    (updates / "terminal-outcome.json").write_text(json.dumps(dict(
        operation_id=item.operation_id, status="rolled_back",
        reported_version="3.2.1", safe_code="launcher_rolled_back",
    )))
    assert await runtime.report_startup_outcome()
    assert not paths.pending_path.exists()
    assert calls == ["recommendation", "requested", "artifact", "scheduled", "rolled_back"]
    assert "updates" not in writes and "downloads" not in writes
    for journal in (adapter._update_state_path(), adapter._report_journal_path()):
        assert json.loads(journal.read_bytes())[0]["operation_id"] == item.operation_id


@pytest.mark.asyncio
async def test_terminal_journal_prepares_updates_without_downloads(tmp_path, monkeypatch):
    paths, Acl, writes = _ota_directory_policy(tmp_path, monkeypatch, "journal-only")
    payload, item = _ota_fixture_artifact()
    adapter, _, _, calls = _ota_journal_adapter(monkeypatch, Acl, paths.updates_root.parent, payload, item)
    assert await adapter.report_terminal(item.operation_id, status="failed",
                                         reported_version="3.2.1", safe_code="launcher_apply_failed")
    assert calls == ["failed"]
    assert not paths.downloads_root.exists()
    assert writes.count("updates") == 1


def test_core_directory_protection_does_not_propagate_to_existing_children(tmp_path, monkeypatch):
    from types import SimpleNamespace

    rights = pytest.importorskip("ntsecuritycon")
    native = pytest.importorskip("win32security")
    from pc_agent.platform.windows import acl as windows_acl
    from pc_agent.platform.windows.update_transaction import _SERVICE_SIDS

    flags = native.OBJECT_INHERIT_ACE | native.CONTAINER_INHERIT_ACE
    info = native.OWNER_SECURITY_INFORMATION | native.DACL_SECURITY_INFORMATION
    protected_info = native.DACL_SECURITY_INFORMATION | native.PROTECTED_DACL_SECURITY_INFORMATION
    modify = rights.FILE_GENERIC_READ | rights.FILE_GENERIC_WRITE | rights.DELETE
    sids = ("S-1-5-18", "S-1-5-32-544", *_SERVICE_SIDS)

    def set_policy(path, ace_flags, updater_mask):
        dacl = native.ACL()
        for sid, mask in zip(sids, (rights.FILE_ALL_ACCESS, rights.FILE_ALL_ACCESS, modify, updater_mask)):
            dacl.AddAccessAllowedAceEx(native.ACL_REVISION, ace_flags, mask, native.ConvertStringSidToSid(sid))
        native.SetNamedSecurityInfo(str(path), native.SE_FILE_OBJECT, protected_info, None, None, dacl, None)

    def read(path):
        return native.GetNamedSecurityInfo(str(path), native.SE_FILE_OBJECT, info)

    def sddl(path):
        return native.ConvertSecurityDescriptorToStringSecurityDescriptor(read(path), 1, info)

    data = tmp_path / "native-data"
    data.mkdir()
    set_policy(data, flags, rights.FILE_GENERIC_WRITE | rights.DELETE)
    updates = data / "updates"
    updates.mkdir()
    owner = updates / "core-shutdown.json"
    owner.write_bytes(b"local fixture")
    set_policy(owner, 0, modify)
    inherited = updates / "inherited.txt"
    inherited.write_bytes(b"local fixture")
    before = [sddl(path) for path in (data, owner, inherited)]
    update_before = sddl(updates)

    # Use the actual native DACL and handle APIs. The operator test token
    # owns the fixture, so substitute only service-account SID resolution.
    validate = windows_acl._core_update_descriptor_mode
    monkeypatch.setattr(native, "LookupAccountName", lambda _, principal: (
        native.ConvertStringSidToSid(windows_acl._machine_data_service_sid(principal)), "", 0,
    ))
    monkeypatch.setattr(windows_acl, "_core_update_descriptor_mode", lambda descriptor, *args: validate(
        SimpleNamespace(
            GetSecurityDescriptorOwner=lambda: native.ConvertStringSidToSid("S-1-5-19"),
            GetSecurityDescriptorControl=descriptor.GetSecurityDescriptorControl,
            GetSecurityDescriptorDacl=descriptor.GetSecurityDescriptorDacl,
        ), *args,
    ))

    windows_acl.PyWin32AclAdapter._protect_core_update_directory(updates, read(data), native, rights)

    assert update_before != sddl(updates)
    assert read(updates).GetSecurityDescriptorControl()[0] & native.SE_DACL_PROTECTED
    assert [sddl(path) for path in (data, owner, inherited)] == before
