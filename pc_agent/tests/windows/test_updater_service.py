"""Contracts for the offline, privileged Windows update worker."""

from __future__ import annotations

import subprocess

import hashlib
import inspect
import json
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


@pytest.mark.parametrize("filename", ["current.json", "previous.json", "startup-attempt.json",
    "terminal-outcome.json", ".endpoint-initial-runtime-selector.rollback.json",
    "startup-confirmation.json", "endpoint_update_state.json", "endpoint_update_reports.json"])
@pytest.mark.parametrize("failure", ["file_flush", "replace", "directory_flush"])
def test_critical_publication_failure_preserves_parseable_restart_state(tmp_path, monkeypatch, filename, failure):
    """Every owning writer must propagate durability failure; visibility is not success."""
    from pc_agent.platform.windows import durable_state, selector_migration, startup_confirmation, updater_service
    from pc_agent.update_adapter import EndpointUpdateAdapter
    paths = _paths(tmp_path)
    paths.install_root.mkdir(parents=True)
    paths.updates_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.1.0"}')
    root = paths.install_root if filename in {"current.json", "previous.json", selector_migration.ROLLBACK_SNAPSHOT_FILENAME} else paths.updates_root
    destination = root / filename
    old = [] if filename.startswith("endpoint_update_") else {"version": "3.1.0"}
    destination.write_text(json.dumps(old))
    adapter = EndpointUpdateAdapter(api_url="https://endpoint.example.test", bearer_token=lambda: "test", session=object(), data_root=paths.updates_root.parent)
    if filename == "startup-confirmation.json":
        paths.current_path.write_text('{"version":"3.2.0"}')
        paths.pending_path.write_text('{"version":"3.2.0","operation_id":"operation"}')
        (paths.updates_root / "startup-attempt.json").write_text('{"version":"3.2.0","operation_id":"operation","attempt_id":"attempt"}')
        monkeypatch.setattr(startup_confirmation, "AGENT_VERSION", "3.2.0")
    original_flush = durable_state.flush_directory
    def fault(*args, **kwargs):
        if failure == "directory_flush" and Path(args[0]) != root:
            return original_flush(*args, **kwargs)
        raise OSError("injected " + failure)
    if failure == "file_flush":
        monkeypatch.setattr(durable_state.os, "fsync", fault)
    elif failure == "replace":
        monkeypatch.setattr(durable_state.os, "replace", fault)
    else:
        monkeypatch.setattr(durable_state, "flush_directory", fault)
    with pytest.raises(OSError, match="injected"):
        if filename in {"current.json", "previous.json"}:
            updater_service._write_json_atomic(destination, {"version": "3.2.0"}, trusted_root=root)
        elif filename == "startup-attempt.json":
            pending = SimpleNamespace(operation_id="operation", version="3.2.0")
            updater_service._write_startup_attempt(paths, pending)
        elif filename == "terminal-outcome.json":
            updater_service._write_terminal_outcome(paths, operation_id="operation", status="failed", reported_version="3.1.0", safe_code="launcher_apply_failed")
        elif filename == selector_migration.ROLLBACK_SNAPSHOT_FILENAME:
            selector_migration._write_rollback_snapshot(paths, "3.1.0")
        elif filename == "startup-confirmation.json":
            startup_confirmation.StartupProofWriter(paths).record_after_server_handshake()
        elif filename == "endpoint_update_state.json":
            adapter._write_update_state([{ "operation_id": "operation" }])
        else:
            adapter._write_report_journal([{ "report_key": "key" }])
    recovered = json.loads(destination.read_text())
    if failure != "directory_flush":
        assert recovered == old
    else:
        assert isinstance(recovered, list if filename.startswith("endpoint_update_") else dict)
    # A new worker can never infer authenticated WSS proof from other journals.
    confirmation = updater_service.FileStartupConfirmation(paths)
    assert not confirmation.is_confirmed(version="3.2.0", operation_id="operation", attempt_id="other", not_before=datetime.now(UTC))


@pytest.mark.parametrize("filename,existing", [("current.json", True), ("previous.json", True),
    (".endpoint-initial-runtime-selector.rollback.json", True), ("previous.json", False),
    (".endpoint-initial-runtime-selector.rollback.json", False)])
def test_selector_replacement_preserves_explicit_native_dacl(tmp_path, filename, existing):
    """An explicit stricter leaf policy must survive atomic replacement."""
    import os
    if os.name != "nt":
        pytest.skip("native Windows ACL evidence")
    import win32security
    from pc_agent.platform.windows import selector_migration, updater_service
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path, tmp_path / "updates" / "pending_update.json")
    path = tmp_path / filename
    paths.current_path.write_text('{"version":"3.1.0"}')
    if existing:
        path.write_text('{"version":"3.1.0"}')
    source = path if existing else paths.current_path
    acl = win32security.ACL()
    sid = win32security.ConvertStringSidToSid("S-1-5-32-544")
    acl.AddAccessAllowedAce(win32security.ACL_REVISION, 0x1F01FF, sid)
    win32security.SetNamedSecurityInfo(str(source), win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, acl, None)
    owner_before = win32security.GetNamedSecurityInfo(str(source), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION).GetSecurityDescriptorOwner()
    if filename == "current.json":
        selector_migration._write_selector_atomic(path, "3.2.0")
    elif filename == "previous.json":
        updater_service._write_json_atomic(path, {"version":"3.2.0"}, trusted_root=paths.install_root, template=paths.current_path)
    else:
        selector_migration._write_rollback_snapshot(paths, "3.2.0")
    descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)
    assert win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) == win32security.ConvertSidToStringSid(owner_before)
    assert descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED
    assert descriptor.GetSecurityDescriptorDacl().GetAceCount() == 1
    assert win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorDacl().GetAce(0)[2]) == "S-1-5-32-544"


def test_startup_attempt_delete_failure_flushes_absent_marker_on_retry(tmp_path, monkeypatch):
    from pc_agent.platform.windows import durable_state, updater_service
    paths = _paths(tmp_path)
    paths.updates_root.mkdir(parents=True)
    attempt = paths.updates_root / "startup-attempt.json"
    attempt.write_text('{"attempt_id":"bound"}')
    def fail(path):
        raise OSError("attempt metadata failed")
    with monkeypatch.context() as patch:
        patch.setattr(durable_state, "flush_directory", fail)
        with pytest.raises(OSError, match="attempt metadata"):
            updater_service._clear_startup_attempt(paths)
    assert not attempt.exists()
    flushed = []
    monkeypatch.setattr(durable_state, "flush_directory", lambda path: flushed.append(path))
    updater_service._clear_startup_attempt(paths)
    assert flushed == [paths.updates_root]


def test_offline_updater_import_graph_has_no_http_clients():
    result = subprocess.run([sys.executable, "-c",
        "import sys; import pc_agent.platform.windows.service_launcher; "
        "import pc_agent.platform.windows.updater_service; "
        "blocked=('aiohttp','httpx','requests','urllib.request'); "
        "found=sorted(n for n in sys.modules if any(n==p or n.startswith(p+'.') for p in blocked)); "
        "print(found); raise SystemExit(bool(found))"],
        capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def _pending(paths, artifact: Path, **changes: object) -> Path:
    payload: dict[str, object] = {
        "archive_type": "zip",
        "artifact_path": str(artifact),
        "channel": "canary",
        "operation_id": "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e",
        "received_at": datetime.now(UTC).isoformat(),
        "requested_by": "gateway",
        "requested_reason": "scheduled_rollout",
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "size": artifact.stat().st_size,
        "target": "windows_amd64",
        "version": "3.2.0",
    }
    payload.update(changes)
    paths.pending_path.parent.mkdir(parents=True, exist_ok=True)
    paths.pending_path.write_text(json.dumps(payload), encoding="utf-8")
    return paths.pending_path


def _artifact(path: Path, content: bytes = b"agent", *, version: str = "3.2.0") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    files = {"pc_agent.exe": content, "_internal/runtime.dat": b"runtime"}
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)
        archive.writestr("endpoint-update-manifest.json", json.dumps({
            "files": [
                {"path": name, "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}
                for name, payload in sorted(files.items())
            ],
            "schema_version": 1,
            "source_revision": "a" * 40,
            "version": version,
        }))
    return path


class _Acl:
    def __init__(self, *, reject: bool = False) -> None:
        self.reject = reject
        self.checked: list[Path] = []

    def assert_update_path(self, path: Path) -> None:
        self.checked.append(path)
        if self.reject:
            raise ValueError("wrong owner or ACL")


def _paths(tmp_path: Path):
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    return WindowsUpdatePaths(
        install_root=tmp_path / "install",
        pending_path=tmp_path / "data" / "updates" / "pending_update.json",
    )


@pytest.mark.parametrize("failure", ["capacity", "extract", "extraction_fsync", "pinned_fsync", "previous", "attempt", "selector", "selector_directory"])
def test_disk_failure_preserves_old_core_and_can_retry(tmp_path, monkeypatch, failure):
    import errno
    from pc_agent.platform.windows import durable_state, updater_service
    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.1.9"}')
    events = []
    service = SimpleNamespace(stop=lambda: events.append("stop"), start=lambda: events.append("start"),
        wait_stopped=lambda: True, crashed_early=lambda: False)
    updater = updater_service.WindowsUpdater(paths, acl=_Acl(), service=service,
        verifier=SimpleNamespace(verify=lambda *_: True), confirmation=SimpleNamespace(is_confirmed=lambda **_: True))
    original_write = updater_service._write_json_atomic
    original_attempt = updater_service._write_startup_attempt
    original_flush = durable_state.flush_directory
    def full(*_, **__):
        raise OSError(errno.ENOSPC, "private/path must never escape")
    def write(path, *args, **kwargs):
        if path.name == {"previous": "previous.json", "selector": "current.json"}.get(failure):
            full()
        original_write(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        if failure == "capacity":
            import shutil
            patch.setattr(shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
        elif failure == "extract":
            patch.setattr(updater_service, "_extract_zip_member", full)
        elif failure in {"extraction_fsync", "pinned_fsync"}:
            original_fsync = updater_service.os.fsync
            def file_full(descriptor):
                if updater_service.os.fstat(descriptor).st_size == (len(b"agent") if failure == "extraction_fsync" else artifact.stat().st_size):
                    full()
                original_fsync(descriptor)
            patch.setattr(updater_service.os, "fsync", file_full)
        elif failure == "attempt":
            patch.setattr(updater_service, "_write_startup_attempt", full)
        elif failure == "selector_directory":
            failed = False
            def flush(path):
                nonlocal failed
                if not failed and path == paths.install_root and json.loads(paths.current_path.read_text())["version"] == "3.2.0":
                    failed = True
                    full()
                original_flush(path)
            patch.setattr(durable_state, "flush_directory", flush)
        else:
            patch.setattr(updater_service, "_write_json_atomic", write)
        result = updater.run_once()
    assert result.status == "disk_insufficient"
    assert result.message == "DISK_INSUFFICIENT"
    assert json.loads(paths.current_path.read_text()) == {"version": "3.1.9"}
    assert paths.pending_path.exists()
    assert not (paths.updates_root / "terminal-outcome.json").exists()
    if failure in {"capacity", "extract", "extraction_fsync", "pinned_fsync", "previous", "attempt"}:
        assert events == []
    else:
        assert events == ["stop", "start"]
    assert updater.run_once().status == "applied"


@pytest.mark.parametrize("size", [-1, 2 * 1024 * 1024 * 1024 + 1])
def test_archive_total_rejects_invalid_members_before_budget(size):
    from pc_agent.platform.windows.updater_service import _validate_archive_limits
    with pytest.raises(ValueError):
        _validate_archive_limits([SimpleNamespace(file_size=size)])


def test_prepared_attempt_cannot_grant_old_core_confirmation(tmp_path, monkeypatch):
    from pc_agent.platform.windows import startup_confirmation, updater_service
    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.1.9"}')
    pending = updater_service.PendingUpdateValidator(paths, _Acl()).load()
    updater_service._write_startup_attempt(paths, pending)
    monkeypatch.setattr(startup_confirmation, "AGENT_VERSION", "3.1.9")
    assert not startup_confirmation.StartupProofWriter(paths).record_after_server_handshake()
    assert not (paths.updates_root / "startup-confirmation.json").exists()


def test_persistent_exhaustion_restores_without_new_payload_allocation(tmp_path, monkeypatch):
    import errno
    from pc_agent.platform.windows import durable_state, updater_service
    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    paths.install_root.mkdir(parents=True)
    old = {"schema_version": 1, "source_revision": "b" * 40, "version": "3.1.9"}
    paths.current_path.write_text(json.dumps(old))
    events = []
    service = SimpleNamespace(stop=lambda: events.append("stop"), start=lambda: events.append("start"),
        wait_stopped=lambda: True, crashed_early=lambda: False)
    worker = updater_service.WindowsUpdater(paths, acl=_Acl(), service=service,
        verifier=SimpleNamespace(verify=lambda *_: True), confirmation=SimpleNamespace(is_confirmed=lambda **_: True))
    original_flush, original_write = durable_state.flush_directory, durable_state.os.write
    exhausted = False
    def flush(path):
        nonlocal exhausted
        if path == paths.install_root and json.loads(paths.current_path.read_text())["version"] == "3.2.0":
            exhausted = True
        if exhausted:
            raise OSError(errno.ENOSPC, "persistent disk exhaustion")
        original_flush(path)
    def write(descriptor, data):
        if exhausted:
            raise OSError(errno.ENOSPC, "persistent disk exhaustion")
        return original_write(descriptor, data)
    with monkeypatch.context() as patch:
        patch.setattr(durable_state, "flush_directory", flush)
        patch.setattr(durable_state.os, "write", write)
        assert worker.run_once().status == "disk_insufficient"
        assert json.loads(paths.current_path.read_text()) == old
        assert events == ["stop", "start"]
        assert paths.pending_path.exists()
    restarted = updater_service.WindowsUpdater(paths, acl=_Acl(), service=service,
        verifier=SimpleNamespace(verify=lambda *_: True), confirmation=SimpleNamespace(is_confirmed=lambda **_: True))
    assert restarted.run_once().status == "applied"


def _interrupted_transition(tmp_path, *, selected=True):
    from pc_agent.platform.windows import updater_service
    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    paths.install_root.mkdir(parents=True)
    old = {"schema_version": 1, "source_revision": "b" * 40, "version": "3.1.9"}
    paths.current_path.write_text(json.dumps(old))
    worker = updater_service.WindowsUpdater(paths, acl=_Acl())
    pending = worker._validator.load()
    staging = worker._extract_to_staging(pending)
    worker._publish(staging, pending)
    candidate = {"schema_version": 1, "source_revision": "a" * 40, "version": "3.2.0"}
    worker._attempt_id = updater_service._write_startup_attempt(paths, pending)
    worker._prepare_transition(pending, candidate)
    if selected:
        updater_service._write_json_atomic(paths.current_path, candidate, trusted_root=paths.install_root)
    return paths, old


def test_old_selected_restart_survives_persistent_exhaustion_and_retries(tmp_path, monkeypatch):
    import errno
    from pc_agent.platform.windows import durable_state, updater_service
    paths, old = _interrupted_transition(tmp_path, selected=False)
    old_bytes = paths.current_path.read_bytes()
    retained = {path: path.read_bytes() for path in (
        paths.pending_path, paths.transition_path, paths.restore_path,
        paths.updates_root / "startup-attempt.json",
    )}
    events, proofs = [], []
    running = False
    def start():
        nonlocal running
        if running:
            error = OSError("service already running")
            error.winerror = 1056
            raise error
        running = True
        events.append(("start", json.loads(paths.current_path.read_text())))
    def stop():
        nonlocal running
        running = False
        events.append(("stop", None))
    def confirmed(**_):
        proofs.append(True)
        return True
    service = SimpleNamespace(start=start, stop=stop, wait_stopped=lambda: True,
        crashed_early=lambda: False)
    def worker():
        return updater_service.WindowsUpdater(paths, acl=_Acl(), service=service,
            verifier=SimpleNamespace(verify=lambda *_: True),
            confirmation=SimpleNamespace(is_confirmed=confirmed))
    def exhausted(*_):
        raise OSError(errno.ENOSPC, "persistent disk exhaustion")
    with monkeypatch.context() as patch:
        patch.setattr(updater_service, "flush_directory", exhausted)
        patch.setattr(durable_state, "flush_directory", exhausted)
        patch.setattr(durable_state.os, "write", exhausted)
        assert worker().run_once().status == "disk_insufficient"
        assert running
        assert events == [("start", old)]
        assert paths.current_path.read_bytes() == old_bytes
        assert {path: path.read_bytes() for path in retained} == retained
        assert not proofs
        assert not (paths.updates_root / "terminal-outcome.json").exists()
    assert worker().run_once().status == "applied"
    assert running
    assert events == [("start", old), ("stop", None),
        ("start", {"schema_version": 1, "source_revision": "a" * 40, "version": "3.2.0"})]
    assert proofs == [True]
    assert not paths.pending_path.exists()
    assert not paths.transition_path.exists()
    assert not paths.restore_path.exists()


@pytest.mark.parametrize("selected", [False, True])
def test_restart_reconciles_unaccepted_transition_before_normal_eligibility(tmp_path, selected):
    from pc_agent.platform.windows import updater_service
    paths, old = _interrupted_transition(tmp_path, selected=selected)
    starts, stops, proofs = [], [], []
    service = SimpleNamespace(stop=lambda: stops.append(True),
        start=lambda: starts.append(json.loads(paths.current_path.read_text())), wait_stopped=lambda: True,
        crashed_early=lambda: False)
    def confirmed(**_):
        proofs.append(True)
        return not selected or len(proofs) > 1
    restarted = updater_service.WindowsUpdater(paths, acl=_Acl(), service=service,
        verifier=SimpleNamespace(verify=lambda *_: True), confirmation=SimpleNamespace(is_confirmed=confirmed))
    assert restarted.run_once().status == "applied"
    assert starts[0] == old
    assert starts[-1]["version"] == "3.2.0"
    assert len(stops) == (2 if selected else 1)
    assert not paths.transition_path.exists()
    assert not paths.restore_path.exists()


@pytest.mark.parametrize("mismatch", ["operation", "archive", "attempt", "revision", "acl", "partial", "payload", "reparse"])
def test_restart_rejects_mismatched_transition_identity_before_service_mutation(tmp_path, monkeypatch, mismatch):
    from pc_agent.platform.windows import updater_service
    paths, _ = _interrupted_transition(tmp_path)
    if mismatch in {"operation", "archive"}:
        payload = json.loads(paths.pending_path.read_text())
        payload["operation_id" if mismatch == "operation" else "sha256"] = "different" if mismatch == "operation" else "f" * 64
        paths.pending_path.write_text(json.dumps(payload))
    elif mismatch == "attempt":
        attempt = paths.updates_root / "startup-attempt.json"
        payload = json.loads(attempt.read_text())
        payload["attempt_id"] = "f" * 32
        attempt.write_text(json.dumps(payload))
    elif mismatch == "revision":
        current = json.loads(paths.current_path.read_text())
        current["source_revision"] = "f" * 40
        paths.current_path.write_text(json.dumps(current))
    elif mismatch == "acl":
        def denied(*_):
            raise updater_service.WindowsAclError("reserved ACL differs")
        monkeypatch.setattr(updater_service, "assert_state_file_permissions_match", denied)
    elif mismatch == "partial":
        transition = json.loads(paths.transition_path.read_text())
        del transition["artifact_size"]
        paths.transition_path.write_text(json.dumps(transition))
    elif mismatch == "payload":
        (paths.versions_root / "3.2.0" / "pc_agent.exe").write_bytes(b"different")
    else:
        # Model a native reparse attribute on the reserved source boundary;
        # no real Windows symlink privilege is required for the hermetic case.
        original = updater_service._reject_reparse_chain
        def reject(root, path):
            if path == paths.transition_path:
                raise ValueError("state path contains a reparse point")
            original(root, path)
        monkeypatch.setattr(updater_service, "_reject_reparse_chain", reject)
    events = []
    service = SimpleNamespace(stop=lambda: events.append("stop"), start=lambda: events.append("start"), wait_stopped=lambda: True)
    worker = updater_service.WindowsUpdater(paths, acl=_Acl(), service=service,
        confirmation=SimpleNamespace(is_confirmed=lambda **_: False))
    assert worker.run_once().status == "rejected"
    assert events == []
    assert json.loads(paths.current_path.read_text())["version"] == "3.2.0"


@pytest.mark.parametrize("leaf", ["pending", "attempt", "restore", "transition"])
@pytest.mark.parametrize("after", [False, True])
def test_accepted_cleanup_restart_needs_no_archive_attempt_or_repeated_service_action(tmp_path, monkeypatch, leaf, after):
    from pc_agent.platform.windows import updater_service
    paths, _ = _interrupted_transition(tmp_path)
    events = []
    service = SimpleNamespace(stop=lambda: events.append("stop"), start=lambda: events.append("start"), wait_stopped=lambda: True)
    worker = updater_service.WindowsUpdater(paths, acl=_Acl(), service=service,
        confirmation=SimpleNamespace(is_confirmed=lambda **_: True))
    target = {"pending": paths.pending_path, "attempt": paths.updates_root / "startup-attempt.json",
        "restore": paths.restore_path, "transition": paths.transition_path}[leaf]
    original = updater_service.durable_unlink
    def interrupted(path, **kwargs):
        if path == target:
            if after:
                original(path, **kwargs)
            raise OSError("interrupted accepted cleanup")
        original(path, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(updater_service, "durable_unlink", interrupted)
        assert worker.run_once().status == "rejected"
    assert events == []
    artifact = paths.downloads_root / "candidate.zip"
    artifact.unlink()
    restarted = updater_service.WindowsUpdater(paths, acl=_Acl(), service=service)
    result = restarted.run_once()
    # If the journal deletion itself completed before the interruption, cleanup
    # is already finished; otherwise the accepted journal completes idempotently.
    assert result.status == ("rejected" if leaf == "transition" and after else "applied")
    assert events == []
    assert not paths.transition_path.exists()
    assert not paths.pending_path.exists()


@pytest.mark.parametrize("failure", ["acceptance_metadata", "pending_metadata", "attempt_metadata"])
def test_accepted_transition_metadata_failure_retains_acceptance_for_cleanup_retry(tmp_path, monkeypatch, failure):
    import errno
    from pc_agent.platform.windows import durable_state, updater_service
    paths, _ = _interrupted_transition(tmp_path)
    events = []
    worker = updater_service.WindowsUpdater(paths, acl=_Acl(),
        service=SimpleNamespace(stop=lambda: events.append("stop"), start=lambda: events.append("start")),
        confirmation=SimpleNamespace(is_confirmed=lambda **_: True))
    original = durable_state.flush_directory
    def interrupted(path):
        transition = json.loads(paths.transition_path.read_text()) if paths.transition_path.exists() else None
        if transition and transition["status"] == "accepted":
            should_fail = (
                failure == "acceptance_metadata" and path == paths.install_root
                or failure == "pending_metadata" and path == paths.updates_root and not paths.pending_path.exists()
                or failure == "attempt_metadata" and path == paths.updates_root and not (path / "startup-attempt.json").exists()
            )
            if should_fail:
                raise OSError(errno.ENOSPC, "persistent accepted metadata exhaustion")
        original(path)
    with monkeypatch.context() as patch:
        patch.setattr(durable_state, "flush_directory", interrupted)
        assert worker.run_once().status == "rejected"
    assert events == []
    assert json.loads(paths.transition_path.read_text())["status"] == "accepted"
    assert not (paths.updates_root / "terminal-outcome.json").exists()
    (paths.downloads_root / "candidate.zip").unlink()
    restarted = updater_service.WindowsUpdater(paths, acl=_Acl(), service=worker._service)
    assert restarted.run_once().status == "applied"
    assert events == []
    assert not paths.transition_path.exists()


@pytest.mark.parametrize("invalid", ["operation", "attempt", "time"])
def test_interrupted_selection_requires_actual_fresh_operation_proof(tmp_path, invalid):
    from pc_agent.platform.windows import updater_service
    paths, old = _interrupted_transition(tmp_path)
    transition = json.loads(paths.transition_path.read_text())
    proof = {"status": "confirmed", "version": "3.2.0", "operation_id": transition["operation_id"],
        "attempt_id": transition["attempt_id"], "confirmed_at": datetime.now(UTC).isoformat()}
    proof[{"operation": "operation_id", "attempt": "attempt_id", "time": "confirmed_at"}[invalid]] = (
        (datetime.now(UTC) - timedelta(days=1)).isoformat() if invalid == "time" else "unbound"
    )
    (paths.updates_root / "startup-confirmation.json").write_text(json.dumps(proof))
    starts = []
    worker = updater_service.WindowsUpdater(paths, acl=_Acl(),
        service=SimpleNamespace(stop=lambda: None, start=lambda: starts.append(json.loads(paths.current_path.read_text())),
            wait_stopped=lambda: True, crashed_early=lambda: False),
        verifier=SimpleNamespace(verify=lambda *_: True), deadline_seconds=0)
    assert worker.run_once().status == "rolled_back"
    assert starts[0] == old
    assert json.loads(paths.current_path.read_text()) == old
    assert not paths.transition_path.exists()


def test_equal_selected_pending_without_bound_transition_remains_ineligible(tmp_path):
    from pc_agent.platform.windows import updater_service
    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.0"}')
    events = []
    worker = updater_service.WindowsUpdater(paths, acl=_Acl(),
        service=SimpleNamespace(stop=lambda: events.append("stop"), start=lambda: events.append("start")))
    result = worker.run_once()
    assert result.status == "rejected"
    assert "not eligible" in result.message
    assert events == []


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["capacity", "extract"])
async def test_supervisor_retains_live_core_when_real_worker_cannot_allocate(tmp_path, monkeypatch, failure):
    import asyncio
    import errno
    import shutil
    from pc_agent.platform.windows import updater_service
    from pc_agent.platform.windows.update_supervisor import WindowsRecoveryUpdateSupervisor
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.tests.windows.test_windows_online_update_runtime import _Adapter, _Acl as OnlineAcl
    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.1.9"}')
    events = []
    service = SimpleNamespace(stop=lambda: events.append("stop"), start=lambda: events.append("start"),
        wait_stopped=lambda: True, crashed_early=lambda: False)
    worker = updater_service.WindowsUpdater(paths, acl=_Acl(), service=service,
        verifier=SimpleNamespace(verify=lambda *_: True), confirmation=SimpleNamespace(is_confirmed=lambda **_: True))
    online = WindowsOnlineUpdateRuntime(adapter=_Adapter(None), paths=paths, acl=OnlineAcl(), download=None)
    checks = []
    async def check():
        return (await online.run_once()).status
    async def no_report():
        return False
    def trigger():
        checks.append(worker.run_once().status)
    async def sleep(delay):
        assert 0 < delay <= 300
        assert events == []
        assert checks == ["disk_insufficient"]
        raise asyncio.CancelledError
    with monkeypatch.context() as patch:
        if failure == "capacity":
            patch.setattr(shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
        else:
            def full(*_):
                raise OSError(errno.ENOSPC, "private/path")
            patch.setattr(updater_service, "_extract_zip_member", full)
        with pytest.raises(asyncio.CancelledError):
            await WindowsRecoveryUpdateSupervisor(check=check, report=no_report, trigger=trigger, sleep=sleep).run()
    assert json.loads(paths.current_path.read_text()) == {"version":"3.1.9"}
    assert paths.pending_path.exists()
    assert worker.run_once().status == "applied"
    assert events == ["stop", "start"]


def test_updater_reads_a_revision_bound_installed_selector(tmp_path: Path) -> None:
    """A fresh MSI selector must remain eligible for normal offline updates."""
    from pc_agent.platform.windows.updater_service import _load_current

    path = tmp_path / "current.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "source_revision": "a" * 40,
        "version": "3.2.1",
    }), encoding="utf-8")

    assert _load_current(path) == "3.2.1"


def test_release_verifier_uses_fixed_enrolled_state_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The candidate verifier requires the local CA and enrolled durable state."""
    from pc_agent.platform.windows import updater_service
    from pc_agent.platform.windows.updater_service import SubprocessReleaseVerifier

    paths = _paths(tmp_path)
    executable = tmp_path / "candidate" / "pc_agent.exe"
    calls: list[tuple[list[str], str]] = []

    def run(command: list[str], *, cwd: str, **_kwargs):
        calls.append((command, cwd))
        return SimpleNamespace(returncode=0, stdout="3.2.0\n")

    monkeypatch.setattr(updater_service.subprocess, "run", run)

    assert SubprocessReleaseVerifier(paths).verify(executable, "3.2.0")
    assert calls == [
        (
            [str(executable), "--print-version"], str(executable.parent),
        ),
        (
        [
            str(executable), "--verify", "--data-dir", str(paths.updates_root.parent),
            "--install-root", str(paths.install_root),
            "--ca-file", str(paths.updates_root.parent / "endpoint-ca.crt"),
        ],
        str(executable.parent),
        ),
    ]


def test_release_verifier_rejects_a_candidate_with_the_wrong_binary_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pc_agent.platform.windows import updater_service
    from pc_agent.platform.windows.updater_service import SubprocessReleaseVerifier

    paths = _paths(tmp_path)
    executable = tmp_path / "candidate" / "pc_agent.exe"
    monkeypatch.setattr(
        updater_service.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="3.2.99\n"),
    )

    assert not SubprocessReleaseVerifier(paths).verify(executable, "3.2.0")


def test_updater_rejects_a_zip_without_a_complete_attested_manifest(tmp_path: Path) -> None:
    """Transport SHA alone does not bind the runtime version and individual files."""
    from pc_agent.platform.windows.updater_service import (
        PendingUpdateValidator, WindowsUpdater, _load_bundle_manifest,
    )

    paths = _paths(tmp_path)
    artifact = paths.downloads_root / "candidate.zip"
    artifact.parent.mkdir(parents=True)
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("pc_agent.exe", b"candidate")
    _pending(paths, artifact)
    pending = PendingUpdateValidator(paths, _Acl()).load()
    updater = WindowsUpdater(paths, acl=_Acl())
    staging = updater._extract_to_staging(pending)

    with pytest.raises(ValueError, match="bundle manifest"):
        _load_bundle_manifest(staging, pending)


def test_updater_rejects_excessive_member_count_or_expanded_size() -> None:
    """A valid outer hash must not authorize a ZIP bomb against Program Files."""
    from pc_agent.platform.windows.updater_service import (
        MAX_ARCHIVE_MEMBERS, MAX_EXTRACTED_BYTES, _validate_archive_limits,
    )

    with pytest.raises(ValueError, match="member count"):
        _validate_archive_limits([SimpleNamespace(file_size=0)] * (MAX_ARCHIVE_MEMBERS + 1))
    with pytest.raises(ValueError, match="extracted size"):
        _validate_archive_limits([SimpleNamespace(file_size=MAX_EXTRACTED_BYTES + 1)])


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"unexpected": True}, "unknown"),
        ({"service_name": "Spooler"}, "unknown"),
        ({"executable": "C:/Windows/System32/cmd.exe"}, "unknown"),
        ({"sha256": "0" * 64}, "hash"),
        ({"size": 1}, "size"),
    ],
)
def test_pending_validator_rejects_untrusted_fields_and_artifact_integrity(
    tmp_path: Path, change: dict[str, object], message: str
) -> None:
    """A root worker must accept only its fixed request shape and bytes."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip", version="3.2.4")
    _pending(paths, artifact, **change)

    with pytest.raises(ValueError, match=message):
        PendingUpdateValidator(paths, _Acl()).load()


def test_pending_validator_rejects_artifact_outside_fixed_download_root(tmp_path: Path) -> None:
    """An absolute artifact path is safe only under the service-owned downloads root."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(tmp_path / "outside.zip")
    _pending(paths, artifact)

    with pytest.raises(ValueError, match="artifact"):
        PendingUpdateValidator(paths, _Acl()).load()


def test_pending_validator_rejects_reparse_point_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Path resolution after a reparse point would let an untrusted leaf redirect root."""
    from pc_agent.platform.windows import updater_service
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip", version="3.2.7")
    _pending(paths, artifact)
    original_lstat = Path.lstat

    class _Details:
        st_file_attributes = 0x400
        st_mode = original_lstat(paths.downloads_root).st_mode

    def reparse_lstat(path: Path):
        if path == paths.downloads_root:
            return _Details()
        return original_lstat(path)

    monkeypatch.setattr(updater_service.Path, "lstat", reparse_lstat)
    with pytest.raises(ValueError, match="reparse"):
        PendingUpdateValidator(paths, _Acl()).load()


def test_pending_validator_delegates_owner_and_acl_check(tmp_path: Path) -> None:
    """Filesystem shape alone cannot establish Windows ownership or DACL integrity."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)

    with pytest.raises(ValueError, match="owner or ACL"):
        PendingUpdateValidator(paths, _Acl(reject=True)).load()


def test_updater_quarantines_an_invalid_pending_handoff_before_exiting(
    tmp_path: Path,
) -> None:
    """A malformed active handoff must not permanently block future polls."""
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    paths = _paths(tmp_path)
    paths.pending_path.parent.mkdir(parents=True)
    paths.pending_path.write_text('{"unexpected":true}', encoding="utf-8")

    result = WindowsUpdater(paths, acl=_Acl()).run_once()

    assert result.status == "rejected"
    assert not paths.pending_path.exists()
    quarantined = list(paths.updates_root.glob("rejected-pending-*.json"))
    assert len(quarantined) == 1
    assert quarantined[0].read_text(encoding="utf-8") == '{"unexpected":true}'


def test_pending_validator_rejects_different_bytes_for_existing_target_version(
    tmp_path: Path,
) -> None:
    """A version directory is immutable; reusing its version label cannot replace bytes."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator, WindowsUpdater

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip", b"candidate")
    existing = paths.versions_root / "3.2.0"
    existing.mkdir(parents=True)
    (existing / ".endpoint-update.json").write_text(
        json.dumps({"sha256": "f" * 64, "size": 99, "version": "3.2.0"}),
        encoding="utf-8",
    )
    _pending(paths, artifact)

    pending = PendingUpdateValidator(paths, _Acl()).load()

    class _Service:
        def stop(self): pass
        def start(self): pass
        def wait_stopped(self): return True
        def crashed_early(self): return False
    class _Verifier:
        def verify(self, _path, _expected_version): return True
    class _Confirmation:
        def is_confirmed(self, **_kwargs): return True

    updater = WindowsUpdater(paths, acl=_Acl(), service=_Service(), verifier=_Verifier(), confirmation=_Confirmation())
    staging = updater._extract_to_staging(pending)
    with pytest.raises(ValueError, match="collision"):
        updater._publish(staging, pending)


def test_publish_reuses_identical_msi_runtime_without_zip_metadata(tmp_path: Path) -> None:
    """A ZIP rollback may select an MSI-owned directory with identical runtime bytes."""
    import shutil

    from pc_agent.platform.windows.updater_service import PendingUpdateValidator, WindowsUpdater

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "rollback.zip")
    _pending(paths, artifact)
    pending = PendingUpdateValidator(paths, _Acl()).load()
    updater = WindowsUpdater(paths, acl=_Acl())
    staging = updater._extract_to_staging(pending)
    target = paths.versions_root / pending.version
    target.mkdir(parents=True)
    shutil.copy2(staging / "pc_agent.exe", target / "pc_agent.exe")
    (target / "_internal").mkdir()
    shutil.copy2(staging / "_internal" / "runtime.dat", target / "_internal" / "runtime.dat")
    target.joinpath(".endpoint-msi-runtime.json").write_text(json.dumps({
        "component_guid": "A7BB0338-5F15-45A2-9B4C-1BF55148FD2B",
        "schema_version": 1,
        "version": pending.version,
    }), encoding="utf-8")

    assert updater._publish(staging, pending) == target
    assert target.joinpath("pc_agent.exe").read_bytes() == b"agent"
    assert not target.joinpath("endpoint-update-manifest.json").exists()
    assert not staging.exists()


@pytest.mark.parametrize("mutation", ["changed", "missing", "extra", "conflicting_manifest", "missing_marker"])
def test_publish_rejects_nonidentical_existing_runtime(tmp_path: Path, mutation: str) -> None:
    """Only transport metadata may differ from a verified ZIP rollback."""
    import shutil

    from pc_agent.platform.windows.updater_service import PendingUpdateValidator, WindowsUpdater

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "rollback.zip")
    _pending(paths, artifact)
    pending = PendingUpdateValidator(paths, _Acl()).load()
    updater = WindowsUpdater(paths, acl=_Acl())
    staging = updater._extract_to_staging(pending)
    target = paths.versions_root / pending.version
    target.mkdir(parents=True)
    shutil.copy2(staging / "pc_agent.exe", target / "pc_agent.exe")
    (target / "_internal").mkdir()
    shutil.copy2(staging / "_internal" / "runtime.dat", target / "_internal" / "runtime.dat")
    if mutation != "missing_marker":
        target.joinpath(".endpoint-msi-runtime.json").write_text(json.dumps({
            "component_guid": "A7BB0338-5F15-45A2-9B4C-1BF55148FD2B",
            "schema_version": 1,
            "version": pending.version,
        }), encoding="utf-8")
    if mutation == "changed":
        target.joinpath("pc_agent.exe").write_bytes(b"other")
    elif mutation == "missing":
        target.joinpath("_internal", "runtime.dat").unlink()
    elif mutation == "extra":
        target.joinpath("unexpected.dat").write_bytes(b"other")
    else:
        target.joinpath("endpoint-update-manifest.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="collision"):
        updater._publish(staging, pending)


@pytest.mark.parametrize("receipt", [None, {"sha256": "f" * 64, "size": 99, "version": "3.2.0"}])
def test_publish_requires_matching_receipt_for_existing_zip_runtime(
    tmp_path: Path, receipt: dict[str, object] | None,
) -> None:
    """An already published ZIP cannot silently inherit another archive identity."""
    import shutil

    from pc_agent.platform.windows.updater_service import PendingUpdateValidator, WindowsUpdater

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    pending = PendingUpdateValidator(paths, _Acl()).load()
    updater = WindowsUpdater(paths, acl=_Acl())
    staging = updater._extract_to_staging(pending)
    target = paths.versions_root / pending.version
    shutil.copytree(staging, target)
    if receipt is not None:
        target.joinpath(".endpoint-update.json").write_text(json.dumps(receipt), encoding="utf-8")

    with pytest.raises(ValueError, match="collision"):
        updater._publish(staging, pending)


def test_updater_records_a_rejected_handoff_for_the_reconnected_agent(
    tmp_path: Path,
) -> None:
    """A privileged failure must become a bounded local terminal outcome, not a stranded rollout."""
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    paths = _paths(tmp_path)
    artifact = paths.downloads_root / "candidate.zip"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"not a ZIP")
    _pending(paths, artifact)
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.1.9"}', encoding="utf-8")

    class _Service:
        def stop(self): pass
        def start(self): pass
        def wait_stopped(self): return True
        def crashed_early(self): return False

    result = WindowsUpdater(paths, acl=_Acl(), service=_Service()).run_once()

    assert result.status == "rejected"
    assert json.loads((paths.updates_root / "terminal-outcome.json").read_text()) == {
        "operation_id": "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e",
        "reported_version": "3.1.9",
        "safe_code": "launcher_apply_failed",
        "status": "failed",
    }


def test_updater_projects_applying_then_failed_without_artifact_detail(
    tmp_path: Path,
) -> None:
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    paths = _paths(tmp_path)
    artifact = paths.downloads_root / "candidate.zip"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"not a ZIP")
    _pending(paths, artifact)
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.1.9"}', encoding="utf-8")
    events: list[tuple[str, str, str, str | None]] = []

    class _Service:
        def stop(self): pass
        def start(self): pass
        def wait_stopped(self): return True
        def crashed_early(self): return False

    class _TrayStatusWriter:
        def publish(self, *, agent_state, endpoint_state, update_state, reason_code=None):
            events.append((agent_state, endpoint_state, update_state, reason_code))

    result = WindowsUpdater(
        paths,
        acl=_Acl(),
        service=_Service(),
        tray_status_writer=_TrayStatusWriter(),
    ).run_once()

    assert result.status == "rejected"
    assert events == [
        ("starting", "unknown", "applying", None),
        ("error", "unknown", "failed", "UPDATE_APPLY"),
    ]


def test_updater_rejects_a_stale_pending_build_after_an_msi_runtime_transition(
    tmp_path: Path,
) -> None:
    """A queued canary cannot downgrade a selector advanced by an MSI repair."""
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip", version="3.2.4")
    _pending(paths, artifact, version="3.2.4")
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.5"}', encoding="utf-8")

    class _Service:
        def stop(self): pass
        def start(self): pass
        def wait_stopped(self): return True
        def crashed_early(self): return False
    class _Verifier:
        def verify(self, _path, _expected_version): return True
    class _Confirmation:
        def is_confirmed(self, **_kwargs): return True

    result = WindowsUpdater(
        paths, acl=_Acl(), service=_Service(), verifier=_Verifier(), confirmation=_Confirmation(),
    ).run_once()

    assert result.status == "rejected"
    assert json.loads((paths.updates_root / "terminal-outcome.json").read_text())["status"] == "failed"
    assert json.loads(paths.current_path.read_text()) == {"version": "3.2.5"}


def test_updater_accepts_an_agent_service_already_stopped_by_the_handoff(
    tmp_path: Path,
) -> None:
    """The updater follows an EXIT_UPDATE_PENDING child without racing SCM's stopped state."""
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip", version="3.2.7")
    _pending(paths, artifact, version="3.2.7")
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.6"}', encoding="utf-8")

    class _InactiveServiceError(OSError):
        winerror = 1062
    class _Service:
        def stop(self): raise _InactiveServiceError()
        def start(self): pass
        def wait_stopped(self): return True
        def crashed_early(self): return False
    class _Verifier:
        def verify(self, _path, _expected_version): return True
    class _Confirmation:
        def is_confirmed(self, **_kwargs): return True

    result = WindowsUpdater(
        paths, acl=_Acl(), service=_Service(), verifier=_Verifier(), confirmation=_Confirmation(),
    ).run_once()

    assert result.status == "applied"
    assert json.loads(paths.current_path.read_text()) == {
        "schema_version": 1,
        "source_revision": "a" * 40,
        "version": "3.2.7",
    }


def test_updater_contract_has_fixed_identity_and_no_network_or_listener_api() -> None:
    """The updater is an offline SCM worker, never an HTTP daemon."""
    from pc_agent.platform.windows import updater_service
    from pc_agent.platform.windows.update_paths import (
        INSTALL_ROOT,
        PENDING_UPDATE_PATH,
        UPDATER_SERVICE_NAME,
    )

    source = Path(updater_service.__file__).read_text(encoding="utf-8").lower()
    assert UPDATER_SERVICE_NAME == "EndpointAgentUpdater"
    assert str(PENDING_UPDATE_PATH) == r"C:\ProgramData\Endpoint Platform\Agent\updates\pending_update.json"
    assert str(INSTALL_ROOT) == r"C:\Program Files\Endpoint Platform\Agent"
    assert "aiohttp" not in source
    assert "socket" not in source


def test_updater_default_adapters_remain_import_safe_off_windows() -> None:
    """MSI can construct the demand-start worker before pywin32 is available on test hosts."""
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    assert isinstance(WindowsUpdater(), WindowsUpdater)


def test_updater_install_contract_is_demand_start_with_fixed_start_acl() -> None:
    """No caller-controlled service name may broaden SCM start authority."""
    from pc_agent.platform.windows import service_control

    spec = service_control.WindowsUpdaterServiceInstallSpec()
    assert spec.name == "EndpointAgentUpdater"
    assert spec.start_type == "demand"
    assert spec.start_principals == ("S-1-5-18", "S-1-5-32-544", "NT SERVICE\\EndpointAgent")
    assert list(inspect.signature(service_control.restrict_updater_start_permissions).parameters) == []


def test_updater_start_acl_keeps_management_rights_without_granting_start_to_others() -> None:
    """Replacing the whole DACL with RP-only ACEs breaks administration and is unnecessary."""
    from pc_agent.platform.windows.service_control import updater_start_access_policy

    policy = updater_start_access_policy(service_all_access=0xFFFF, service_start=0x10)
    assert policy == {
        "S-1-5-18": 0xFFFF,
        "S-1-5-32-544": 0xFFFF,
        "NT SERVICE\\EndpointAgent": 0x10,
    }


def test_update_acl_rejects_inherited_deny_or_wrong_access_mask() -> None:
    """A SID subset check wrongly accepts a weak allow ACE or an overriding deny ACE."""
    from pc_agent.platform.windows.updater_service import _validate_strict_update_dacl

    class _Dacl:
        def __init__(self, aces): self.aces = aces
        def GetAceCount(self): return len(self.aces)
        def GetAce(self, index): return self.aces[index]
    class _Descriptor:
        def __init__(self, aces, control): self.aces, self.control = aces, control
        def GetSecurityDescriptorDacl(self): return _Dacl(self.aces)
        def GetSecurityDescriptorControl(self): return self.control, 1
    class _Security:
        ACCESS_ALLOWED_ACE_TYPE = 0
        SE_DACL_PROTECTED = 0x1000
        INHERITED_ACE = 0x10
        FILE_ALL_ACCESS = 0xFF
        FILE_GENERIC_READ = 0x01
        FILE_GENERIC_WRITE = 0x02
        DELETE = 0x04
        @staticmethod
        def ConvertSidToStringSid(sid): return sid
        @staticmethod
        def LookupAccountName(_server, principal):
            return {"NT SERVICE\\EndpointAgent": "agent", "NT SERVICE\\EndpointAgentUpdater": "updater"}[principal], None, None

    security = _Security()
    bad = _Descriptor([((1, 0), 0xFF, "S-1-5-18")], security.SE_DACL_PROTECTED)
    with pytest.raises(ValueError, match="ACL"):
        _validate_strict_update_dacl(bad, security)
    inherited = _Descriptor([((0, 0x10), 0xFF, "S-1-5-18")], security.SE_DACL_PROTECTED)
    with pytest.raises(ValueError, match="ACL"):
        _validate_strict_update_dacl(inherited, security)


def test_pending_validator_accepts_the_real_orchestrator_received_at_field(tmp_path: Path) -> None:
    """The headless agent producer includes its reception timestamp in Windows requests."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact, received_at=datetime.now(UTC).isoformat())

    assert PendingUpdateValidator(paths, _Acl()).load().version == "3.2.0"


def test_updater_exposes_a_fixed_name_scm_dispatcher_without_importing_pywin32() -> None:
    """The MSI service binary needs an actual EndpointAgentUpdater dispatch entrypoint."""
    from pc_agent.platform.windows import updater_service

    assert updater_service.UPDATER_SERVICE_NAME == "EndpointAgentUpdater"
    assert callable(updater_service.run_windows_updater_service)


def test_startup_proof_writer_binds_the_post_handshake_proof_to_pending_operation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A matching version alone would allow a stale success marker to authorize a release."""
    from pc_agent.platform.windows import startup_confirmation
    from pc_agent.platform.windows.startup_confirmation import StartupProofWriter

    monkeypatch.setattr(startup_confirmation, "AGENT_VERSION", "3.2.0")

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    operation_id = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"
    _pending(paths, artifact, received_at=datetime.now(UTC).isoformat(), operation_id=operation_id)
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text(json.dumps({"version": "3.2.0"}), encoding="utf-8")
    (paths.updates_root / "startup-attempt.json").write_text(json.dumps({
        "attempt_id": "candidate-attempt", "operation_id": operation_id, "version": "3.2.0",
    }), encoding="utf-8")

    assert StartupProofWriter(paths).record_after_server_handshake() is True
    proof = json.loads((paths.updates_root / "startup-confirmation.json").read_text())
    assert proof["operation_id"] == operation_id
    assert proof["attempt_id"] == "candidate-attempt"
    assert proof["version"] == "3.2.0"
    assert proof["status"] == "confirmed"


def test_startup_proof_writer_is_a_noop_on_clean_install(tmp_path: Path) -> None:
    from pc_agent.platform.windows.startup_confirmation import StartupProofWriter

    paths = _paths(tmp_path)
    assert StartupProofWriter(paths).record_after_server_handshake() is False
    assert not (paths.updates_root / "startup-confirmation.json").exists()


def test_startup_proof_writer_rejects_a_selector_that_disagrees_with_its_binary(
    tmp_path: Path,
) -> None:
    """A new selector cannot make an old process attest to a different release."""
    from pc_agent.platform.windows.startup_confirmation import StartupProofWriter

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text(json.dumps({
        "schema_version": 1, "source_revision": "a" * 40, "version": "3.2.0",
    }), encoding="utf-8")
    (paths.updates_root / "startup-attempt.json").write_text(json.dumps({
        "attempt_id": "candidate-attempt", "operation_id": "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e",
        "version": "3.2.0",
    }), encoding="utf-8")

    assert StartupProofWriter(paths).record_after_server_handshake() is False


def test_confirmation_rejects_a_stale_or_wrong_operation_proof(tmp_path: Path) -> None:
    from pc_agent.platform.windows.updater_service import FileStartupConfirmation

    paths = _paths(tmp_path)
    paths.updates_root.mkdir(parents=True)
    (paths.updates_root / "startup-confirmation.json").write_text(json.dumps({
        "status": "confirmed", "version": "3.2.0", "operation_id": "old",
        "confirmed_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
    }), encoding="utf-8")

    assert FileStartupConfirmation(paths).is_confirmed(
        version="3.2.0", operation_id="new", attempt_id="new-attempt", not_before=datetime.now(UTC) - timedelta(seconds=5)
    ) is False


def test_extraction_rejects_an_artifact_replaced_after_validation(tmp_path: Path) -> None:
    """Hashing a pathname then reopening it lets a replacement archive win the race."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator, WindowsUpdater

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    pending = PendingUpdateValidator(paths, _Acl()).load()
    artifact.write_bytes(b"replacement")

    class _Service:
        def stop(self): pass
        def start(self): pass
        def wait_stopped(self): return True
        def crashed_early(self): return False
    class _Verifier:
        def verify(self, _path, _expected_version): return True
    class _Confirmation:
        def is_confirmed(self, **_kwargs): return True

    updater = WindowsUpdater(paths, acl=_Acl(), service=_Service(), verifier=_Verifier(), confirmation=_Confirmation())
    with pytest.raises(ValueError, match="artifact changed"):
        updater._extract_to_staging(pending)


def test_corrupt_zip_removes_the_private_pinned_artifact_copy(tmp_path: Path) -> None:
    """A corrupt archive must not leave a root-owned sibling for a later confused run."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator, WindowsUpdater

    paths = _paths(tmp_path)
    artifact = paths.downloads_root / "candidate.zip"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"not a zip")
    _pending(paths, artifact)
    pending = PendingUpdateValidator(paths, _Acl()).load()
    class _Service:
        def stop(self): pass
        def start(self): pass
        def wait_stopped(self): return True
        def crashed_early(self): return False
    class _Verifier:
        def verify(self, _path, _expected_version): return True
    class _Confirmation:
        def is_confirmed(self, **_kwargs): return True
    updater = WindowsUpdater(paths, acl=_Acl(), service=_Service(), verifier=_Verifier(), confirmation=_Confirmation())
    with pytest.raises(Exception):
        updater._extract_to_staging(pending)
    assert not list((paths.versions_root / "_staging").glob(".artifact-*.zip"))


def test_confirmation_requires_a_new_candidate_attempt_id(tmp_path: Path) -> None:
    """A previous proof for the same rollout must not confirm a restarted candidate."""
    from pc_agent.platform.windows.updater_service import FileStartupConfirmation

    paths = _paths(tmp_path)
    paths.updates_root.mkdir(parents=True)
    (paths.updates_root / "startup-confirmation.json").write_text(json.dumps({
        "attempt_id": "old-attempt", "confirmed_at": datetime.now(UTC).isoformat(),
        "operation_id": "op", "status": "confirmed", "version": "3.2.0",
    }), encoding="utf-8")
    assert FileStartupConfirmation(paths).is_confirmed(
        version="3.2.0", operation_id="op", attempt_id="new-attempt", not_before=datetime.now(UTC) - timedelta(seconds=1)
    ) is False


def test_strict_update_acl_rejects_any_propagation_flag() -> None:
    """Explicit object/container/inherit-only ACE propagation is not a protected file DACL."""
    from pc_agent.platform.windows.updater_service import _validate_strict_update_dacl

    class _Dacl:
        def GetAceCount(self): return 4
        def GetAce(self, index): return ((0, 0x01 if index == 0 else 0), 0xFF if index < 2 else 0x07, ("S-1-5-18", "S-1-5-32-544", "agent", "updater")[index])
    class _Descriptor:
        def GetSecurityDescriptorControl(self): return 0x1000, 1
        def GetSecurityDescriptorDacl(self): return _Dacl()
    class _Security:
        ACCESS_ALLOWED_ACE_TYPE = 0
        SE_DACL_PROTECTED = 0x1000
        INHERITED_ACE = 0x10
        @staticmethod
        def ConvertSidToStringSid(sid): return sid
        @staticmethod
        def LookupAccountName(_server, principal):
            return {"NT SERVICE\\EndpointAgent": "agent", "NT SERVICE\\EndpointAgentUpdater": "updater"}[principal], None, None
    class _Rights:
        FILE_ALL_ACCESS = 0xFF
        FILE_GENERIC_READ = 1
        FILE_GENERIC_WRITE = 2
        DELETE = 4
    with pytest.raises(ValueError, match="ACL"):
        _validate_strict_update_dacl(_Descriptor(), _Security(), _Rights())


def test_strict_update_acl_accepts_explicit_child_inheritance_for_protected_directory() -> None:
    """The protected updates root must keep its four explicit child-inheritable ACEs."""
    from pc_agent.platform.windows.updater_service import _validate_strict_update_dacl

    class _Dacl:
        def GetAceCount(self): return 4
        def GetAce(self, index): return ((0, 0x03), 0xFF if index < 2 else 0x07, ("S-1-5-18", "S-1-5-32-544", "agent", "updater")[index])
    class _Descriptor:
        def GetSecurityDescriptorControl(self): return 0x1000, 1
        def GetSecurityDescriptorDacl(self): return _Dacl()
    class _Security:
        ACCESS_ALLOWED_ACE_TYPE = 0
        SE_DACL_PROTECTED = 0x1000
        INHERITED_ACE = 0x10
        OBJECT_INHERIT_ACE = 0x01
        CONTAINER_INHERIT_ACE = 0x02
        @staticmethod
        def ConvertSidToStringSid(sid): return sid
        @staticmethod
        def LookupAccountName(_server, principal):
            return {"NT SERVICE\\EndpointAgent": "agent", "NT SERVICE\\EndpointAgentUpdater": "updater"}[principal], None, None
    class _Rights:
        FILE_ALL_ACCESS = 0xFF
        FILE_GENERIC_READ = 1
        FILE_GENERIC_WRITE = 2
        DELETE = 4

    _validate_strict_update_dacl(
        _Descriptor(), _Security(), _Rights(), allow_child_inheritance=True,
    )


@pytest.mark.parametrize(
    ("worker_status", "expected_statuses"),
    [
        (
            "applied",
            [
                (2, {}),
                (4, {}),
                (3, {}),
                (1, {}),
            ],
        ),
        (
            "rejected",
            [
                (2, {}),
                (4, {}),
                (1, {"win32ExitCode": 1066, "svcExitCode": 0x20000001}),
            ],
        ),
    ],
)
def test_updater_dispatcher_leaves_single_terminal_status_to_native_pywin32_host(
    monkeypatch: pytest.MonkeyPatch,
    worker_status: str,
    expected_statuses: list[tuple[int, dict[str, int]]],
) -> None:
    """PythonService.service_main must own the sole terminal SCM report."""
    from pc_agent.platform.windows import updater_service

    events: list[tuple[int, dict[str, int]]] = []
    errors: list[str] = []
    hosted: dict[str, type] = {}
    win32service = ModuleType("win32service")
    win32service.SERVICE_STOPPED = 1
    win32service.SERVICE_START_PENDING = 2
    win32service.SERVICE_STOP_PENDING = 3
    win32service.SERVICE_RUNNING = 4
    win32service.ERROR_SERVICE_SPECIFIC_ERROR = 1066

    class _ServiceFrameworkBaseSequence:
        """Exact status sequence used by pywin32 ServiceFramework.SvcRun."""

        def __init__(self, _args) -> None:
            pass

        def ReportServiceStatus(self, status: int, **kwargs: int) -> None:
            events.append((status, kwargs))

        def SvcRun(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            self.SvcDoRun()
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

    win32serviceutil = ModuleType("win32serviceutil")
    win32serviceutil.ServiceFramework = _ServiceFrameworkBaseSequence
    servicemanager = ModuleType("servicemanager")
    servicemanager.Initialize = lambda: None

    def prepare(service_class: type) -> None:
        hosted["service_class"] = service_class

    def dispatch() -> None:
        service = hosted["service_class"](["EndpointAgentUpdater"])
        # Faithful boundary sequence from pywin32 311 PythonService.cpp:
        # native service_main brackets the Python SvcRun call with the initial
        # START_PENDING and exactly one final STOPPED report.
        service.ReportServiceStatus(win32service.SERVICE_START_PENDING)
        try:
            service.SvcRun()
        except Exception as error:
            errors.append(str(error))
            service.ReportServiceStatus(
                win32service.SERVICE_STOPPED,
                win32ExitCode=win32service.ERROR_SERVICE_SPECIFIC_ERROR,
                svcExitCode=0x20000001,
            )
        else:
            service.ReportServiceStatus(win32service.SERVICE_STOPPED)

    servicemanager.PrepareToHostSingle = prepare
    servicemanager.StartServiceCtrlDispatcher = dispatch
    monkeypatch.setitem(sys.modules, "servicemanager", servicemanager)
    monkeypatch.setitem(sys.modules, "win32service", win32service)
    monkeypatch.setitem(sys.modules, "win32serviceutil", win32serviceutil)
    monkeypatch.setattr(
        updater_service,
        "WindowsUpdater",
        lambda: SimpleNamespace(
            run_once=lambda: SimpleNamespace(
                status=worker_status, message="candidate validation failed"
            )
        ),
    )

    assert updater_service.run_windows_updater_service() == 0
    assert events == expected_statuses
    if worker_status == "rejected":
        assert errors == [
            "EndpointAgentUpdater worker failed with status 'rejected': "
            "candidate validation failed"
        ]
    else:
        assert errors == []

@pytest.mark.skipif(__import__('os').name!='nt',reason='native competing proof-process evidence')
def test_candidate_proof_wait_leaves_transaction_available(tmp_path):
    from pc_agent.platform.windows import updater_service,update_transaction
    paths=_paths(tmp_path)
    artifact=_artifact(paths.downloads_root/'candidate.zip');_pending(paths,artifact)
    paths.install_root.mkdir();paths.current_path.write_text('{"version":"3.1.9"}')
    code='''
import sys
from pathlib import Path
from pc_agent.platform.windows import update_transaction as t
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
t._MUTEX_NAME=sys.argv[1]
with t.update_transaction(WindowsUpdatePaths(Path(sys.argv[2]),Path(sys.argv[3])),timeout_ms=0):
    print('proof-owner-entered')
'''
    def confirmed(**_):
        child=subprocess.run([sys.executable,'-c',code,update_transaction._MUTEX_NAME,str(paths.install_root),str(paths.pending_path)],capture_output=True,text=True,timeout=5)
        assert child.returncode==0,child.stderr
        assert child.stdout.strip()=='proof-owner-entered'
        return True
    service=SimpleNamespace(stop=lambda:None,start=lambda:None,wait_stopped=lambda:True,crashed_early=lambda:False)
    worker=updater_service.WindowsUpdater(paths,acl=_Acl(),service=service,verifier=SimpleNamespace(verify=lambda *_:True),confirmation=SimpleNamespace(is_confirmed=confirmed))
    assert worker.run_once().status=='applied'


@pytest.mark.parametrize("phase", ["staging", "staging_error", "proof", "proof_error"])
@pytest.mark.parametrize("newer", [False, True])
def test_superseded_worker_preserves_successful_owner_state(tmp_path, monkeypatch, phase, newer):
    from pc_agent.platform.windows import updater_service as module
    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    paths.install_root.mkdir()
    paths.current_path.write_text('{"version":"3.1.9"}')

    def worker():
        return module.WindowsUpdater(paths, acl=_Acl(), service=SimpleNamespace(
            stop=lambda: None, start=lambda: None, wait_stopped=lambda: True,
            crashed_early=lambda: False), verifier=SimpleNamespace(verify=lambda *_: True),
            confirmation=SimpleNamespace(is_confirmed=lambda **_: True))

    first, second = worker(), worker()
    preserved = {}

    def competing_owner():
        assert second.run_once().status == "applied"
        if newer:
            _pending(paths, artifact, operation_id="7c141250-2bba-455c-a957-c1b14cdd99c0")
            # A later owner's state must be untouched even if not parseable by this worker.
            paths.transition_path.write_text('{"newer":"transition"}')
            (paths.updates_root / "startup-attempt.json").write_text('{"attempt_id":"newer"}')
        for path in (paths.current_path, paths.pending_path, paths.transition_path,
                     paths.updates_root / "startup-attempt.json"):
            preserved[path] = path.read_bytes() if path.exists() else None

    if phase.startswith("staging"):
        extract = first._extract_to_staging
        def interleaved(pending):
            staging = extract(pending)
            competing_owner()
            if phase.endswith("error"):
                raise ValueError("old extraction failed")
            return staging
        monkeypatch.setattr(first, "_extract_to_staging", interleaved)
    else:
        def interleaved(pending):
            competing_owner()
            if phase.endswith("error"):
                raise ValueError("old proof failed")
            return True
        monkeypatch.setattr(first, "_wait_for_candidate_confirmation", interleaved)

    assert first.run_once().status == "rejected"
    assert not (paths.updates_root / "terminal-outcome.json").exists()
    for path, expected in preserved.items():
        assert (path.read_bytes() if path.exists() else None) == expected


@pytest.mark.parametrize("changed", ["selector", "transition", "attempt"])
def test_proof_acceptance_requires_unchanged_authority(tmp_path, monkeypatch, changed):
    from pc_agent.platform.windows import updater_service as module
    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    paths.install_root.mkdir()
    paths.current_path.write_text('{"version":"3.1.9"}')
    service = SimpleNamespace(stop=lambda: None, start=lambda: None,
                              wait_stopped=lambda: True, crashed_early=lambda: False)
    worker = module.WindowsUpdater(paths, acl=_Acl(), service=service,
        verifier=SimpleNamespace(verify=lambda *_: True))
    preserved = {}

    def confirmation(pending):
        with module.update_transaction(paths):
            path = {"selector": paths.current_path, "transition": paths.transition_path,
                    "attempt": paths.updates_root / "startup-attempt.json"}[changed]
            state = json.loads(path.read_text())
            state["source_revision" if changed == "selector" else "attempt_id"] = "b" * (40 if changed == "selector" else 32)
            path.write_text(json.dumps(state))
            for leaf in (paths.current_path, paths.pending_path, paths.transition_path,
                         paths.updates_root / "startup-attempt.json", paths.restore_path):
                preserved[leaf] = leaf.read_bytes()
        return True

    monkeypatch.setattr(worker, "_wait_for_candidate_confirmation", confirmation)
    assert worker.run_once().status == "rejected"
    assert not (paths.updates_root / "terminal-outcome.json").exists()
    assert all(leaf.read_bytes() == expected for leaf, expected in preserved.items())
