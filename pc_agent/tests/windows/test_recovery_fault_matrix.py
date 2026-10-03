"""Fresh-owner source simulations; no installed SCM, WSS or release proof.

Only the initial known-good test installation is seeded. Every pending, attempt,
transition, proof and report under test is produced by its production owner.
Crash is a test-owned process-loss sentinel; it bypasses ordinary error recovery.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from pc_agent import update_adapter
from pc_agent.platform.windows import (
    online_update_runtime, startup_confirmation, updater_service,
)
from pc_agent.platform.windows.update_supervisor import WindowsRecoveryUpdateSupervisor
from pc_agent.tests.windows.test_updater_service import _artifact, _paths

OPERATION = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"
OLD, NEW = "3.1.0", "3.2.0"  # Synthetic bytes never impersonate immutable82/83-87.


class Crash(BaseException):
    """Interrupted owner, not an ordinary handled filesystem error."""


class Acl:
    def assert_update_path(self, path):
        pass

    def protect_update_path(self, path):
        pass


class Response:
    def __init__(self, status, body="", enter=lambda: None, leave=lambda: None):
        self.status, self.body, self.enter, self.leave = status, body, enter, leave

    async def __aenter__(self):
        self.enter()
        return self

    async def __aexit__(self, *_):
        self.leave()

    async def text(self):
        return self.body


class Rig:
    def __init__(self, root, monkeypatch):
        if os.name == "nt":
            # Native state reader uses the production ACL policy. Protect the
            # temporary test root rather than bypassing its security callback.
            import win32security
            descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1)
            win32security.SetNamedSecurityInfo(str(root), win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                None, None, descriptor.GetSecurityDescriptorDacl(), None)
        self.paths = _paths(root)
        self.paths.updates_root.parent.mkdir(parents=True)
        old = self.paths.versions_root / OLD / "pc_agent.exe"
        old.parent.mkdir(parents=True)
        old.write_bytes(b"known-good")
        self.paths.current_path.write_text(json.dumps({"version": OLD}))
        self.artifact = _artifact(root / "source.zip")
        self.payload = self.artifact.read_bytes()
        self.posts, self.events, self.proofs = [], [], []
        self.running = OLD
        self.fault = None
        self.fired = False
        self.failure = Crash
        self.confirm = True
        self.monkeypatch = monkeypatch
        monkeypatch.setattr(startup_confirmation, "AGENT_VERSION", NEW)
        monkeypatch.setattr(startup_confirmation, "PyWin32AclAdapter", Acl)

    def hit(self, point):
        if self.fault == point and not self.fired:
            self.fired = True
            raise self.failure(point)

    def get(self, url, **_):
        # recommendation_for_device exposes only active targets. A successful
        # terminal POST retires this operation; it cannot be assigned again.
        if any(endpoint.endswith("/reports") for endpoint, _ in self.posts):
            return Response(204)
        return Response(200, json.dumps({
            "schema_version": "agent_update_recommendation_v1", "operation_id": OPERATION,
            "build_identifier": "source-test-only", "version": NEW,
            "platform": "windows_amd64", "channel": "stable",
            "artifact_url": "https://endpoint.example.test/source.zip",
            "artifact_name": "source.zip", "archive_type": "zip",
            "sha256": hashlib.sha256(self.payload).hexdigest(), "size": len(self.payload),
            "reason": "scheduled_rollout",
        }))

    def post(self, url, *, json, **_):
        previous = [body for endpoint, body in self.posts if endpoint.endswith("/reports")]
        if url.endswith("/reports") and previous:
            # Match the server's idempotent same-key retry/terminal conflict.
            if json != previous[0]:
                return Response(409)
        def enter():
            if json.get("status") == "scheduled":
                self.hit("before_scheduled_ack")
            if url.endswith("/reports"):
                self.hit("terminal_post")
            self.posts.append((url, dict(json)))

        def leave():
            if json.get("status") == "scheduled":
                self.hit("after_scheduled_ack")

        return Response(200 if url.endswith("/reports") else 204, enter=enter, leave=leave)

    def adapter(self):
        return update_adapter.EndpointUpdateAdapter(
            api_url="https://endpoint.example.test", bearer_token=lambda: "test-only",
            session=self, data_root=self.paths.updates_root.parent, strict_recovery=True,
        )

    def online(self):
        async def download(_, path):
            path.write_bytes(self.payload)
            self.hit("download")
            return hashlib.sha256(self.payload).hexdigest(), len(self.payload)
        return online_update_runtime.WindowsOnlineUpdateRuntime(
            adapter=self.adapter(), paths=self.paths, acl=Acl(), download=download,
        )

    def worker(self):
        rig = self

        class Service:
            def stop(self):
                rig.hit("before_scm")
                rig.events.append(("stop", rig.running))
                rig.running = None

            def wait_stopped(self):
                rig.events.append(("wait_stopped", rig.running))
                return rig.running is None

            def start(self):
                version = json.loads(rig.paths.current_path.read_text())["version"]
                if version == NEW:
                    rig.hit("candidate_start")
                rig.events.append(("start", version))
                rig.running = version
                if version == NEW and rig.confirm:
                    rig.hit("wss_proof")
                    # Same public hook called after authenticated GatewayHello;
                    # this source test does not claim real network authentication.
                    assert startup_confirmation.StartupProofWriter(rig.paths).record_after_server_handshake()
                    rig.proofs.append(json.loads((rig.paths.updates_root / "startup-confirmation.json").read_text()))

            def crashed_early(self):
                return not rig.confirm

        class Verifier:
            def verify(self, executable, expected_version):
                return expected_version == NEW and executable.read_bytes() == b"agent"

        return updater_service.WindowsUpdater(
            self.paths, acl=Acl(), service=Service(), verifier=Verifier(), deadline_seconds=1,
            tray_status_writer=SimpleNamespace(publish=lambda **_: None),
        )

    def state(self):
        def read(path):
            return json.loads(path.read_text()) if path.exists() else None
        return {
            "current": read(self.paths.current_path), "previous": read(self.paths.previous_path),
            "pending": read(self.paths.pending_path), "transition": read(self.paths.transition_path),
            "attempt": read(self.paths.updates_root / "startup-attempt.json"),
            "proof": read(self.paths.updates_root / "startup-confirmation.json"),
            "handoff": self.adapter()._load_update_state(),
            "reports": self.adapter()._load_report_journal(), "running": self.running,
            "scm": list(self.events),
        }

    def assert_safe(self):
        state = self.state()
        current = state["current"]["version"]
        assert current in {OLD, NEW}
        assert (self.paths.versions_root / current / "pc_agent.exe").read_bytes() == (
            b"known-good" if current == OLD else b"agent")
        if state["previous"]:
            assert state["previous"] == {"version": OLD}
        for name in ("pending", "transition", "attempt", "proof"):
            if state[name]:
                assert state[name]["operation_id"] == OPERATION
        if state["proof"]:
            assert state["proof"] in self.proofs
            assert state["proof"]["version"] == NEW
        if state["attempt"] and state["transition"]:
            assert state["attempt"]["attempt_id"] == state["transition"]["attempt_id"]
        if state["transition"] and state["transition"]["status"] == "accepted":
            assert any(p["attempt_id"] == state["transition"]["attempt_id"] for p in self.proofs)
        for report in state["reports"]:
            assert report["operation_id"] == OPERATION
            if report["status"] == "applied":
                assert current == NEW and self.proofs
        statuses = {report["status"] for report in state["reports"]}
        assert not ("applied" in statuses and statuses != {"applied"})
        assert self.running in {None, OLD, NEW}
        return state


POINTS = (
    "download", "artifact_fsync", "handoff_journal", "pending_publication",
    "before_scheduled_ack", "after_scheduled_ack", "before_scm", "after_current_selector",
    "candidate_start", "wss_proof", "terminal_persistence", "terminal_post", "cleanup",
)


@pytest.mark.asyncio
@pytest.mark.parametrize("point", POINTS)
@pytest.mark.parametrize("failure", [Crash, OSError], ids=["interruption", "io_error"])
async def test_fresh_owners_recover_all_thirteen_fault_boundaries(tmp_path, monkeypatch, point, failure):
    rig = Rig(tmp_path, monkeypatch)
    rig.fault = point
    rig.failure = failure
    if point == "terminal_persistence":
        rig.confirm = False
    with monkeypatch.context() as patch:
        original_fsync = os.fsync
        def fsync(fd):
            # Only the opened downloaded artifact, never mutex/journal setup.
            if os.fstat(fd).st_size == len(rig.payload):
                rig.hit("artifact_fsync")
            return original_fsync(fd)
        patch.setattr(os, "fsync", fsync)
        for module, symbol, selected, fault, after in (
            (update_adapter, "write_json_atomic", "endpoint_update_state.json", "handoff_journal", False),
            (online_update_runtime, "write_json_atomic", "pending_update.json", "pending_publication", False),
            (updater_service, "_write_json_atomic", "current.json", "after_current_selector", True),
            (updater_service, "_write_json_atomic", "terminal-outcome.json", "terminal_persistence", False),
            (updater_service, "durable_unlink", "pending_update.json", "cleanup", True),
        ):
            original = getattr(module, symbol)
            def wrapped(path, *args, _original=original, _selected=selected, _fault=fault, _after=after, **kwargs):
                if Path(path).name == _selected and not _after:
                    rig.hit(_fault)
                result = _original(path, *args, **kwargs)
                if Path(path).name == _selected and _after:
                    rig.hit(_fault)
                return result
            patch.setattr(module, symbol, wrapped)
        try:
            await rig.online().run_once()
            rig.worker().run_once()
            await rig.online().report_startup_outcome()
        except (Crash, OSError) as error:
            assert isinstance(error, failure) and str(error) == point
        else:
            assert failure is OSError  # Ordinary errors may be handled by their owner.
    assert rig.fired
    interrupted = rig.assert_safe()
    # Construct new production owners at every retry from actual leftover bytes.
    rig.confirm = True
    for _ in range(3):
        await rig.online().report_startup_outcome()
        result = await rig.online().run_once()
        if result.status in {"pending", "scheduled", "recovery_pending", "verifying"}:
            rig.worker().run_once()
        await rig.online().report_startup_outcome()
        rig.assert_safe()
    final = rig.assert_safe()
    expected = NEW if final["reports"][0]["status"] == "applied" else OLD
    assert final["running"] == final["current"]["version"] == expected
    if failure is Crash:
        assert expected == NEW
    assert not final["pending"] and not final["transition"] and not final["attempt"]
    assert len(final["reports"]) == 1 and final["reports"][0]["delivered_at"]
    assert final["handoff"][0]["scheduled_ack_delivered_at"]
    report_posts = [body for url, body in rig.posts if url.endswith("/reports")]
    assert {body["report_key"] for body in report_posts} == {final["reports"][0]["report_key"]}
    event_count, post_count = len(rig.events), len(rig.posts)
    assert await rig.online().report_startup_outcome() is (expected == NEW)
    assert (await rig.online().run_once()).status == "idle"
    assert len(rig.events) == event_count and len(rig.posts) == post_count
    from pc_agent.platform.windows.update_transaction import active_update_state
    assert active_update_state(rig.paths) is None
    if point == "after_scheduled_ack":
        assert interrupted["handoff"][0]["scheduled_ack_delivered_at"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("point", ["download", "pending_publication"])
async def test_persistent_enospc_keeps_known_good_and_fresh_owner_can_retry(tmp_path, monkeypatch, point):
    rig = Rig(tmp_path, monkeypatch)
    with monkeypatch.context() as patch:
        def full(*_, **__):
            raise OSError(errno.ENOSPC, "source-test-only")
        if point == "pending_publication":
            patch.setattr(online_update_runtime, "write_json_atomic", full)
        else:
            async def no_space(*_, **__):
                full()
            original = rig.online
            def online():
                owner = original()
                owner._download = no_space
                return owner
            patch.setattr(rig, "online", online)
        for _ in range(2):
            assert (await rig.online().run_once()).status == "disk_insufficient"
            state = rig.assert_safe()
            assert state["current"] == {"version": OLD} and state["running"] == OLD
            assert not state["pending"] and not state["proof"] and not state["scm"]
    assert (await rig.online().run_once()).status == "scheduled"
    assert rig.worker().run_once().status == "applied"
    assert await rig.online().report_startup_outcome()
    rig.assert_safe()


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["duplicate", "oversized", "truncated"])
async def test_pending_restart_consumer_rejects_ambiguous_or_unbounded_json(tmp_path, monkeypatch, attack):
    rig = Rig(tmp_path, monkeypatch)
    assert (await rig.online().run_once()).status == "scheduled"
    raw = rig.paths.pending_path.read_text()
    corrupt = {"duplicate": '{"version":"0.0.0",' + raw[1:],
               "oversized": raw + " " * 16385, "truncated": raw[:-1]}[attack]
    rig.paths.pending_path.write_text(corrupt)
    before = len(rig.posts)
    with pytest.raises(ValueError):
        await rig.online().run_once()
    assert len(rig.posts) == before and rig.events == []


def damage(path, attack):
    raw = path.read_text()
    first_key = next(iter(json.loads(raw)))
    if attack == "duplicate":
        path.write_text(json.dumps({first_key: "untrusted"})[:-1] + "," + raw[1:])
    elif attack == "oversized":
        path.write_text(raw + " " * 32769)
    elif attack == "truncated":
        path.write_text(raw[:-1])
    elif attack == "reparse":
        outside = path.with_name(path.name + ".outside")
        path.rename(outside)
        path.symlink_to(outside)
    else:
        raise AssertionError(attack)


async def selected_candidate(rig, monkeypatch):
    assert (await rig.online().run_once()).status == "scheduled"
    original = updater_service._write_json_atomic
    def publish(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == rig.paths.current_path:
            raise Crash("selected candidate")
        return result
    with monkeypatch.context() as patch:
        patch.setattr(updater_service, "_write_json_atomic", publish)
        with pytest.raises(Crash):
            rig.worker().run_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["duplicate", "oversized", "truncated", "reparse"])
@pytest.mark.parametrize("document", ["current", "pending", "attempt"])
async def test_startup_producer_rejects_damaged_authority_before_proof(tmp_path, monkeypatch, attack, document):
    rig = Rig(tmp_path, monkeypatch)
    await selected_candidate(rig, monkeypatch)
    path = {"current": rig.paths.current_path, "pending": rig.paths.pending_path,
            "attempt": rig.paths.updates_root / "startup-attempt.json"}[document]
    damage(path, attack)
    assert not startup_confirmation.StartupProofWriter(rig.paths).record_after_server_handshake()
    assert not (rig.paths.updates_root / "startup-confirmation.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["duplicate", "oversized", "truncated", "reparse"])
async def test_offline_proof_consumer_rejects_damaged_handshake_document(tmp_path, monkeypatch, attack):
    rig = Rig(tmp_path, monkeypatch)
    await selected_candidate(rig, monkeypatch)
    assert startup_confirmation.StartupProofWriter(rig.paths).record_after_server_handshake()
    proof = json.loads((rig.paths.updates_root / "startup-confirmation.json").read_text())
    pending = json.loads(rig.paths.pending_path.read_text())
    damage(rig.paths.updates_root / "startup-confirmation.json", attack)
    from datetime import datetime
    assert not updater_service.FileStartupConfirmation(rig.paths).is_confirmed(
        version=NEW, operation_id=OPERATION, attempt_id=proof["attempt_id"],
        not_before=datetime.fromisoformat(pending["received_at"]),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["duplicate", "oversized", "truncated", "reparse"])
@pytest.mark.parametrize("document", ["current", "proof", "outcome"])
async def test_online_report_consumer_rejects_damaged_terminal_authority(tmp_path, monkeypatch, attack, document):
    rig = Rig(tmp_path, monkeypatch)
    assert (await rig.online().run_once()).status == "scheduled"
    rig.confirm = document != "outcome"
    assert rig.worker().run_once().status == ("rolled_back" if document == "outcome" else "applied")
    path = {"current": rig.paths.current_path,
            "proof": rig.paths.updates_root / "startup-confirmation.json",
            "outcome": rig.paths.updates_root / "terminal-outcome.json"}[document]
    damage(path, attack)
    before = len(rig.posts)
    assert not await rig.online().report_startup_outcome()
    assert len(rig.posts) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("identity", ["operation_id", "attempt_id", "version", "confirmed_at"])
async def test_offline_restart_rejects_substituted_proof_identity(tmp_path, monkeypatch, identity):
    rig = Rig(tmp_path, monkeypatch)
    await selected_candidate(rig, monkeypatch)
    assert startup_confirmation.StartupProofWriter(rig.paths).record_after_server_handshake()
    path = rig.paths.updates_root / "startup-confirmation.json"
    proof = json.loads(path.read_text())
    proof[identity] = "2000-01-01T00:00:00+00:00" if identity == "confirmed_at" else "substituted"
    path.write_text(json.dumps(proof))
    rig.confirm = False
    result = rig.worker().run_once()
    assert result.status == "rolled_back"
    assert json.loads(rig.paths.current_path.read_text())["version"] == OLD
    assert rig.running == OLD


@pytest.mark.asyncio
@pytest.mark.parametrize("document", ["current", "pending", "attempt"])
@pytest.mark.parametrize("attack", ["duplicate", "oversized", "reparse"])
async def test_online_transition_restart_rejects_damaged_identity_before_network(tmp_path, monkeypatch, document, attack):
    rig = Rig(tmp_path, monkeypatch)
    await selected_candidate(rig, monkeypatch)
    path = {"current": rig.paths.current_path, "pending": rig.paths.pending_path,
            "attempt": rig.paths.updates_root / "startup-attempt.json"}[document]
    damage(path, attack)
    before = len(rig.posts)
    with pytest.raises(ValueError):
        await rig.online().run_once()
    assert len(rig.posts) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["duplicate_member", "duplicate_manifest", "payload_identity"])
async def test_bad_candidate_never_changes_running_selector(tmp_path, monkeypatch, attack):
    import io
    import zipfile
    rig = Rig(tmp_path, monkeypatch)
    if attack == "payload_identity":
        # Validly downloaded container with inner payload disagreeing with its
        # own manifest, not a fabricated accepted operation.
        with zipfile.ZipFile(io.BytesIO(rig.payload)) as source:
            entries = {name: source.read(name) for name in source.namelist()}
        entries["pc_agent.exe"] = b"different-executable"
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, content in entries.items():
                archive.writestr(name, content)
    else:
        target = "pc_agent.exe" if attack == "duplicate_member" else "endpoint-update-manifest.json"
        buffer = io.BytesIO(rig.payload)
        with zipfile.ZipFile(buffer, "a") as archive, pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr(target, b"duplicate")
    rig.payload = buffer.getvalue()
    assert (await rig.online().run_once()).status == "scheduled"
    assert rig.worker().run_once().status == "rejected"
    assert await rig.online().report_startup_outcome()
    state = rig.assert_safe()
    assert state["running"] == OLD and state["current"] == {"version": OLD}
    assert not state["scm"] and not state["proof"]
    assert state["reports"][0]["status"] == "failed"


@pytest.mark.parametrize("attack", ["replace", "rewrite"])
def test_strict_state_reader_rechecks_open_file_identity(tmp_path, monkeypatch, protected_update_state_root, attack):
    from contextlib import contextmanager
    from pc_agent.platform.windows.update_transaction import _read_state
    path = tmp_path / "state.json"
    path.write_text('{"state":"old"}')
    real_open = Path.open
    @contextmanager
    def substituted(leaf, *args, **kwargs):
        with real_open(leaf, *args, **kwargs) as stream:
            class Changed:
                def fileno(self):
                    return stream.fileno()
                def read(self, maximum):
                    value = stream.read(maximum)
                    # Atomic path replacement preserves old opened descriptor.
                    replacement = path.with_suffix(".replacement")
                    with real_open(replacement, "w") as destination:
                        destination.write('{"state":"new"}')
                    if attack == "replace":
                        os.replace(replacement, path)
                    else:
                        with real_open(path, "w") as destination:
                            destination.write('{"state":"changed-size"}')
                    return value
            yield Changed()
    monkeypatch.setattr(Path, "open", substituted)
    # Windows may itself prevent replacement of the held descriptor. The
    # rewrite case still exercises the reader's post-read identity/size check.
    with pytest.raises((ValueError, OSError)) as rejected:
        _read_state(path, 4096)
    if isinstance(rejected.value, OSError):
        assert attack == "replace" and os.name == "nt"
        assert rejected.value.winerror == 5
        with real_open(path, "r") as original:
            assert original.read() == '{"state":"old"}'


@pytest.mark.skipif(os.name == "nt", reason="POSIX transaction root policy")
def test_posix_transaction_never_creates_missing_trusted_root(tmp_path):
    from pc_agent.platform.windows.update_transaction import update_transaction
    paths = _paths(tmp_path)
    with pytest.raises(FileNotFoundError):
        with update_transaction(paths):
            pytest.fail("missing trusted root admitted")
    assert not paths.updates_root.parent.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("document", ["current", "attempt", "receipt"])
@pytest.mark.parametrize("attack", ["duplicate", "oversized"])
async def test_offline_restart_never_accepts_ambiguous_recovery_authority(tmp_path, monkeypatch, document, attack):
    rig = Rig(tmp_path, monkeypatch)
    await selected_candidate(rig, monkeypatch)
    assert startup_confirmation.StartupProofWriter(rig.paths).record_after_server_handshake()
    path = {"current": rig.paths.current_path, "attempt": rig.paths.updates_root / "startup-attempt.json",
            "receipt": rig.paths.versions_root / NEW / ".endpoint-update.json"}[document]
    damage(path, attack)
    result = rig.worker().run_once()
    assert result.status == "rejected"
    assert not any(event[0] == "start" for event in rig.events)


@pytest.mark.asyncio
async def test_accepted_cleanup_rejects_oversized_pending_owner(tmp_path, monkeypatch):
    rig = Rig(tmp_path, monkeypatch)
    assert (await rig.online().run_once()).status == "scheduled"
    original = updater_service.durable_unlink
    def interrupted(path, **kwargs):
        if path == rig.paths.pending_path:
            raise Crash("before cleanup")
        return original(path, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(updater_service, "durable_unlink", interrupted)
        with pytest.raises(Crash):
            rig.worker().run_once()
    damage(rig.paths.pending_path, "oversized")
    assert rig.worker().run_once().status == "rejected"
    assert rig.paths.pending_path.exists() and rig.running == NEW


@pytest.mark.asyncio
async def test_supervisor_trigger_failure_leaves_actual_handoff_for_fresh_worker(tmp_path, monkeypatch):
    rig = Rig(tmp_path, monkeypatch)
    sleeps = 0
    async def sleep(_):
        nonlocal sleeps
        sleeps += 1
        if sleeps == 2:
            raise Crash("stop bounded supervisor")
    def unavailable():
        raise OSError("SCM unavailable")
    supervisor = WindowsRecoveryUpdateSupervisor(device_id=OPERATION,
        check=rig.online().run_once, report=rig.online().report_startup_outcome,
        trigger=unavailable, sleep=sleep)
    with pytest.raises(Crash):
        await supervisor.run()
    state = rig.assert_safe()
    assert state["pending"] and state["running"] == OLD and not state["scm"]
    assert rig.worker().run_once().status == "applied"
    assert await rig.online().report_startup_outcome()
    rig.assert_safe()


async def failed_candidate(rig):
    assert (await rig.online().run_once()).status == "scheduled"
    rig.fault, rig.failure = "before_scm", OSError
    assert rig.worker().run_once().status == "rejected"
    assert (rig.paths.updates_root / "startup-attempt.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["duplicate", "oversized", "truncated", "reparse", "foreign"])
async def test_failed_outcome_rejects_invalid_attempt_before_post(tmp_path, monkeypatch, attack):
    rig = Rig(tmp_path, monkeypatch)
    await failed_candidate(rig)
    path = rig.paths.updates_root / "startup-attempt.json"
    if attack == "foreign":
        value = json.loads(path.read_text())
        value["operation_id"] = "11111111-1111-4111-8111-111111111111"
        path.write_text(json.dumps(value))
    else:
        damage(path, attack)
    before = len(rig.posts)
    assert not await rig.online().report_startup_outcome()
    assert len(rig.posts) == before and path.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("leaf", ["startup-attempt.json", "pending_update.json"])
async def test_terminal_cleanup_restarts_after_each_retired_leaf(tmp_path, monkeypatch, leaf):
    rig = Rig(tmp_path, monkeypatch)
    await failed_candidate(rig)
    original = online_update_runtime.durable_unlink
    def interrupted(path, **kwargs):
        result = original(path, **kwargs)
        if path.name == leaf:
            raise Crash("after terminal leaf deletion")
        return result
    with monkeypatch.context() as patch:
        patch.setattr(online_update_runtime, "durable_unlink", interrupted)
        with pytest.raises(Crash):
            await rig.online().report_startup_outcome()
    assert (rig.paths.updates_root / "terminal-outcome.json").exists()
    assert await rig.online().report_startup_outcome()
    from pc_agent.platform.windows.update_transaction import active_update_state
    assert active_update_state(rig.paths) is None
    assert len([url for url, _ in rig.posts if url.endswith("/reports")]) == 1


@pytest.mark.asyncio
async def test_terminal_cleanup_preserves_attempt_changed_during_post(tmp_path, monkeypatch):
    rig = Rig(tmp_path, monkeypatch)
    await failed_candidate(rig)
    path = rig.paths.updates_root / "startup-attempt.json"
    original = rig.post
    def changed(url, **kwargs):
        response = original(url, **kwargs)
        if url.endswith("/reports"):
            def replace_attempt():
                value = json.loads(path.read_text())
                value["attempt_id"] = "f" * 32
                path.write_text(json.dumps(value))
            response.leave = replace_attempt
        return response
    monkeypatch.setattr(rig, "post", changed)
    assert not await rig.online().report_startup_outcome()
    assert json.loads(path.read_text())["attempt_id"] == "f" * 32
    assert rig.paths.pending_path.exists()
    assert (rig.paths.updates_root / "terminal-outcome.json").exists()
