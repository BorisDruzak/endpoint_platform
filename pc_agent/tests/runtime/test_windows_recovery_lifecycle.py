"""Service-owned Windows recovery must progress without a Gateway hello."""
from __future__ import annotations

import asyncio
import sys
from dataclasses import replace

import pytest

from pc_agent.runtime import application
from pc_agent.runtime.lifecycle import RuntimeLifecycle
from pc_agent.runtime.status import RuntimeStatus
from pc_agent.transport.websocket import GatewayTransportUnavailable
from pc_agent.tests.runtime.test_headless_lifecycle import _Executor, _settings

pytestmark = pytest.mark.usefixtures("protected_update_state_root")


@pytest.fixture(autouse=True)
def enrolled_data_root(tmp_path):
    (tmp_path / "data").mkdir(exist_ok=True)

DEVICE_ID = "00000000-0000-4000-8000-000000000001"


def _skip_initial_sleep(sleep):
    first = True
    async def scheduled_sleep(delay):
        nonlocal first
        if first:
            first = False
            assert 0 <= delay <= 15
            return
        await sleep(delay)
    return scheduled_sleep


@pytest.mark.asyncio
@pytest.mark.parametrize("http_status,status,authenticated", [
    (204, "idle", True), (503, "unavailable", False), (404, "unavailable", False),
])
async def test_composed_https_check_retains_actual_adapter_provenance(tmp_path, monkeypatch, http_status, status, authenticated):
    from pc_agent.tests.test_update_adapter import _Response
    settings = replace(_settings(tmp_path), transport_mode="gateway_wss")
    settings.install_root.mkdir()
    (settings.install_root / "current.json").write_text('{"version":"3.2.1"}')
    class Session:
        def __init__(self, **_):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *_):
            pass
        def get(self, url, *, headers, allow_redirects):
            assert url.endswith("/agent/v1/updates/recommendation?platform=windows_amd64&channel=canary")
            assert headers == {"Authorization": "Bearer fixture-credential"}
            assert allow_redirects is False
            return _Response(http_status, "")
    monkeypatch.setattr(application.ssl, "create_default_context", lambda **_: object())
    monkeypatch.setattr(application.aiohttp, "TCPConnector", lambda **_: object())
    monkeypatch.setattr(application.aiohttp, "ClientSession", Session)
    result = await application._run_windows_update_check(settings, "fixture-credential")
    assert result.status == status
    assert result.authenticated_check is authenticated


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["capacity", "extract"])
async def test_disk_rejected_offline_worker_preserves_connected_root_lifecycle(tmp_path, monkeypatch, failure):
    import errno
    import json
    import shutil
    from types import SimpleNamespace
    from pc_agent.platform.windows import updater_service
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_supervisor import WindowsRecoveryUpdateSupervisor
    from pc_agent.tests.windows.test_updater_service import _paths, _artifact, _pending, _Acl
    from pc_agent.tests.windows.test_windows_online_update_runtime import _Adapter, _Acl as OnlineAcl
    from pc_agent.tests.runtime.test_headless_lifecycle import _dependencies, _Transport
    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.1.9"}')
    service_events, results, events = [], [], []
    connected, checked = asyncio.Event(), asyncio.Event()
    service = SimpleNamespace(stop=lambda: service_events.append("stop"), start=lambda: service_events.append("start"),
        wait_stopped=lambda: True, crashed_early=lambda: False)
    worker = updater_service.WindowsUpdater(paths, acl=_Acl(), service=service,
        verifier=SimpleNamespace(verify=lambda *_: True), confirmation=SimpleNamespace(is_confirmed=lambda **_: True))
    online = WindowsOnlineUpdateRuntime(adapter=_Adapter(None), paths=paths, acl=OnlineAcl(), download=None)
    async def check():
        return await online.run_once()
    async def report():
        return False
    async def sleep(delay):
        assert 0 < delay <= 36
        checked.set()
        await asyncio.Future()
    class Connected(_Transport):
        async def receive(self):
            connected.set()
            await asyncio.Future()
    supervisor = WindowsRecoveryUpdateSupervisor(device_id=DEVICE_ID, check=check, report=report,
        trigger=lambda: results.append(worker.run_once().status), sleep=_skip_initial_sleep(sleep))
    deps = replace(_dependencies(events, []), create_transport=lambda *_: Connected(events),
        create_service_tasks=lambda *_: (supervisor.run(),))
    with monkeypatch.context() as patch:
        if failure == "capacity":
            patch.setattr(shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
        else:
            def full(*_):
                raise OSError(errno.ENOSPC, "private/path")
            patch.setattr(updater_service, "_extract_zip_member", full)
        task = asyncio.create_task(RuntimeLifecycle(_settings(tmp_path), deps, RuntimeStatus()).run())
        try:
            await asyncio.wait_for(asyncio.gather(connected.wait(), checked.wait()), 1)
            assert not task.done()
            assert "executor.stop" not in events
            assert "transport.close" not in events
            assert service_events == []
            assert results == ["disk_insufficient"]
            assert json.loads(paths.current_path.read_text()) == {"version":"3.1.9"}
            assert paths.pending_path.exists()
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    assert worker.run_once().status == "applied"
    assert service_events == ["stop", "start"]


@pytest.mark.asyncio
async def test_root_supervisor_reaches_stopped_interrupted_worker_and_active_poll_is_idempotent(tmp_path):
    import json
    from types import SimpleNamespace
    from pc_agent.platform.windows import updater_service
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_supervisor import WindowsRecoveryUpdateSupervisor
    from pc_agent.tests.windows.test_updater_service import _interrupted_transition, _Acl
    from pc_agent.tests.windows.test_windows_online_update_runtime import _Adapter, _Acl as OnlineAcl
    from pc_agent.tests.runtime.test_headless_lifecycle import _dependencies, _Transport
    paths, old = _interrupted_transition(tmp_path)
    events, starts, launches, statuses, delays = [], [], [], [], []
    connected, recovered = asyncio.Event(), asyncio.Event()
    service = SimpleNamespace(stop=lambda: starts.append("stop"),
        start=lambda: starts.append(json.loads(paths.current_path.read_text())["version"]), wait_stopped=lambda: True,
        crashed_early=lambda: False)
    proofs = []
    def confirmed(**_):
        proofs.append(True)
        return len(proofs) > 1
    worker = updater_service.WindowsUpdater(paths, acl=_Acl(), service=service,
        verifier=SimpleNamespace(verify=lambda *_: True), confirmation=SimpleNamespace(is_confirmed=confirmed))
    adapter = _Adapter(None)
    online = WindowsOnlineUpdateRuntime(adapter=adapter, paths=paths, acl=OnlineAcl(), download=None)
    running = True
    polls = 0
    async def check():
        result = await online.run_once()
        assert result.authenticated_check is False
        statuses.append(result.status)
        return result
    async def report():
        return False
    def trigger():
        nonlocal running
        # Fixed SCM StartService returns already-running1056 during active proof
        # wait. Only a stopped worker creates a new native service invocation.
        if not running:
            launches.append(worker.run_once().status)
            running = True
            recovered.set()
    async def sleep(delay):
        nonlocal running, polls
        assert 24 <= delay <= 36
        delays.append(delay)
        polls += 1
        if polls < 3:
            assert starts == [] and launches == []
            running = False if polls == 2 else True
            await asyncio.sleep(0)
        else:
            await asyncio.Future()
    class Connected(_Transport):
        async def receive(self):
            connected.set()
            await asyncio.Future()
    supervisor = WindowsRecoveryUpdateSupervisor(device_id=DEVICE_ID, check=check, report=report, trigger=trigger, sleep=_skip_initial_sleep(sleep))
    deps = replace(_dependencies(events, []), create_transport=lambda *_: Connected(events),
        create_service_tasks=lambda *_: (supervisor.run(),))
    task = asyncio.create_task(RuntimeLifecycle(_settings(tmp_path), deps, RuntimeStatus()).run())
    try:
        await asyncio.wait_for(asyncio.gather(connected.wait(), recovered.wait()), 2)
        assert not task.done()
        assert statuses == ["recovery_pending"] * 3
        assert launches == ["applied"]
        assert starts == ["stop", old["version"], "stop", "3.2.0"]
        assert adapter.calls == []
        assert "executor.stop" not in events and "transport.close" not in events
        assert not paths.pending_path.exists()
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_upgrade_required_control_message_is_recoverable():
    from pc_agent.runtime.lifecycle import _handle_inbound
    from pc_agent.transport.protocol import GatewayInboundV1
    from pc_agent.transport.base import GatewayProtocolIncompatible
    inbound = GatewayInboundV1.model_validate({
        "schema_version": "gateway_ws_envelope_v1", "sequence": 0, "kind": "error",
        "payload": {"schema_version": "gateway_error_v1", "code": "agent_upgrade_required",
                    "message": "Upgrade required", "retryable": False},
    })
    with pytest.raises(GatewayProtocolIncompatible):
        await _handle_inbound(None, None, inbound)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows startup proof")
@pytest.mark.asyncio
async def test_corrupt_startup_state_cannot_abort_a_successful_wss_handshake(tmp_path):
    settings = _settings(tmp_path)
    settings.install_root.mkdir()
    updates = settings.data_root / "updates"
    updates.mkdir(parents=True)
    (settings.install_root / "current.json").write_text('[]')
    (updates / "pending_update.json").write_text('[]')
    (updates / "startup-attempt.json").write_text('[]')
    await application._startup_proof_hook(settings)
    assert not (updates / "startup-confirmation.json").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows startup proof")
@pytest.mark.asyncio
async def test_startup_proof_write_failure_keeps_control_connected(tmp_path, monkeypatch):
    import json
    from pc_agent.platform.windows.acl import PyWin32AclAdapter
    from pc_agent.version import AGENT_VERSION
    settings = _settings(tmp_path)
    settings.install_root.mkdir()
    updates = settings.data_root / "updates"
    updates.mkdir(parents=True)
    (settings.install_root / "current.json").write_text(json.dumps({"version": AGENT_VERSION}))
    pending = {"version": AGENT_VERSION, "operation_id": "operation"}
    (updates / "pending_update.json").write_text(json.dumps(pending))
    (updates / "startup-attempt.json").write_text(json.dumps({**pending, "attempt_id": "attempt"}))
    original_protect = PyWin32AclAdapter.protect_update_path
    def protect(self, path):
        if path.name.startswith(".startup-confirmation.json"):
            raise PermissionError("test ACL failure")
        return original_protect(self, path)
    monkeypatch.setattr(PyWin32AclAdapter, "protect_update_path", protect)
    await application._startup_proof_hook(settings)
    assert not (updates / "startup-confirmation.json").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows ACL contract")
@pytest.mark.asyncio
@pytest.mark.parametrize("error_mode", ["native", "wrapped"])
async def test_real_startup_proof_acl_failure_keeps_authenticated_lifecycle_connected(tmp_path, monkeypatch, error_mode):
    import json
    import pywintypes
    import win32security
    from pc_agent.platform.windows.acl import PyWin32AclAdapter, WindowsAclError
    from pc_agent.tests.runtime.test_headless_lifecycle import _dependencies
    from pc_agent.version import AGENT_VERSION
    settings = replace(_settings(tmp_path), transport_mode="gateway_wss")
    settings.install_root.mkdir()
    updates = settings.data_root / "updates"
    updates.mkdir(parents=True)
    (settings.install_root / "current.json").write_text(json.dumps({"version": AGENT_VERSION}))
    pending = {"version": AGENT_VERSION, "operation_id": "operation"}
    (updates / "pending_update.json").write_text(json.dumps(pending))
    (updates / "startup-attempt.json").write_text(json.dumps({**pending, "attempt_id": "attempt"}))
    native = pywintypes.error(5, "SetNamedSecurityInfo", "injected native ACL failure")
    def native_failure(*args):
        raise native
    def wrapped_failure(*args):
        raise WindowsAclError("injected wrapped ACL failure") from native
    if error_mode == "native":
        monkeypatch.setattr(win32security, "SetNamedSecurityInfo", native_failure)
    else:
        monkeypatch.setattr(PyWin32AclAdapter, "protect_update_path", wrapped_failure)
    events = []
    deps = replace(_dependencies(events, [None]), after_server_handshake=application._startup_proof_hook)
    assert await RuntimeLifecycle(settings, deps, RuntimeStatus()).run() == 0
    assert events.index("transport.connect") < events.index("transport.receive") < events.index("transport.close")
    assert events[-1] == "executor.stop"
    assert not (updates / "startup-confirmation.json").exists()
    assert not list(updates.glob(".startup-confirmation.json.*.tmp"))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows startup proof hook")
@pytest.mark.asyncio
async def test_startup_proof_hook_does_not_swallow_unexpected_runtime_error(tmp_path, monkeypatch):
    from pc_agent.platform.windows.startup_confirmation import StartupProofWriter
    def fail(self):
        raise RuntimeError("unexpected proof implementation error")
    monkeypatch.setattr(StartupProofWriter, "record_after_server_handshake", fail)
    with pytest.raises(RuntimeError, match="unexpected proof"):
        await application._startup_proof_hook(_settings(tmp_path))

@pytest.mark.skipif(sys.platform != "win32", reason="Windows default composition")
@pytest.mark.asyncio
async def test_windows_checks_updates_before_any_successful_wss(monkeypatch, tmp_path):
    settings = replace(_settings(tmp_path), transport_mode="gateway_wss")
    checks = []
    events = []
    connected = []
    settings.data_root.mkdir(parents=True, exist_ok=True)
    (settings.data_root / "enrollment-identity.json").write_text(
        '{"schema_version":"endpoint_enrollment_identity_v1","device_id":"' + DEVICE_ID + '"}')
    checked = asyncio.Event()
    from pc_agent.platform.windows import update_supervisor
    original = update_supervisor.WindowsRecoveryUpdateSupervisor
    monkeypatch.setattr(update_supervisor, "WindowsRecoveryUpdateSupervisor",
        lambda **kwargs: original(**kwargs, sleep=_skip_initial_sleep(asyncio.sleep)))

    async def check(_settings, _credential):
        checks.append("recommendation")
        checked.set()
        from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateResult
        return WindowsOnlineUpdateResult("idle", authenticated_check=True)

    async def report(*_args):
        return False

    class Unavailable:
        async def connect(self, _hello):
            raise GatewayTransportUnavailable("WSS unavailable")

        async def close(self):
            events.append("closed")

    monkeypatch.setattr(application, "_run_windows_update_check", check)
    monkeypatch.setattr(application, "_run_windows_startup_report", report)
    deps = replace(application._default_dependencies(),
        load_credential=lambda _: "c" * 43,
        create_executor=lambda: _Executor(events),
        create_transport=lambda *_: Unavailable(),
        after_server_handshake=lambda _: connected.append(True),
        create_canary_status_writer=lambda _: None,
        create_tray_status_writer=lambda _: None,
        reconnect_delay=0.01,
    )
    task = asyncio.create_task(RuntimeLifecycle(settings, deps, RuntimeStatus()).run())
    await asyncio.wait_for(checked.wait(), 1)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert not connected
    assert len(checks) >= 1
    assert "executor.stop" in events


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["connecting", "connected", "reconnecting"])
async def test_scheduled_update_wins_over_control_and_awaits_cleanup(mode, tmp_path):
    from pc_agent.runtime.lifecycle import UpdatePending
    from pc_agent.tests.runtime.test_headless_lifecycle import _dependencies, _Transport
    from pc_agent.version import EXIT_UPDATE_PENDING
    entered = asyncio.Event()
    closed = asyncio.Event()
    events = []

    class Control(_Transport):
        async def connect(self, hello):
            if mode == "connecting":
                entered.set()
                await asyncio.Future()
            if mode == "reconnecting":
                raise GatewayTransportUnavailable()
            return await super().connect(hello)

        async def receive(self):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                events.append("receive.cancelled")

        async def close(self):
            await super().close()
            closed.set()

    async def sleep(_delay):
        entered.set()
        await asyncio.Future()

    async def recovery():
        await entered.wait()
        raise UpdatePending()

    deps = replace(_dependencies(events, []),
        create_transport=lambda *_: Control(events), sleep=sleep,
        create_service_tasks=lambda *_: (recovery(),))
    status = RuntimeStatus()
    assert await asyncio.wait_for(RuntimeLifecycle(_settings(tmp_path), deps, status).run(), 1) == EXIT_UPDATE_PENDING
    assert status.phase.value == "update_pending"
    assert closed.is_set()
    assert events[-1] == "executor.stop"
    if mode == "connected":
        assert events.index("receive.cancelled") < events.index("transport.close")


@pytest.mark.asyncio
@pytest.mark.parametrize("http_status", [401, 403])
async def test_recovery_rejects_credential_without_retry(http_status):
    from pc_agent.tests.test_update_adapter import _Response
    from pc_agent.update_adapter import EndpointUpdateAdapter
    from pc_agent.transport.base import GatewayCredentialRejected
    class Session:
        def get(self, *_args, **kwargs):
            assert kwargs["allow_redirects"] is False
            return _Response(http_status, "")
    adapter = EndpointUpdateAdapter(api_url="https://endpoint.example.test",
        bearer_token=lambda: "c" * 43, session=Session(),
        strict_recovery=True)
    with pytest.raises(GatewayCredentialRejected):
        await adapter.fetch_recommendation(platform="windows_amd64", channel="canary")


@pytest.mark.asyncio
async def test_recovery_does_not_treat_tls_failure_as_idle():
    import ssl
    from pc_agent.update_adapter import EndpointUpdateAdapter
    from pc_agent.transport.base import GatewayTerminalError
    class Session:
        def get(self, *_args, **_kwargs):
            raise ssl.SSLError("hostname mismatch")
    adapter = EndpointUpdateAdapter(api_url="https://endpoint.example.test",
        bearer_token=lambda: "c" * 43, session=Session(), strict_recovery=True)
    with pytest.raises(GatewayTerminalError):
        await adapter.fetch_recommendation(platform="windows_amd64", channel="canary")


@pytest.mark.asyncio
async def test_candidate_pending_does_not_restart_updater_before_wss_proof(tmp_path):
    import json
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.updates_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.79"}')
    operation_id = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"
    paths.pending_path.write_text(json.dumps({"version": "3.2.79", "operation_id": operation_id}))
    (paths.updates_root / "startup-attempt.json").write_text(json.dumps({
        "version": "3.2.79", "operation_id": operation_id, "attempt_id": "fresh",
    }))
    runtime = WindowsOnlineUpdateRuntime(adapter=None, paths=paths, acl=None, download=None)
    assert (await runtime.run_once()).status == "verifying"


@pytest.mark.asyncio
async def test_broken_wss_real_stager_fetches_acks_validates_and_hands_off(tmp_path):
    import hashlib
    import json
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    from pc_agent.platform.windows.update_supervisor import WindowsRecoveryUpdateSupervisor
    from pc_agent.tests.windows.test_windows_online_update_runtime import _Adapter, _Acl, _OPERATION_ID
    from pc_agent.tests.runtime.test_headless_lifecycle import _dependencies
    from pc_agent.update_adapter import EndpointRecommendation
    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.current_path.write_text('{"version":"3.2.78"}')
    payload = b"verified recovery artifact"
    item = EndpointRecommendation(operation_id=_OPERATION_ID, version="3.2.79",
        platform="windows_amd64", channel="canary", archive_type="zip",
        artifact_url="https://endpoint.example.test/candidate.zip", artifact_name="candidate.zip",
        sha256=hashlib.sha256(payload).hexdigest(), size=len(payload), reason="scheduled_rollout")
    adapter = _Adapter(item)
    async def download(_item, destination):
        destination.write_bytes(payload)
        return hashlib.sha256(payload).hexdigest(), len(payload)
    online = WindowsOnlineUpdateRuntime(adapter=adapter, paths=paths, acl=_Acl(), download=download)
    async def check():
        return await online.run_once()
    trigger = []
    triggered = asyncio.Event()
    loop = asyncio.get_running_loop()
    def trigger_worker():
        trigger.append(True)
        loop.call_soon_threadsafe(triggered.set)
    supervisor = WindowsRecoveryUpdateSupervisor(device_id=DEVICE_ID, check=check,
        report=online.report_startup_outcome, trigger=trigger_worker, sleep=_skip_initial_sleep(asyncio.sleep))
    events = []
    class Broken:
        async def connect(self, _hello):
            raise GatewayTransportUnavailable()
        async def close(self):
            events.append("close")
    deps = replace(_dependencies(events, []), create_transport=lambda *_: Broken(),
        create_service_tasks=lambda *_: (supervisor.run(),))
    task = asyncio.create_task(RuntimeLifecycle(_settings(tmp_path), deps, RuntimeStatus()).run())
    try:
        await asyncio.wait_for(triggered.wait(), 3)
        assert trigger == [True]
        assert not task.done()
        assert json.loads(paths.current_path.read_text())["version"] == "3.2.78"
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert adapter.calls == [("windows_amd64", "canary"), (_OPERATION_ID, "requested"),
        (_OPERATION_ID, "scheduled:3.2.79:3.2.78")]
    assert json.loads(paths.pending_path.read_text())["sha256"] == item.sha256
    assert trigger == [True]


@pytest.mark.asyncio
async def test_cancelling_stream_removes_temporary_and_never_publishes_artifact(tmp_path):
    from pc_agent.endpoint_gateway import _download_gateway_artifact
    from pc_agent.tests.runtime.test_current_update_characterization import _recommendation
    entered = asyncio.Event()
    class Response:
        status = 200
        content = None
        def raise_for_status(self):
            pass
        async def __aenter__(self):
            self.content = self
            return self
        async def __aexit__(self, *_):
            pass
        async def iter_chunked(self, _size):
            yield b"incomplete"
            entered.set()
            await asyncio.Future()
    class Session:
        def get(self, *_args, **_kwargs):
            return Response()
    destination = tmp_path / "candidate.zip"
    task = asyncio.create_task(_download_gateway_artifact(Session(), _recommendation(),
        destination, credential_source=lambda: "c" * 43))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not destination.exists()
    assert not destination.with_name(".candidate.zip.tmp").exists()


@pytest.mark.asyncio
async def test_protocol_failure_retries_with_same_supervisor_until_control_recovers(tmp_path):
    from pc_agent.transport.base import GatewayProtocolIncompatible
    from pc_agent.tests.runtime.test_headless_lifecycle import _dependencies
    created = []
    cancelled = []
    events = []
    async def supervisor():
        created.append(True)
        try:
            await asyncio.Future()
        finally:
            cancelled.append(True)
    deps = replace(_dependencies(events, [GatewayProtocolIncompatible(), None]),
        create_service_tasks=lambda *_: (supervisor(),), recover_protocol_errors=True)
    status = RuntimeStatus()
    assert await RuntimeLifecycle(_settings(tmp_path), deps, status).run() == 0
    assert status.reconnect_attempts == 1
    assert created == cancelled == [True]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows default composition")
@pytest.mark.asyncio
async def test_canonical_identity_loaded_once_for_root_across_reconnect_and_equal_setup_rerun(tmp_path, monkeypatch):
    from pc_agent.enrollment_identity import serialize_enrollment_identity
    from pc_agent.platform.windows import setup_entry, update_supervisor
    from pc_agent.tests.runtime.test_headless_lifecycle import _dependencies, _Transport
    settings = replace(_settings(tmp_path), transport_mode="gateway_wss")
    settings.data_root.mkdir(parents=True, exist_ok=True)
    identity_path = settings.data_root / "enrollment-identity.json"
    identity_path.write_bytes(serialize_enrollment_identity(DEVICE_ID))
    reads, starts, stopped, attempts = [], [], [], []
    original_read = application.read_enrollment_device_id
    def read(path):
        reads.append(path)
        return original_read(path)
    monkeypatch.setattr(application, "read_enrollment_device_id", read)
    monkeypatch.setattr(setup_entry, "_msi_reconciliation_required", lambda *_: False)
    real_supervisor = update_supervisor.WindowsRecoveryUpdateSupervisor
    class ObservedSupervisor(real_supervisor):
        async def run(self):
            starts.append(self)
            try:
                await super().run()
            finally:
                stopped.append(self)
    async def sleep(_delay):
        await asyncio.sleep(0)
    monkeypatch.setattr(update_supervisor, "WindowsRecoveryUpdateSupervisor",
        lambda **kwargs: ObservedSupervisor(**kwargs, sleep=sleep))
    async def check(*_):
        from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateResult
        return WindowsOnlineUpdateResult("idle", authenticated_check=True)
    async def report(*_):
        return False
    monkeypatch.setattr(application, "_run_windows_update_check", check)
    monkeypatch.setattr(application, "_run_windows_startup_report", report)
    events = []
    class Reconnect(_Transport):
        async def connect(self, hello):
            attempts.append(str(hello.device_id))
            assert not setup_entry._setup_msi_required("3.2.82", "3.2.82",
                installation_valid=True, msi_path=tmp_path / "EndpointAgent.msi")
            # A subsequent read would observe another identity: neither WSS
            # reconnect nor an equal-package Setup decision may reload it.
            identity_path.write_bytes(serialize_enrollment_identity(
                "00000000-0000-4000-8000-000000000002"))
            if len(attempts) < 3:
                raise GatewayTransportUnavailable()
            return await super().connect(hello)
    deps = replace(_dependencies(events, [None]), load_hello=application._load_hello,
        create_transport=lambda *_: Reconnect(events), sleep=sleep,
        create_service_tasks=application._create_service_tasks)
    assert await RuntimeLifecycle(settings, deps, RuntimeStatus()).run() == 0
    assert reads == [identity_path]
    assert attempts == [DEVICE_ID] * 3
    assert len(starts) == 1
    assert stopped == starts
    assert starts[0]._device_id == DEVICE_ID


@pytest.mark.asyncio
async def test_neutral_root_passes_once_loaded_identity_to_one_factory_across_reconnect(tmp_path, monkeypatch):
    from pc_agent.enrollment_identity import serialize_enrollment_identity
    from pc_agent.tests.runtime.test_headless_lifecycle import _dependencies, _Transport
    settings = replace(_settings(tmp_path), transport_mode="gateway_wss")
    settings.data_root.mkdir(parents=True, exist_ok=True)
    identity_path = settings.data_root / "enrollment-identity.json"
    identity_path.write_bytes(serialize_enrollment_identity(DEVICE_ID))
    reads, factory_hellos, connection_hellos, stopped = [], [], [], []
    original_read = application.read_enrollment_device_id
    def read(path):
        reads.append(path)
        return original_read(path)
    monkeypatch.setattr(application, "read_enrollment_device_id", read)
    async def service():
        try:
            await asyncio.Future()
        finally:
            stopped.append(True)
    def service_factory(factory_settings, credential, hello, publish):
        assert factory_settings is settings
        assert callable(publish)
        factory_hellos.append(hello)
        return (service(),)
    events = []
    class Reconnect(_Transport):
        async def connect(self, hello):
            connection_hellos.append(hello)
            identity_path.write_bytes(serialize_enrollment_identity(
                "00000000-0000-4000-8000-000000000002"))
            if len(connection_hellos) < 3:
                raise GatewayTransportUnavailable()
            return await super().connect(hello)
    async def sleep(_delay):
        await asyncio.sleep(0)
    deps = replace(_dependencies(events, [None]), load_hello=application._load_hello,
        create_transport=lambda *_: Reconnect(events), sleep=sleep,
        create_service_tasks=service_factory)
    assert await RuntimeLifecycle(settings, deps, RuntimeStatus()).run() == 0
    assert reads == [identity_path]
    assert len(factory_hellos) == 1
    assert str(factory_hellos[0].device_id) == DEVICE_ID
    assert len(connection_hellos) == 3
    assert all(hello is factory_hellos[0] for hello in connection_hellos)
    assert stopped == [True]


@pytest.mark.asyncio
async def test_artifact_tls_failure_is_terminal_local_repair(tmp_path):
    import ssl
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    from pc_agent.tests.windows.test_windows_online_update_runtime import _Adapter, _Acl, _OPERATION_ID
    from pc_agent.update_adapter import EndpointRecommendation
    from pc_agent.transport.base import GatewayTerminalError
    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.current_path.write_text('{"version":"3.2.78"}')
    item = EndpointRecommendation(operation_id=_OPERATION_ID, version="3.2.79",
        platform="windows_amd64", channel="canary", archive_type="zip",
        artifact_url="https://endpoint.example.test/candidate.zip", artifact_name="candidate.zip",
        sha256="a" * 64, size=1, reason="scheduled_rollout")
    async def download(*_):
        raise ssl.SSLError("certificate mismatch")
    runtime = WindowsOnlineUpdateRuntime(adapter=_Adapter(item), paths=paths,
        acl=_Acl(), download=download)
    with pytest.raises(GatewayTerminalError):
        await runtime.run_once()
    assert not paths.pending_path.exists()
