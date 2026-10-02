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


@pytest.mark.skipif(sys.platform != "win32", reason="Windows default composition")
@pytest.mark.asyncio
async def test_windows_checks_updates_before_any_successful_wss(monkeypatch, tmp_path):
    settings = replace(_settings(tmp_path), transport_mode="gateway_wss")
    checks = []
    events = []
    connected = []

    async def check(_settings, _credential):
        checks.append("recommendation")
        return "idle"

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
        load_hello=lambda _: application.compatibility_agent_hello(),
        after_server_handshake=lambda _: connected.append(True),
        create_canary_status_writer=lambda _: None,
        create_tray_status_writer=lambda _: None,
        reconnect_delay=0.01,
    )
    task = asyncio.create_task(RuntimeLifecycle(settings, deps, RuntimeStatus()).run())
    await asyncio.sleep(0.08)
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
    paths.pending_path.write_text('{"version":"3.2.79","operation_id":"operation"}')
    (paths.updates_root / "startup-attempt.json").write_text(json.dumps({
        "version": "3.2.79", "operation_id": "operation", "attempt_id": "fresh",
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
    from pc_agent.version import EXIT_UPDATE_PENDING
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
        return (await online.run_once()).status
    trigger = []
    supervisor = WindowsRecoveryUpdateSupervisor(check=check,
        report=online.report_startup_outcome, trigger=lambda: trigger.append(True))
    events = []
    class Broken:
        async def connect(self, _hello):
            raise GatewayTransportUnavailable()
        async def close(self):
            events.append("close")
    deps = replace(_dependencies(events, []), create_transport=lambda *_: Broken(),
        create_service_tasks=lambda *_: (supervisor.run(),))
    assert await asyncio.wait_for(RuntimeLifecycle(_settings(tmp_path), deps, RuntimeStatus()).run(), 1) == EXIT_UPDATE_PENDING
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
