"""Lifecycle contracts for the neutral headless runtime."""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import aiohttp
import pytest

from endpoint_contracts import AgentCommandV1, GatewayHelloV1
from pc_agent.enrollment_bootstrap import EnrollmentOutcome
from pc_agent import endpoint_gateway
from pc_agent.runtime import application as runtime_application
from pc_agent.runtime import main as runtime_main
from pc_agent.runtime.application import (
    RuntimeApplication,
    RuntimeDependencies,
    RuntimeSettings,
    run_runtime,
)
from pc_agent.runtime.command_executor import CommandExecutor
from pc_agent.runtime.lifecycle import CredentialRejected, RetryableTransportError
from pc_agent.runtime.status import RuntimePhase
from pc_agent.tests.context.conftest import FakeProbe
from pc_agent.transport.protocol import compatibility_agent_hello
from pc_agent.version import AGENT_VERSION, EXIT_UPDATE_PENDING


def _settings(tmp_path: Path) -> RuntimeSettings:
    return RuntimeSettings(
        data_root=tmp_path / "data",
        install_root=tmp_path / "install",
        ca_file=tmp_path / "endpoint-ca.crt",
        endpoint_origin="https://endpoint.sosnadmin.local",
        transport_mode="gateway_http_pull",
    )


def test_headless_runtime_prints_its_compiled_version_without_runtime_inputs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """RPM assembly must be able to query the frozen core before publishing it."""
    assert runtime_main.main(["--print-version"]) == 0
    assert capsys.readouterr().out.strip() == AGENT_VERSION


def test_headless_runtime_prints_one_canonical_hardware_fingerprint_without_runtime_inputs(
) -> None:
    """The RPM claim controller must query the frozen core before any network work."""
    completed = subprocess.run(
        [sys.executable, "-m", "pc_agent.runtime.main", "--print-hardware-fingerprint"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    assert re.fullmatch(r"sha256:[0-9a-f]{64}\n?", completed.stdout)
    assert completed.stderr == ""


def test_headless_runtime_defines_a_first_boot_enrollment_boundary() -> None:
    """The RPM entrypoint must gate first start before the Gateway runtime."""
    assert hasattr(runtime_main, "_run_runtime_after_first_boot_enrollment")


@pytest.mark.asyncio
async def test_headless_runtime_exchanges_systemd_claim_before_gateway_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No Gateway component may start until the first-boot exchange is accepted."""
    events: list[str] = []
    settings = _settings(tmp_path)
    paths = (Path("/run/config"), Path("/run/ca"), Path("/run/claim"))
    monkeypatch.setenv("ENDPOINT_AGENT_ENROLLMENT_REQUIRED", "1")
    monkeypatch.setattr(runtime_main, "systemd_runtime_paths", lambda: paths)

    async def enroll(**kwargs: object) -> EnrollmentOutcome:
        assert kwargs == {
            "config_path": paths[0],
            "ca_file": paths[1],
            "claim_file": paths[2],
        }
        events.append("enroll")
        return EnrollmentOutcome("already_enrolled", "device-1")

    async def start_gateway(observed: RuntimeSettings) -> int:
        assert observed is settings
        events.append("gateway")
        return 0

    monkeypatch.setattr(runtime_main, "run_linux_enrollment_gate", enroll)
    monkeypatch.setattr(runtime_main, "run_runtime", start_gateway)

    assert await runtime_main._run_runtime_after_first_boot_enrollment(settings) == 0
    assert events == ["enroll", "gateway"]


def test_headless_runtime_rejects_unapproved_staging_origin_before_gateway_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A unit override alone must not redirect a production agent to staging."""
    settings: list[RuntimeSettings] = []
    monkeypatch.setenv("ENDPOINT_AGENT_GATEWAY_READY", "1")
    monkeypatch.setenv("ENDPOINT_AGENT_ORIGIN", "https://endpoint-staging.sosnadmin.local")

    async def forbidden_gateway(observed: RuntimeSettings) -> int:
        settings.append(observed)
        return 0

    monkeypatch.setattr(runtime_main, "run_runtime", forbidden_gateway)

    assert runtime_main.main(["--ca-file", str(tmp_path / "ca.crt")]) == 75
    assert settings == []


def test_headless_runtime_accepts_explicitly_approved_staging_origin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The only staging path is the marker-bound canary origin."""
    settings: list[RuntimeSettings] = []
    monkeypatch.setenv("ENDPOINT_AGENT_GATEWAY_READY", "1")
    monkeypatch.setenv("ENDPOINT_AGENT_ORIGIN", "https://endpoint-staging.sosnadmin.local")
    monkeypatch.setenv("ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT", "staging")
    monkeypatch.setenv("CANARY_ENVIRONMENT", "staging")
    monkeypatch.setenv("CANARY_APPROVED", "true")

    async def gateway(observed: RuntimeSettings) -> int:
        settings.append(observed)
        return 0

    monkeypatch.setattr(runtime_main, "run_runtime", gateway)

    assert runtime_main.main(["--ca-file", str(tmp_path / "ca.crt")]) == 0
    assert [item.endpoint_origin for item in settings] == [
        "https://endpoint-staging.sosnadmin.local"
    ]


class _Executor:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    async def start(self) -> None:
        self._events.append("executor.start")

    async def stop(self) -> None:
        self._events.append("executor.stop")

    async def execute(self, _command):
        raise AssertionError("the lifecycle test transport must not deliver commands")


def _gateway_hello() -> GatewayHelloV1:
    return GatewayHelloV1(
        schema_version="gateway_hello_v1",
        session_id=UUID("00000000-0000-4000-8000-000000000403"),
        heartbeat_interval_seconds=30,
        maximum_message_bytes=1024,
        policy_revision=0,
        effective_capabilities=["context.baseline.collect"],
        server_time=datetime(2026, 8, 1, tzinfo=UTC),
    )


class _Transport:
    def __init__(self, events: list[str], outcome: BaseException | None = None) -> None:
        self._events = events
        self._outcome = outcome

    async def connect(self, _hello) -> GatewayHelloV1:
        self._events.append("transport.connect")
        if self._outcome is not None:
            raise self._outcome
        return _gateway_hello()

    async def receive(self):
        self._events.append("transport.receive")
        raise asyncio.CancelledError()

    async def send_ack(self, _ack) -> None:
        raise AssertionError("the lifecycle test transport must not deliver commands")

    async def send_result(self, _result) -> None:
        raise AssertionError("the lifecycle test transport must not deliver commands")

    async def send_heartbeat(self, _heartbeat) -> None:
        raise AssertionError("the lifecycle test transport must not send heartbeats")

    async def close(self) -> None:
        self._events.append("transport.close")


def _dependencies(
    events: list[str],
    outcomes: list[BaseException | None],
    *,
    sleeps: list[float] | None = None,
) -> RuntimeDependencies:
    def load_credential(_settings: RuntimeSettings) -> str:
        events.append("credential.load")
        return "c" * 43

    def create_executor() -> _Executor:
        events.append("executor.create")
        return _Executor(events)

    def create_transport(
        _settings: RuntimeSettings, _credential: str, _executor: _Executor
    ) -> _Transport:
        events.append("transport.create")
        return _Transport(events, outcomes.pop(0))

    async def sleep(delay: float) -> None:
        if sleeps is not None:
            sleeps.append(delay)

    return RuntimeDependencies(
        load_credential=load_credential,
        create_executor=create_executor,
        create_transport=create_transport,
        sleep=sleep,
        reconnect_delay=0.25,
    )


@pytest.mark.asyncio
async def test_runtime_starts_in_order_and_closes_every_started_component(
    tmp_path: Path,
) -> None:
    """Skipping credential/executor startup or cleanup would leak a partial runtime."""
    events: list[str] = []
    application = RuntimeApplication(
        _settings(tmp_path), _dependencies(events, [None])
    )

    assert await application.run() == 0
    assert events == [
        "credential.load",
        "executor.create",
        "executor.start",
        "transport.create",
        "transport.connect",
        "transport.receive",
        "transport.close",
        "executor.stop",
    ]
    assert application.status.phase is RuntimePhase.STOPPED


@pytest.mark.asyncio
async def test_runtime_cancels_connected_background_tasks_before_transport_cleanup(
    tmp_path: Path,
) -> None:
    """A task tied to one WSS session must not survive its transport cleanup."""
    events: list[str] = []

    class YieldingTransport(_Transport):
        async def receive(self):
            self._events.append("transport.receive")
            await asyncio.sleep(0)
            raise asyncio.CancelledError()

    async def connected_task() -> None:
        events.append("connected_task.start")
        try:
            await asyncio.Event().wait()
        finally:
            events.append("connected_task.cancelled")

    dependencies = RuntimeDependencies(
        load_credential=lambda _settings: "c" * 43,
        create_executor=lambda: _Executor(events),
        create_transport=lambda *_args: YieldingTransport(events),
        create_connected_tasks=lambda _settings, _credential, _transport: [
            connected_task()
        ],
    )
    application = RuntimeApplication(_settings(tmp_path), dependencies)

    assert await application.run() == 0
    assert events.index("connected_task.cancelled") < events.index("transport.close")


@pytest.mark.asyncio
async def test_runtime_returns_controlled_update_exit_after_clean_shutdown(
    tmp_path: Path,
) -> None:
    """An update handoff must retain exit 42 while closing local components."""
    events: list[str] = []
    application = RuntimeApplication(
        _settings(tmp_path),
        _dependencies(events, [SystemExit(EXIT_UPDATE_PENDING)]),
    )

    assert await application.run() == EXIT_UPDATE_PENDING
    assert events[-2:] == ["transport.close", "executor.stop"]
    assert application.status.phase is RuntimePhase.UPDATE_PENDING


@pytest.mark.asyncio
async def test_retryable_transport_failure_reconnects_without_reloading_credential(
    tmp_path: Path,
) -> None:
    """A transient transport outage must reconnect without restarting local state."""
    events: list[str] = []
    sleeps: list[float] = []
    application = RuntimeApplication(
        _settings(tmp_path),
        _dependencies(
            events,
            [RetryableTransportError("gateway unavailable"), None],
            sleeps=sleeps,
        ),
    )

    assert await application.run() == 0
    assert events.count("credential.load") == 1
    assert events.count("executor.start") == 1
    assert events.count("transport.connect") == 2
    assert events.count("transport.close") == 2
    assert sleeps == [0.25]
    assert application.status.reconnect_attempts == 1


@pytest.mark.asyncio
async def test_gateway_credential_rejection_is_terminal_in_process(
    tmp_path: Path,
) -> None:
    """A 401/403 classification must not enter the reconnect branch."""
    events: list[str] = []
    sleeps: list[float] = []
    application = RuntimeApplication(
        _settings(tmp_path),
        _dependencies(
            events,
            [CredentialRejected("credential rejected")],
            sleeps=sleeps,
        ),
    )

    assert await application.run() == 75
    assert events.count("transport.connect") == 1
    assert sleeps == []
    assert application.status.phase is RuntimePhase.CREDENTIAL_REJECTED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "expected_code", "expected_phase"),
    [
        (SystemExit(EXIT_UPDATE_PENDING), EXIT_UPDATE_PENDING, RuntimePhase.UPDATE_PENDING),
        (CredentialRejected("credential rejected"), 75, RuntimePhase.CREDENTIAL_REJECTED),
        (None, 0, RuntimePhase.STOPPED),
    ],
)
async def test_cleanup_failures_preserve_primary_exit_and_phase(
    tmp_path: Path,
    outcome: BaseException | None,
    expected_code: int,
    expected_phase: RuntimePhase,
) -> None:
    """Cleanup is best-effort after the lifecycle has selected its exit contract."""
    events: list[str] = []

    class FailingCleanupExecutor(_Executor):
        async def stop(self) -> None:
            await super().stop()
            raise RuntimeError("executor cleanup failed")

    class FailingCleanupTransport(_Transport):
        async def close(self) -> None:
            await super().close()
            raise RuntimeError("transport cleanup failed")

    dependencies = RuntimeDependencies(
        load_credential=lambda _settings: "c" * 43,
        create_executor=lambda: FailingCleanupExecutor(events),
        create_transport=lambda *_args: FailingCleanupTransport(events, outcome),
    )
    application = RuntimeApplication(_settings(tmp_path), dependencies)

    assert await application.run() == expected_code
    assert application.status.phase is expected_phase
    assert events[-2:] == ["transport.close", "executor.stop"]


@pytest.mark.asyncio
async def test_executor_startup_failure_returns_runtime_error(tmp_path: Path) -> None:
    """A local startup failure must not escape without an actionable exit code."""
    events: list[str] = []
    dependencies = _dependencies(events, [None])

    def broken_executor():
        raise RuntimeError("executor construction failed")

    application = RuntimeApplication(
        _settings(tmp_path),
        RuntimeDependencies(
            load_credential=dependencies.load_credential,
            create_executor=broken_executor,
            create_transport=dependencies.create_transport,
            sleep=dependencies.sleep,
            reconnect_delay=dependencies.reconnect_delay,
        ),
    )

    assert await application.run() == 1
    assert application.status.phase is RuntimePhase.FAILED


def _command(capability: str) -> AgentCommandV1:
    created_at = datetime(2026, 8, 1, 9, 0, tzinfo=UTC)
    return AgentCommandV1.model_construct(
        schema_version="agent_command_v1",
        command_id=UUID("00000000-0000-4000-8000-000000000401"),
        device_id=UUID("00000000-0000-4000-8000-000000000402"),
        capability=capability,
        parameters={},
        requested_by_service="runtime-test",
        idempotency_key="runtime-command-401",
        created_at=created_at,
        deadline_at=created_at + timedelta(minutes=5),
    )


@pytest.mark.asyncio
async def test_command_executor_rejects_unknown_capability_before_collector_invocation(
) -> None:
    """An unknown typed capability must never reach the Device Context executor."""
    calls: list[str] = []

    def forbidden_execution(*_args, **_kwargs):
        calls.append("collector")
        raise AssertionError("unknown capability reached collector execution")

    executor = CommandExecutor(
        probe_factory=object,
        execute_context_command=forbidden_execution,
    )
    await executor.start()

    result = await executor.execute(_command("context.shell.execute"))

    assert result.status == "failed"
    assert result.result_items == []
    assert result.message == "CONTEXT_CAPABILITY_REJECTED"
    assert calls == []


@pytest.mark.asyncio
async def test_command_executor_uses_existing_typed_context_path() -> None:
    """An allowed capability must retain the validated AgentResultV1 path."""
    executor = CommandExecutor(probe_factory=FakeProbe)
    await executor.start()

    result = await executor.execute(_command("context.baseline.collect"))

    assert result.status == "succeeded"
    assert len(result.result_items) == 1
    assert result.result_items[0]["profile"] == "baseline_v1"


@pytest.mark.asyncio
async def test_default_runtime_wires_executor_into_current_http_pull(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Default selection must create the accepted pull adapter with neutral inputs."""
    settings = _settings(tmp_path)
    settings.data_root.mkdir()
    settings.install_root.mkdir()
    settings.ca_file.write_text("test-only CA fixture", encoding="ascii")
    (settings.data_root / "device-credential").write_text(
        "c" * 43 + "\n", encoding="ascii"
    )
    (settings.data_root / "enrollment-identity.json").write_text(
        '{"device_id":"00000000-0000-4000-8000-000000000435",'
        '"schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="utf-8",
    )
    observed: list[dict[str, object]] = []

    class NoWorkPullTransport:
        async def connect(self, _hello) -> GatewayHelloV1:
            return _gateway_hello()

        async def receive(self) -> object:
            raise asyncio.CancelledError()

        async def send_ack(self, _ack) -> None:
            raise AssertionError("no command should be delivered")

        async def send_result(self, _result) -> None:
            raise AssertionError("no command should be delivered")

        async def send_heartbeat(self, _heartbeat) -> None:
            raise AssertionError("no heartbeat should be sent")

        async def close(self) -> None:
            return None

    def create_pull(**kwargs: object) -> NoWorkPullTransport:
        observed.append(kwargs)
        return NoWorkPullTransport()

    monkeypatch.setattr(endpoint_gateway, "create_http_pull_transport", create_pull)

    assert await run_runtime(settings) == 0
    assert len(observed) == 1
    assert observed[0] == {
        "ca_file": settings.ca_file,
        "credential": "c" * 43,
        "endpoint_origin": settings.endpoint_origin,
        "data_root": settings.data_root,
        "current_selector": settings.install_root / "current.json",
        "poll_updates": True,
        "on_update_poll_complete": observed[0]["on_update_poll_complete"],
    }


@pytest.mark.asyncio
async def test_default_lifecycle_hello_uses_exact_stored_enrollment_device_id(
    tmp_path: Path,
) -> None:
    """Catches sending machine_id, UUID zero, or another fallback in the real hello."""
    settings = _settings(tmp_path)
    settings.data_root.mkdir()
    (settings.data_root / "device-credential").write_text("c" * 43, encoding="ascii")
    stored_device_id = UUID("00000000-0000-4000-8000-000000000431")
    (settings.data_root / "enrollment-identity.json").write_text(
        json.dumps(
            {
                "device_id": str(stored_device_id),
                "schema_version": "endpoint_enrollment_identity_v1",
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (settings.data_root / "identity.json").write_text(
        json.dumps(
            {
                "machine_id": "00000000-0000-4000-8000-000000000432",
                "uuid": "00000000-0000-4000-8000-000000000432",
            }
        ),
        encoding="utf-8",
    )
    observed: list[object] = []
    events: list[str] = []

    class CaptureHelloTransport(_Transport):
        async def connect(self, hello) -> GatewayHelloV1:
            observed.append(hello)
            return await super().connect(hello)

    defaults = runtime_application._default_dependencies()
    dependencies = RuntimeDependencies(
        load_credential=defaults.load_credential,
        create_executor=lambda: _Executor(events),
        create_transport=lambda *_args: CaptureHelloTransport(events),
        load_hello=defaults.load_hello,
    )

    assert await RuntimeApplication(settings, dependencies).run() == 0
    expected = compatibility_agent_hello().model_copy(
        update={"device_id": stored_device_id}
    )
    assert observed == [expected]
    assert expected.agent_version == "http-pull"
    assert expected.launcher_version == "http-pull"


@pytest.mark.asyncio
async def test_default_wss_composition_binds_bearer_to_stored_server_device_id(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Catches breaking identity loading before the real default WSS boundary."""
    from pc_agent.transport.websocket import WebSocketGatewayTransport

    stored_device_id = UUID("00000000-0000-4000-8000-000000000436")
    settings = RuntimeSettings(
        data_root=tmp_path / "data",
        install_root=tmp_path / "install",
        ca_file=tmp_path / "endpoint-ca.crt",
        endpoint_origin="https://endpoint.sosnadmin.local",
        transport_mode="gateway_wss",
    )
    settings.data_root.mkdir()
    settings.install_root.mkdir()
    settings.ca_file.write_text("test-only CA fixture", encoding="ascii")
    (settings.data_root / "device-credential").write_text(
        "w" * 43, encoding="ascii"
    )
    (settings.data_root / "enrollment-identity.json").write_text(
        json.dumps(
            {
                "device_id": str(stored_device_id),
                "schema_version": "endpoint_enrollment_identity_v1",
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    observed: list[tuple[WebSocketGatewayTransport, object]] = []

    async def capture_connect(
        transport: WebSocketGatewayTransport, hello: object
    ) -> GatewayHelloV1:
        observed.append((transport, hello))
        raise asyncio.CancelledError()

    monkeypatch.setattr(WebSocketGatewayTransport, "connect", capture_connect)

    assert await RuntimeApplication(settings).run() == 0
    assert len(observed) == 1
    transport, hello = observed[0]
    assert type(transport) is WebSocketGatewayTransport
    assert transport._credential == "w" * 43
    assert hello.device_id == stored_device_id
    assert hello.agent_version == AGENT_VERSION
    assert hello.launcher_version == AGENT_VERSION


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {
            "device_id": "not-a-uuid",
            "schema_version": "endpoint_enrollment_identity_v1",
        },
        {
            "device_id": "00000000-0000-4000-8000-000000000433",
            "schema_version": "unknown_identity_v1",
        },
    ],
)
def test_default_hello_loader_rejects_missing_or_invalid_enrollment_identity(
    tmp_path: Path, payload: dict[str, object] | None
) -> None:
    """Catches silently synthesizing a hello identity when enrollment state is bad."""
    settings = _settings(tmp_path)
    settings.data_root.mkdir()
    if payload is not None:
        (settings.data_root / "enrollment-identity.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
    (settings.data_root / "identity.json").write_text(
        json.dumps(
            {
                "machine_id": "00000000-0000-4000-8000-000000000434",
                "uuid": "00000000-0000-4000-8000-000000000434",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="enrollment identity"):
        runtime_application._default_dependencies().load_hello(settings)


class _AttemptResponse:
    def __init__(self, status: int) -> None:
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise aiohttp.ClientResponseError(
                request_info=SimpleNamespace(real_url="https://endpoint.invalid"),
                history=(),
                status=self.status,
                message="synthetic response",
            )


class _AttemptSession:
    def __init__(
        self,
        *,
        status: int | None = None,
        failure: BaseException | None = None,
    ) -> None:
        self._status = status
        self._failure = failure

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    def get(self, *_args: object, **_kwargs: object) -> _AttemptResponse:
        if self._failure is not None:
            raise self._failure
        assert self._status is not None
        return _AttemptResponse(self._status)


class _IdleUpdateRuntime:
    def __init__(self) -> None:
        self.calls = 0

    async def report_startup_outcome(self) -> bool:
        return False

    async def run_once(self) -> SimpleNamespace:
        self.calls += 1
        return SimpleNamespace(status="idle")


class _RetryableUpdateRuntime(_IdleUpdateRuntime):
    async def run_once(self) -> SimpleNamespace:
        self.calls += 1
        if self.calls == 1:
            raise aiohttp.ClientConnectionError("update poll offline")
        return SimpleNamespace(status="idle")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "first_outcome",
        "expected_reconnects",
        "expected_sleeps",
        "expected_update_polls",
    ),
    [
        ("network", 1, [0.25], 1),
        ("http_500", 1, [0.25], 1),
        ("no_command", 0, [5.0], 1),
        ("update_network", 1, [0.25], 2),
    ],
)
async def test_production_http_attempt_preserves_update_poll_deadline_through_lifecycle(
    first_outcome: str,
    expected_reconnects: int,
    expected_sleeps: list[float],
    expected_update_polls: int,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Only a failed update poll may repeat before its 300-second deadline."""
    settings = _settings(tmp_path)
    settings.data_root.mkdir()
    settings.install_root.mkdir()
    settings.ca_file.write_text("test-only CA fixture", encoding="ascii")
    (settings.data_root / "device-credential").write_text(
        "c" * 43 + "\n", encoding="ascii"
    )
    if first_outcome == "network":
        first = _AttemptSession(failure=aiohttp.ClientConnectionError("offline"))
    elif first_outcome == "http_500":
        first = _AttemptSession(status=500)
    else:
        first = _AttemptSession(status=204)
    sessions = [first, _AttemptSession(status=403)]
    sleeps: list[float] = []
    update_runtime = (
        _RetryableUpdateRuntime()
        if first_outcome == "update_network"
        else _IdleUpdateRuntime()
    )

    monkeypatch.setattr(
        endpoint_gateway.ssl, "create_default_context", lambda **_kwargs: object()
    )
    monkeypatch.setattr(
        endpoint_gateway.aiohttp, "TCPConnector", lambda **_kwargs: object()
    )
    monkeypatch.setattr(
        endpoint_gateway.aiohttp,
        "ClientSession",
        lambda **_kwargs: sessions.pop(0),
    )
    monkeypatch.setattr(
        endpoint_gateway,
        "_gateway_update_runtime",
        lambda *_args, **_kwargs: update_runtime,
    )

    async def capture_sleep(delay: float) -> None:
        sleeps.append(delay)

    defaults = runtime_application._default_dependencies()
    application = RuntimeApplication(
        settings,
        RuntimeDependencies(
            load_credential=defaults.load_credential,
            create_executor=defaults.create_executor,
            create_transport=defaults.create_transport,
            sleep=capture_sleep,
            reconnect_delay=0.25,
        ),
    )

    assert await application.run() == 75
    assert application.status.phase is RuntimePhase.CREDENTIAL_REJECTED
    assert application.status.reconnect_attempts == expected_reconnects
    assert sleeps == expected_sleeps
    assert update_runtime.calls == expected_update_polls
    assert sessions == []


def test_ws_agent_gateway_compatibility_entrypoint_delegates_to_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The accepted ALT branch must not invoke the old Gateway entrypoint directly."""
    from pc_agent import ws_agent
    from pc_agent.runtime import main as runtime_main

    observed: list[RuntimeSettings] = []

    async def runtime_runner(settings: RuntimeSettings) -> int:
        observed.append(settings)
        return 0

    monkeypatch.setattr(runtime_main, "run_runtime", runtime_runner)
    monkeypatch.setenv("ENDPOINT_AGENT_CA_FILE", str(tmp_path / "endpoint-ca.crt"))

    ws_agent._run_endpoint_gateway()

    assert len(observed) == 1
    assert observed[0].ca_file == tmp_path / "endpoint-ca.crt"
    assert observed[0].endpoint_origin == "https://endpoint.sosnadmin.local"
    assert observed[0].transport_mode == "gateway_http_pull"
