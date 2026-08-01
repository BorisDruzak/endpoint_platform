"""Lifecycle contracts for the neutral headless runtime."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import aiohttp
import pytest

from endpoint_contracts import AgentCommandV1
from pc_agent import endpoint_gateway
from pc_agent.runtime import application as runtime_application
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
from pc_agent.version import EXIT_UPDATE_PENDING


def _settings(tmp_path: Path) -> RuntimeSettings:
    return RuntimeSettings(
        data_root=tmp_path / "data",
        install_root=tmp_path / "install",
        ca_file=tmp_path / "endpoint-ca.crt",
        endpoint_origin="https://endpoint.sosnadmin.local",
        transport_mode="gateway_http_pull",
    )


class _Executor:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    async def start(self) -> None:
        self._events.append("executor.start")

    async def stop(self) -> None:
        self._events.append("executor.stop")

    async def execute(self, _command):
        raise AssertionError("the lifecycle test transport must not deliver commands")


class _Transport:
    def __init__(self, events: list[str], outcome: BaseException | None = None) -> None:
        self._events = events
        self._outcome = outcome

    async def start(self) -> None:
        self._events.append("transport.start")
        if self._outcome is not None:
            raise self._outcome

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
        "transport.start",
        "transport.close",
        "executor.stop",
    ]
    assert application.status.phase is RuntimePhase.STOPPED


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
    assert events.count("transport.start") == 2
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
    assert events.count("transport.start") == 1
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
    """The compatibility transport must execute commands through the neutral executor."""
    settings = _settings(tmp_path)
    settings.data_root.mkdir()
    settings.install_root.mkdir()
    settings.ca_file.write_text("test-only CA fixture", encoding="ascii")
    (settings.data_root / "device-credential").write_text(
        "c" * 43 + "\n", encoding="ascii"
    )
    observed: list[
        tuple[Path, CommandExecutor, str, str, Path, Path]
    ] = []

    async def gateway_runner(
        *,
        ca_file: Path,
        command_executor: CommandExecutor,
        credential: str,
        endpoint_origin: str,
        data_root: Path,
        current_selector: Path,
        poll_updates: bool,
    ) -> None:
        observed.append(
            (
                ca_file,
                command_executor,
                credential,
                endpoint_origin,
                data_root,
                current_selector,
            )
        )

        assert poll_updates is True

    monkeypatch.setattr(endpoint_gateway, "run_gateway_once", gateway_runner)

    assert await run_runtime(settings) == 0
    assert len(observed) == 1
    assert observed[0][0] == settings.ca_file
    assert isinstance(observed[0][1], CommandExecutor)
    assert observed[0][2:] == (
        "c" * 43,
        settings.endpoint_origin,
        settings.data_root,
        settings.install_root / "current.json",
    )


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
    async def report_startup_outcome(self) -> bool:
        return False

    async def run_once(self) -> SimpleNamespace:
        return SimpleNamespace(status="idle")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("first_outcome", "expected_reconnects", "expected_sleeps"),
    [
        ("network", 1, [0.25]),
        ("http_500", 1, [0.25]),
        ("no_command", 0, [5.0]),
    ],
)
async def test_production_http_attempt_continues_through_lifecycle(
    first_outcome: str,
    expected_reconnects: int,
    expected_sleeps: list[float],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The real HTTP seam surfaces both polling and retry outcomes to lifecycle."""
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
        lambda *_args, **_kwargs: _IdleUpdateRuntime(),
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
