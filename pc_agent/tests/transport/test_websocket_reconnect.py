from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import aiohttp
import pytest

from endpoint_contracts import AgentHelloV1, GatewayHelloV1
from pc_agent.transport.base import (
    GatewayCredentialRejected,
    GatewayRetryableError,
    GatewayTerminalError,
)


_ORIGIN = "https://endpoint.sosnadmin.local"
_WSS_URL = "wss://endpoint.sosnadmin.local/agent/v1/connect"


def _hello() -> AgentHelloV1:
    return AgentHelloV1(
        schema_version="agent_hello_v1",
        device_id=UUID("00000000-0000-4000-8000-000000000711"),
        agent_instance_id=UUID("00000000-0000-4000-8000-000000000712"),
        agent_version="3.1.76",
        launcher_version="3.1.70",
        platform="linux_amd64",
        boot_id="boot-711",
        capabilities=["context.baseline.collect"],
        last_result_sequence=0,
        last_policy_revision=0,
    )


def _gateway_hello() -> dict[str, object]:
    return {
        "schema_version": "gateway_ws_envelope_v1",
        "sequence": 0,
        "kind": "gateway_hello",
        "payload": {
            "schema_version": "gateway_hello_v1",
            "session_id": "00000000-0000-4000-8000-000000000713",
            "heartbeat_interval_seconds": 30,
            "maximum_message_bytes": 65536,
            "policy_revision": 0,
            "effective_capabilities": ["context.baseline.collect"],
            "server_time": "2026-08-02T05:30:00Z",
        },
    }


class _FailingSession:
    def __init__(self, error: Exception) -> None:
        self.error = error
        self.closed = False

    async def ws_connect(self, *_args, **_kwargs):
        raise self.error

    async def close(self) -> None:
        self.closed = True


class _Socket:
    def __init__(self) -> None:
        self._response = SimpleNamespace(history=(), url=_WSS_URL)
        self.sent: list[dict[str, object]] = []

    async def send_json(self, message: dict[str, object]) -> None:
        self.sent.append(message)

    async def receive(self):
        return SimpleNamespace(
            type=aiohttp.WSMsgType.TEXT,
            data=json.dumps(_gateway_hello()),
        )

    async def close(self) -> None:
        return None


class _SuccessfulSession:
    def __init__(self, socket: _Socket | None = None) -> None:
        self.socket = socket or _Socket()

    async def ws_connect(self, *_args, **_kwargs):
        return self.socket

    async def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_transient_connect_failures_use_bounded_exponential_jitter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Removing retry, exponential growth, jitter, or the cap must fail."""
    from pc_agent.transport import websocket

    sessions = [
        _FailingSession(aiohttp.ClientConnectionError("offline-1")),
        _FailingSession(aiohttp.ClientConnectionError("offline-2")),
        _SuccessfulSession(),
    ]
    created: list[object] = []
    delays: list[float] = []

    def create_session(**_kwargs):
        session = sessions.pop(0)
        created.append(session)
        return session

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr(
        websocket.ssl, "create_default_context", lambda **_kwargs: object()
    )
    monkeypatch.setattr(websocket.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(websocket.aiohttp, "ClientSession", create_session)
    transport = websocket.WebSocketGatewayTransport(
        ca_file=tmp_path / "endpoint-ca.pem",
        credential="r" * 43,
        endpoint_origin=_ORIGIN,
        reconnect_policy=websocket.WebSocketReconnectPolicy(
            maximum_attempts=3,
            base_delay=1.0,
            maximum_delay=1.5,
            jitter_ratio=0.25,
        ),
        sleep=record_sleep,
        random_value=lambda: 1.0,
    )

    hello = await transport.connect(_hello())

    assert str(hello.session_id) == "00000000-0000-4000-8000-000000000713"
    assert delays == [1.25, 1.5]
    assert len(created) == 3
    assert all(session.closed for session in created[:2])


@pytest.mark.asyncio
async def test_unavailable_wss_upgrade_exhausts_budget_as_transport_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Treating a 503 as policy-terminal would prevent safe migration fallback."""
    from pc_agent.transport import websocket

    sessions = [
        _FailingSession(
            aiohttp.WSServerHandshakeError(None, (), status=503)
        )
        for _ in range(3)
    ]
    delays: list[float] = []
    monkeypatch.setattr(
        websocket.ssl, "create_default_context", lambda **_kwargs: object()
    )
    monkeypatch.setattr(websocket.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(
        websocket.aiohttp,
        "ClientSession",
        lambda **_kwargs: sessions.pop(0),
    )
    transport = websocket.WebSocketGatewayTransport(
        ca_file=tmp_path / "endpoint-ca.pem",
        credential="r" * 43,
        endpoint_origin=_ORIGIN,
        reconnect_policy=websocket.WebSocketReconnectPolicy(
            maximum_attempts=3,
            base_delay=1.0,
            maximum_delay=8.0,
            jitter_ratio=0.0,
        ),
        sleep=lambda delay: _record_delay(delays, delay),
    )

    with pytest.raises(websocket.GatewayTransportUnavailable):
        await transport.connect(_hello())

    assert delays == [1.0, 2.0]
    assert sessions == []


async def _record_delay(delays: list[float], delay: float) -> None:
    delays.append(delay)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_authentication_denial_is_terminal_without_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: int,
) -> None:
    from pc_agent.transport import websocket

    sessions = [
        _FailingSession(aiohttp.WSServerHandshakeError(None, (), status=status)),
        _SuccessfulSession(),
    ]
    delays: list[float] = []
    monkeypatch.setattr(
        websocket.ssl, "create_default_context", lambda **_kwargs: object()
    )
    monkeypatch.setattr(websocket.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(
        websocket.aiohttp,
        "ClientSession",
        lambda **_kwargs: sessions.pop(0),
    )
    transport = websocket.WebSocketGatewayTransport(
        ca_file=tmp_path / "endpoint-ca.pem",
        credential="r" * 43,
        endpoint_origin=_ORIGIN,
        sleep=lambda delay: _record_delay(delays, delay),
    )

    with pytest.raises(websocket.GatewayCredentialRejected):
        await transport.connect(_hello())

    assert delays == []
    assert len(sessions) == 1


class _InvalidHelloSocket(_Socket):
    def __init__(self, response: dict[str, object]) -> None:
        super().__init__()
        self._response_body = response

    async def receive(self):
        return SimpleNamespace(
            type=aiohttp.WSMsgType.TEXT,
            data=json.dumps(self._response_body),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        {
            **_gateway_hello(),
            "payload": {**_gateway_hello()["payload"], "unexpected": True},
        },
        {
            "schema_version": "gateway_ws_envelope_v1",
            "sequence": 0,
            "kind": "error",
            "payload": {
                "schema_version": "gateway_error_v1",
                "code": "policy_denied",
                "message": "Gateway message rejected",
                "retryable": False,
            },
        },
    ],
)
async def test_schema_or_policy_denial_is_terminal_without_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    response: dict[str, object],
) -> None:
    from pc_agent.transport import websocket

    sessions = [_SuccessfulSession(_InvalidHelloSocket(response)), _SuccessfulSession()]
    delays: list[float] = []
    monkeypatch.setattr(
        websocket.ssl, "create_default_context", lambda **_kwargs: object()
    )
    monkeypatch.setattr(websocket.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(
        websocket.aiohttp,
        "ClientSession",
        lambda **_kwargs: sessions.pop(0),
    )
    transport = websocket.WebSocketGatewayTransport(
        ca_file=tmp_path / "endpoint-ca.pem",
        credential="r" * 43,
        endpoint_origin=_ORIGIN,
        sleep=lambda delay: _record_delay(delays, delay),
    )

    with pytest.raises(websocket.GatewayTerminalError):
        await transport.connect(_hello())

    assert delays == []
    assert len(sessions) == 1


class _DisconnectAfterHelloSocket(_Socket):
    def __init__(self, failure: object) -> None:
        super().__init__()
        self._failure = failure
        self._receive_count = 0

    async def receive(self):
        self._receive_count += 1
        if self._receive_count == 1:
            return await super().receive()
        if isinstance(self._failure, BaseException):
            raise self._failure
        return self._failure


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected_error"),
    [
        (
            aiohttp.ClientConnectionError("connection dropped"),
            "GatewayTransportUnavailable",
        ),
        (
            SimpleNamespace(type=aiohttp.WSMsgType.CLOSE, data=4401),
            "GatewayCredentialRejected",
        ),
        (
            SimpleNamespace(type=aiohttp.WSMsgType.CLOSE, data=1008),
            "GatewayTerminalError",
        ),
    ],
)
async def test_connected_receive_classifies_network_auth_and_policy_disconnects(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: object,
    expected_error: str,
) -> None:
    from pc_agent.transport import websocket

    session = _SuccessfulSession(_DisconnectAfterHelloSocket(failure))
    monkeypatch.setattr(
        websocket.ssl, "create_default_context", lambda **_kwargs: object()
    )
    monkeypatch.setattr(websocket.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(
        websocket.aiohttp, "ClientSession", lambda **_kwargs: session
    )
    transport = websocket.WebSocketGatewayTransport(
        ca_file=tmp_path / "endpoint-ca.pem",
        credential="r" * 43,
        endpoint_origin=_ORIGIN,
        reconnect_policy=websocket.WebSocketReconnectPolicy(maximum_attempts=1),
    )
    await transport.connect(_hello())

    with pytest.raises(getattr(websocket, expected_error)):
        await transport.receive()


class _RecordingTransport:
    def __init__(self, name: str, events: list[str], error: Exception | None = None):
        self.name = name
        self.events = events
        self.error = error

    async def connect(self, _hello: AgentHelloV1) -> GatewayHelloV1:
        self.events.append(f"{self.name}:connect")
        if self.error is not None:
            raise self.error
        return GatewayHelloV1.model_validate(_gateway_hello()["payload"])

    async def receive(self):
        self.events.append(f"{self.name}:receive")
        return None

    async def send_ack(self, _ack) -> None:
        self.events.append(f"{self.name}:ack")

    async def send_result(self, _result) -> None:
        self.events.append(f"{self.name}:result")

    async def send_heartbeat(self, _heartbeat) -> None:
        self.events.append(f"{self.name}:heartbeat")

    async def close(self) -> None:
        self.events.append(f"{self.name}:close")


@pytest.mark.asyncio
async def test_explicit_same_origin_fallback_activates_only_after_wss_unavailable() -> None:
    """Skipping WSS or catching a broader retry error must fail this selection."""
    from pc_agent.transport import websocket

    events: list[str] = []
    primary = _RecordingTransport(
        "wss", events, websocket.GatewayTransportUnavailable("offline")
    )
    fallback = _RecordingTransport("http", events)
    transport = websocket.MigrationFallbackGatewayTransport(
        primary=primary,
        fallback=fallback,
        enabled=True,
        endpoint_origin=_ORIGIN,
        fallback_origin=_ORIGIN,
    )

    hello = await transport.connect(_hello())
    await transport.send_heartbeat(None)
    await transport.close()

    assert str(hello.session_id) == "00000000-0000-4000-8000-000000000713"
    assert events == [
        "wss:connect",
        "wss:close",
        "http:connect",
        "http:heartbeat",
        "http:close",
    ]


@pytest.mark.asyncio
async def test_local_ca_oserror_is_terminal_and_never_selects_http_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A missing or unreadable local CA is configuration failure, not WSS outage."""
    from pc_agent.transport import websocket

    events: list[str] = []

    def missing_ca(**_kwargs):
        raise FileNotFoundError("missing Endpoint CA")

    monkeypatch.setattr(websocket.ssl, "create_default_context", missing_ca)
    primary = websocket.WebSocketGatewayTransport(
        ca_file=tmp_path / "missing-endpoint-ca.pem",
        credential="r" * 43,
        endpoint_origin=_ORIGIN,
        reconnect_policy=websocket.WebSocketReconnectPolicy(maximum_attempts=1),
    )
    fallback = _RecordingTransport("http", events)
    transport = websocket.MigrationFallbackGatewayTransport(
        primary=primary,
        fallback=fallback,
        enabled=True,
        endpoint_origin=_ORIGIN,
        fallback_origin=_ORIGIN,
    )

    with pytest.raises(GatewayTerminalError, match="FileNotFoundError"):
        await transport.connect(_hello())

    assert events == []


@pytest.mark.asyncio
async def test_explicit_fallback_switches_after_connected_wss_unavailability() -> None:
    from pc_agent.transport import websocket

    events: list[str] = []

    class DroppedPrimary(_RecordingTransport):
        async def receive(self):
            self.events.append("wss:receive")
            raise websocket.GatewayTransportUnavailable("dropped")

    primary = DroppedPrimary("wss", events)
    fallback = _RecordingTransport("http", events)
    transport = websocket.MigrationFallbackGatewayTransport(
        primary=primary,
        fallback=fallback,
        enabled=True,
        endpoint_origin=_ORIGIN,
        fallback_origin=_ORIGIN,
    )
    await transport.connect(_hello())

    assert await transport.receive() is None
    assert events == [
        "wss:connect",
        "wss:receive",
        "wss:close",
        "http:connect",
        "http:receive",
    ]


@pytest.mark.asyncio
async def test_connected_receive_and_heartbeat_share_one_fallback_transition() -> None:
    """Concurrent WSS loss must close/connect once and retain the selected fallback."""
    from pc_agent.runtime.lifecycle import _run_connected
    from pc_agent.transport import websocket

    events: list[str] = []
    both_primary_calls_started = asyncio.Event()
    fallback_heartbeat_sent = asyncio.Event()

    class ConcurrentlyDroppedPrimary(_RecordingTransport):
        failure_calls = 0
        close_calls = 0

        async def _fail_together(self, operation: str):
            self.events.append(f"wss:{operation}")
            self.failure_calls += 1
            if self.failure_calls == 2:
                both_primary_calls_started.set()
            await both_primary_calls_started.wait()
            raise websocket.GatewayTransportUnavailable("connected WSS dropped")

        async def receive(self):
            return await self._fail_together("receive")

        async def send_heartbeat(self, _heartbeat) -> None:
            await self._fail_together("heartbeat")

        async def close(self) -> None:
            self.events.append("wss:close")
            self.close_calls += 1
            await asyncio.sleep(0)

    class ConcurrentFallback(_RecordingTransport):
        connect_calls = 0

        async def connect(self, hello: AgentHelloV1) -> GatewayHelloV1:
            self.connect_calls += 1
            return await super().connect(hello)

        async def receive(self):
            self.events.append("http:receive")
            await fallback_heartbeat_sent.wait()
            raise asyncio.CancelledError()

        async def send_heartbeat(self, _heartbeat) -> None:
            self.events.append("http:heartbeat")
            fallback_heartbeat_sent.set()

    class NoCommandExecutor:
        async def execute(self, _command):
            raise AssertionError("concurrent fallback test must not execute a command")

    heartbeat_sleeps = 0

    async def heartbeat_sleep(_delay: float) -> None:
        nonlocal heartbeat_sleeps
        heartbeat_sleeps += 1
        if heartbeat_sleeps > 1:
            await asyncio.Future()
        await asyncio.sleep(0)

    primary = ConcurrentlyDroppedPrimary("wss", events)
    fallback = ConcurrentFallback("http", events)
    transport = websocket.MigrationFallbackGatewayTransport(
        primary=primary,
        fallback=fallback,
        enabled=True,
        endpoint_origin=_ORIGIN,
        fallback_origin=_ORIGIN,
    )
    gateway_hello = await transport.connect(_hello())

    with pytest.raises(asyncio.CancelledError):
        await _run_connected(
            transport,
            NoCommandExecutor(),
            _hello(),
            gateway_hello,
            heartbeat_sleep,
        )
    await transport.close()

    assert primary.close_calls == 1
    assert fallback.connect_calls == 1
    assert events.count("http:receive") == 1
    assert events.count("http:heartbeat") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "primary_error",
    [
        pytest.param(GatewayCredentialRejected("denied"), id="credential"),
        pytest.param(GatewayTerminalError("schema-or-policy"), id="schema-policy"),
        pytest.param(
            GatewayRetryableError("server-retry"), id="non-availability-retry"
        ),
    ],
)
async def test_fallback_never_activates_after_auth_schema_or_policy_denial(
    primary_error: Exception,
) -> None:
    from pc_agent.transport import websocket

    events: list[str] = []
    transport = websocket.MigrationFallbackGatewayTransport(
        primary=_RecordingTransport("wss", events, primary_error),
        fallback=_RecordingTransport("http", events),
        enabled=True,
        endpoint_origin=_ORIGIN,
        fallback_origin=_ORIGIN,
    )

    with pytest.raises(type(primary_error)):
        await transport.connect(_hello())

    assert events == ["wss:connect"]


def test_fallback_configuration_rejects_a_different_origin() -> None:
    from pc_agent.transport import websocket

    with pytest.raises(ValueError, match="same Endpoint origin"):
        websocket.MigrationFallbackGatewayTransport(
            primary=_RecordingTransport("wss", []),
            fallback=_RecordingTransport("http", []),
            enabled=True,
            endpoint_origin=_ORIGIN,
            fallback_origin="https://other.sosnadmin.local",
        )


def test_runtime_wss_selection_constructs_only_secure_primary_initially(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Default-false fallback must not eagerly construct an HTTP command path."""
    from pc_agent.runtime import application

    settings = application.RuntimeSettings(
        data_root=tmp_path / "data",
        install_root=tmp_path / "install",
        ca_file=tmp_path / "endpoint-ca.pem",
        endpoint_origin=_ORIGIN,
        transport_mode="gateway_wss",
        migration_http_pull_fallback=False,
    )
    events: list[str] = []
    primary = _RecordingTransport("wss", events)
    observed: dict[str, object] = {}

    def create_wss(**kwargs):
        observed.update(kwargs)
        return primary

    def unexpected_http(*_args, **_kwargs):
        raise AssertionError("disabled fallback constructed HTTP pull eagerly")

    monkeypatch.setattr(application, "WebSocketGatewayTransport", create_wss)
    monkeypatch.setattr(application, "_create_http_pull_transport", unexpected_http)

    selected = application._create_transport(
        settings,
        "d" * 43,
        object(),
        state=application._EndpointHttpPullState(),
    )

    assert selected is primary
    assert observed["ca_file"] == settings.ca_file
    assert observed["credential"] == "d" * 43
    assert observed["endpoint_origin"] == _ORIGIN
    assert callable(observed["on_connected"])


@pytest.mark.asyncio
async def test_runtime_wss_success_preserves_updates_on_https(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A WSS control handshake must retain the existing HTTPS update poll."""
    from pc_agent.runtime import application

    settings = application.RuntimeSettings(
        data_root=tmp_path / "data",
        install_root=tmp_path / "install",
        ca_file=tmp_path / "endpoint-ca.pem",
        endpoint_origin=_ORIGIN,
        transport_mode="gateway_wss",
    )
    observed: dict[str, object] = {}
    update_events: list[str] = []

    def create_wss(**kwargs):
        observed.update(kwargs)
        return _RecordingTransport("wss", [])

    class UpdateOnlyTransport(_RecordingTransport):
        async def connect(self, hello: AgentHelloV1) -> GatewayHelloV1:
            update_events.append(f"https:connect:{hello.schema_version}")
            return GatewayHelloV1.model_validate(_gateway_hello()["payload"])

        async def close(self) -> None:
            update_events.append("https:close")

    monkeypatch.setattr(application, "WebSocketGatewayTransport", create_wss)
    monkeypatch.setattr(
        application,
        "_create_http_pull_transport",
        lambda *_args, **_kwargs: UpdateOnlyTransport("https", []),
    )
    application._create_transport(
        settings,
        "d" * 43,
        object(),
        state=application._EndpointHttpPullState(),
    )

    hook = observed["on_connected"]
    await hook(GatewayHelloV1.model_validate(_gateway_hello()["payload"]))

    assert update_events == ["https:connect:agent_hello_v1", "https:close"]


@pytest.mark.asyncio
async def test_runtime_explicit_fallback_uses_same_configured_origin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from pc_agent.runtime import application
    from pc_agent.transport import websocket

    settings = application.RuntimeSettings(
        data_root=tmp_path / "data",
        install_root=tmp_path / "install",
        ca_file=tmp_path / "endpoint-ca.pem",
        endpoint_origin=_ORIGIN,
        transport_mode="gateway_wss",
        migration_http_pull_fallback=True,
    )
    events: list[str] = []
    primary = _RecordingTransport(
        "wss", events, websocket.GatewayTransportUnavailable("offline")
    )
    fallback = _RecordingTransport("http", events)
    observed_http: list[tuple[object, str]] = []

    monkeypatch.setattr(
        application, "WebSocketGatewayTransport", lambda **_kwargs: primary
    )

    def create_http(settings_arg, _credential, *, state):
        observed_http.append((state, settings_arg.endpoint_origin))
        return fallback

    monkeypatch.setattr(application, "_create_http_pull_transport", create_http)
    state = application._EndpointHttpPullState()
    selected = application._create_transport(
        settings,
        "d" * 43,
        object(),
        state=state,
    )

    await selected.connect(_hello())

    assert events == ["wss:connect", "wss:close", "http:connect"]
    assert observed_http == [(state, _ORIGIN)]


def test_runtime_settings_reject_non_boolean_fallback_flag(tmp_path: Path) -> None:
    from pc_agent.runtime.application import RuntimeSettings

    ca_file = tmp_path / "endpoint-ca.pem"
    ca_file.write_text("fixture", encoding="ascii")
    settings = RuntimeSettings(
        data_root=tmp_path / "data",
        install_root=tmp_path / "install",
        ca_file=ca_file,
        endpoint_origin=_ORIGIN,
        transport_mode="gateway_wss",
        migration_http_pull_fallback="true",  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="fallback must be boolean"):
        settings.validate()


def test_migration_fallback_cli_defaults_off_and_supports_explicit_disable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pc_agent.runtime import main

    monkeypatch.delenv("ENDPOINT_AGENT_MIGRATION_HTTP_PULL_FALLBACK", raising=False)
    assert main._parser().parse_args([]).migration_http_pull_fallback is False

    monkeypatch.setenv("ENDPOINT_AGENT_MIGRATION_HTTP_PULL_FALLBACK", "true")
    assert main._parser().parse_args([]).migration_http_pull_fallback is True
    assert (
        main._parser()
        .parse_args(["--no-migration-http-pull-fallback"])
        .migration_http_pull_fallback
        is False
    )
