"""Executable baseline for the accepted ALT Gateway transport."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import ssl
from types import SimpleNamespace
from uuid import UUID

import aiohttp
import pytest
from aiohttp.client_reqrep import ConnectionKey

from endpoint_contracts import AgentCommandV1
from pc_agent import endpoint_gateway
from pc_agent.context_profiles.command_execution import execute_context_agent_command


_COMMAND_ID = UUID("caa31a48-bf2f-4f1c-8b77-d1be77e12b4e")
_DEVICE_ID = UUID("8a45f2dc-9fed-4da5-b1e7-48f95e0e27ee")
_ALT_CAPABILITIES = {
    "context.baseline.collect",
    "context.health.collect",
    "context.network.collect",
    "context.diagnostic.collect",
}


class _Probe:
    """Bounded local inputs sufficient for every accepted context profile."""

    platform_name = "linux"

    def read_text(self, _path: str, _limit: int) -> str:
        return ""

    def run(self, _command: tuple[str, ...], _timeout: float, _limit: int) -> str:
        return ""


def _command(capability: str) -> AgentCommandV1:
    created_at = datetime(2026, 8, 1, tzinfo=UTC)
    return AgentCommandV1(
        schema_version="agent_command_v1",
        command_id=_COMMAND_ID,
        device_id=_DEVICE_ID,
        capability=capability,
        parameters={"reason": "operator requested diagnostics"}
        if capability == "context.diagnostic.collect"
        else {},
        requested_by_service="endpoint-gateway",
        idempotency_key="gateway-baseline-0001",
        created_at=created_at,
        deadline_at=created_at + timedelta(minutes=1),
    )


def test_alt_transport_executes_exactly_the_accepted_context_capabilities() -> None:
    """A dynamic tool capability must not become executable through the Gateway."""
    profiles = {}
    for capability in _ALT_CAPABILITIES:
        result = execute_context_agent_command(_command(capability), probe=_Probe())
        assert result.status == "succeeded"
        profiles[capability] = result.result_items[0]["profile"]

    rejected = execute_context_agent_command(
        SimpleNamespace(
            command_id=_COMMAND_ID,
            device_id=_DEVICE_ID,
            capability="context.shell.execute",
            parameters={},
        ),
        probe=_Probe(),
    )

    assert profiles == {
        "context.baseline.collect": "baseline_v1",
        "context.health.collect": "health_v1",
        "context.network.collect": "network_v1",
        "context.diagnostic.collect": "diagnostic_v1",
    }
    assert rejected.status == "failed"
    assert rejected.message == "CONTEXT_CAPABILITY_REJECTED"


class _GatewayResponse:
    def __init__(self, status: int, *, payload: object | None = None) -> None:
        self.status = status
        self._payload = payload

    async def __aenter__(self) -> _GatewayResponse:
        return self

    async def __aexit__(self, *_args: object) -> bool:
        return False

    async def json(self) -> object:
        if self._payload is None:
            raise AssertionError("credential rejection must not parse a command")
        return self._payload

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise aiohttp.ClientResponseError(None, (), status=self.status)


class _GatewaySession:
    def __init__(self, *, response: _GatewayResponse | None = None, failure: BaseException | None = None) -> None:
        self._response = response
        self._failure = failure
        self.requests: list[tuple[str, dict[str, object]]] = []

    async def __aenter__(self) -> _GatewaySession:
        return self

    async def __aexit__(self, *_args: object) -> bool:
        return False

    def get(self, url: str, **kwargs: object) -> _GatewayResponse:
        self.requests.append((url, kwargs))
        if self._failure is not None:
            raise self._failure
        assert self._response is not None
        return self._response


class _GatewayCommandSession:
    def __init__(self, command: dict[str, object]) -> None:
        self._command = command
        self.requests: list[tuple[str, dict[str, object]]] = []

    async def __aenter__(self) -> _GatewayCommandSession:
        return self

    async def __aexit__(self, *_args: object) -> bool:
        return False

    def get(self, url: str, **kwargs: object) -> _GatewayResponse:
        self.requests.append((url, kwargs))
        return _GatewayResponse(200, payload=self._command)

    def post(self, url: str, **kwargs: object) -> _GatewayResponse:
        self.requests.append((url, kwargs))
        return _GatewayResponse(204)


class _IdleUpdateRuntime:
    async def report_startup_outcome(self) -> bool:
        return False

    async def run_once(self) -> SimpleNamespace:
        return SimpleNamespace(status="idle")


class _PermanentUpdateRuntime:
    def __init__(self, failure: ValueError) -> None:
        self._failure = failure
        self.calls = 0

    async def report_startup_outcome(self) -> bool:
        return False

    async def run_once(self) -> SimpleNamespace:
        self.calls += 1
        if self.calls == 1:
            raise self._failure
        raise RuntimeError("a permanent update failure must not reach a second poll")


@pytest.mark.asyncio
async def test_gateway_uses_configured_ca_and_endpoint_origin_without_legacy_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Changing the origin or bypassing the CA must fail this accepted ALT boundary."""
    ca_file = tmp_path / "endpoint-ca.crt"
    tls_context = object()
    contexts: list[dict[str, object]] = []
    connectors: list[object] = []
    session = _GatewaySession(response=_GatewayResponse(401))

    monkeypatch.setattr(
        endpoint_gateway.ssl,
        "create_default_context",
        lambda **kwargs: contexts.append(kwargs) or tls_context,
    )
    monkeypatch.setattr(
        endpoint_gateway.aiohttp,
        "TCPConnector",
        lambda *, ssl: connectors.append(ssl) or object(),
    )
    monkeypatch.setattr(
        endpoint_gateway.aiohttp, "ClientSession", lambda **_kwargs: session
    )
    monkeypatch.setattr(endpoint_gateway, "_credential", lambda: "device-token")
    monkeypatch.setattr(
        endpoint_gateway, "_gateway_update_runtime", lambda _session: _IdleUpdateRuntime()
    )

    with pytest.raises(endpoint_gateway.GatewayCredentialRejected):
        await endpoint_gateway.run_gateway_once(ca_file=ca_file)

    assert contexts == [{"cafile": str(ca_file)}]
    assert connectors == [tls_context]
    assert session.requests == [
        (
            "https://endpoint.sosnadmin.local/agent/v1/gateway/commands/next",
            {"headers": {"Authorization": "Bearer device-token"}, "ssl": tls_context},
        )
    ]
    assert "helpdesk" not in session.requests[0][0].lower()


@pytest.mark.asyncio
async def test_gateway_surfaces_transient_transport_failure_after_one_attempt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The poller must not hide a transport outage from the runtime lifecycle."""
    first_session = _GatewaySession(failure=aiohttp.ClientConnectionError("offline"))
    second_session = _GatewaySession(response=_GatewayResponse(403))
    sessions = [first_session, second_session]

    monkeypatch.setattr(endpoint_gateway.ssl, "create_default_context", lambda **_kwargs: object())
    monkeypatch.setattr(endpoint_gateway.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(
        endpoint_gateway.aiohttp, "ClientSession", lambda **_kwargs: sessions.pop(0)
    )
    monkeypatch.setattr(endpoint_gateway, "_credential", lambda: "device-token")
    monkeypatch.setattr(
        endpoint_gateway, "_gateway_update_runtime", lambda _session: _IdleUpdateRuntime()
    )

    with pytest.raises(aiohttp.ClientConnectionError):
        await endpoint_gateway.run_gateway_once(ca_file=tmp_path / "endpoint-ca.crt")

    assert len(first_session.requests) == 1
    assert second_session.requests == []


def _tls_connection_key() -> ConnectionKey:
    return ConnectionKey(
        host="endpoint.sosnadmin.local",
        port=443,
        is_ssl=True,
        ssl=True,
        proxy=None,
        proxy_auth=None,
        proxy_headers_hash=None,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        aiohttp.ClientConnectorSSLError(_tls_connection_key(), ssl.SSLError("TLS failure")),
        aiohttp.ClientConnectorCertificateError(
            _tls_connection_key(), ssl.SSLCertVerificationError("certificate failure")
        ),
    ],
)
async def test_gateway_does_not_retry_tls_verification_or_configuration_failures(
    failure: aiohttp.ClientConnectionError,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """TLS failures must terminate before a second Gateway poll can occur."""
    session = _GatewaySession(failure=failure)
    retry_session = _GatewaySession(response=_GatewayResponse(403))
    sessions = [session, retry_session]

    monkeypatch.setattr(endpoint_gateway.ssl, "create_default_context", lambda **_kwargs: object())
    monkeypatch.setattr(endpoint_gateway.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(
        endpoint_gateway.aiohttp, "ClientSession", lambda **_kwargs: sessions.pop(0)
    )
    monkeypatch.setattr(endpoint_gateway, "_credential", lambda: "device-token")
    monkeypatch.setattr(
        endpoint_gateway, "_gateway_update_runtime", lambda _session: _IdleUpdateRuntime()
    )

    with pytest.raises(type(failure)):
        await endpoint_gateway.run_gateway_once(ca_file=tmp_path / "endpoint-ca.crt")

    assert len(session.requests) == 1
    assert retry_session.requests == []


@pytest.mark.asyncio
async def test_gateway_surfaces_http_failure_without_internal_retry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A controller 500 must be classified by the owning runtime lifecycle."""
    session = _GatewaySession(response=_GatewayResponse(500))
    retry_session = _GatewaySession(response=_GatewayResponse(403))
    sessions = [session, retry_session]

    monkeypatch.setattr(endpoint_gateway.ssl, "create_default_context", lambda **_kwargs: object())
    monkeypatch.setattr(endpoint_gateway.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(
        endpoint_gateway.aiohttp, "ClientSession", lambda **_kwargs: sessions.pop(0)
    )
    monkeypatch.setattr(endpoint_gateway, "_credential", lambda: "device-token")
    monkeypatch.setattr(
        endpoint_gateway, "_gateway_update_runtime", lambda _session: _IdleUpdateRuntime()
    )

    with pytest.raises(aiohttp.ClientResponseError) as error:
        await endpoint_gateway.run_gateway_once(ca_file=tmp_path / "endpoint-ca.crt")

    assert error.value.status == 500
    assert len(session.requests) == 1
    assert retry_session.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        ValueError("invalid Endpoint device credential"),
        ValueError("Gateway update artifact integrity mismatch"),
    ],
)
async def test_gateway_does_not_retry_permanent_configuration_or_integrity_failures(
    failure: ValueError,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Credential and artifact validation failures must not be converted into retries."""
    update_runtime = _PermanentUpdateRuntime(failure)
    session = _GatewaySession(response=_GatewayResponse(204))

    monkeypatch.setattr(endpoint_gateway.ssl, "create_default_context", lambda **_kwargs: object())
    monkeypatch.setattr(endpoint_gateway.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(endpoint_gateway.aiohttp, "ClientSession", lambda **_kwargs: session)
    monkeypatch.setattr(endpoint_gateway, "_credential", lambda: "device-token")
    monkeypatch.setattr(endpoint_gateway, "_gateway_update_runtime", lambda _session: update_runtime)

    with pytest.raises(ValueError, match=str(failure)):
        await endpoint_gateway.run_gateway_once(ca_file=tmp_path / "endpoint-ca.crt")

    assert update_runtime.calls == 1
    assert session.requests == []


def _command_payload(capability: str) -> dict[str, object]:
    created_at = datetime(2026, 8, 1, tzinfo=UTC)
    return {
        "schema_version": "agent_command_v1",
        "command_id": str(_COMMAND_ID),
        "device_id": str(_DEVICE_ID),
        "capability": capability,
        "parameters": {"reason": "operator requested diagnostics"}
        if capability == "context.diagnostic.collect"
        else {},
        "requested_by_service": "endpoint-gateway",
        "idempotency_key": "gateway-baseline-0001",
        "created_at": created_at.isoformat(),
        "deadline_at": (created_at + timedelta(minutes=1)).isoformat(),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("capability", "expected_status"),
    [
        ("context.baseline.collect", "succeeded"),
        ("context.health.collect", "succeeded"),
        ("context.network.collect", "succeeded"),
        ("context.diagnostic.collect", "succeeded"),
        ("agent.status.read", "failed"),
        ("gateway.echo", "failed"),
    ],
)
async def test_gateway_parses_executes_acknowledges_and_reports_only_context_allowlist(
    capability: str,
    expected_status: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A non-context command must yield a rejected result, not dynamic execution."""
    command_session = _GatewayCommandSession(_command_payload(capability))
    terminal_session = _GatewaySession(response=_GatewayResponse(403))
    sessions = [command_session, terminal_session]
    probe = _Probe()

    monkeypatch.setattr(endpoint_gateway.ssl, "create_default_context", lambda **_kwargs: object())
    monkeypatch.setattr(endpoint_gateway.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(
        endpoint_gateway.aiohttp, "ClientSession", lambda **_kwargs: sessions.pop(0)
    )
    monkeypatch.setattr(endpoint_gateway, "_credential", lambda: "device-token")
    monkeypatch.setattr(endpoint_gateway, "SystemProbe", lambda: probe)
    monkeypatch.setattr(
        endpoint_gateway, "_gateway_update_runtime", lambda _session: _IdleUpdateRuntime()
    )

    outcome = await endpoint_gateway.run_gateway_once(
        ca_file=tmp_path / "endpoint-ca.crt"
    )

    assert outcome.delay_before_next == 0
    assert terminal_session.requests == []
    assert [url for url, _kwargs in command_session.requests] == [
        "https://endpoint.sosnadmin.local/agent/v1/gateway/commands/next",
        f"https://endpoint.sosnadmin.local/agent/v1/gateway/commands/{_COMMAND_ID}/ack",
        f"https://endpoint.sosnadmin.local/agent/v1/gateway/commands/{_COMMAND_ID}/results",
    ]
    ack_payload = command_session.requests[1][1]["json"]
    result_payload = command_session.requests[2][1]["json"]
    assert ack_payload["status"] == "acknowledged"
    assert result_payload["status"] == expected_status
    assert "helpdesk" not in "\n".join(url for url, _kwargs in command_session.requests).lower()
