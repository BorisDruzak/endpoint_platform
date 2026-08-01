"""Executable baseline for the accepted ALT Gateway transport."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import aiohttp
import pytest

from endpoint_contracts import AgentCommandV1
from pc_agent import endpoint_gateway
from pc_agent.core.orchestrator import execute_context_agent_command


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
    def __init__(self, status: int) -> None:
        self.status = status

    async def __aenter__(self) -> _GatewayResponse:
        return self

    async def __aexit__(self, *_args: object) -> bool:
        return False

    async def json(self) -> object:
        raise AssertionError("credential rejection must not parse a command")

    def raise_for_status(self) -> None:
        raise AssertionError("401/403 must be terminal before generic HTTP handling")


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


class _IdleUpdateRuntime:
    async def report_startup_outcome(self) -> bool:
        return False

    async def run_once(self) -> SimpleNamespace:
        return SimpleNamespace(status="idle")


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
        await endpoint_gateway.run_gateway_forever(ca_file=ca_file)

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
async def test_gateway_retries_transient_transport_failures_but_not_credential_rejection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A credential rejection must escape, while a transport outage gets one retry."""
    first_session = _GatewaySession(failure=aiohttp.ClientConnectionError("offline"))
    second_session = _GatewaySession(response=_GatewayResponse(403))
    sessions = [first_session, second_session]
    sleeps: list[float] = []

    monkeypatch.setattr(endpoint_gateway.ssl, "create_default_context", lambda **_kwargs: object())
    monkeypatch.setattr(endpoint_gateway.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(
        endpoint_gateway.aiohttp, "ClientSession", lambda **_kwargs: sessions.pop(0)
    )
    monkeypatch.setattr(endpoint_gateway, "_credential", lambda: "device-token")
    monkeypatch.setattr(
        endpoint_gateway, "_gateway_update_runtime", lambda _session: _IdleUpdateRuntime()
    )

    async def capture_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(endpoint_gateway.asyncio, "sleep", capture_sleep)

    with pytest.raises(endpoint_gateway.GatewayCredentialRejected):
        await endpoint_gateway.run_gateway_forever(ca_file=tmp_path / "endpoint-ca.crt")

    assert sleeps == [5]
    assert len(first_session.requests) == 1
    assert len(second_session.requests) == 1
