"""Behavioural compatibility checks for the Endpoint HTTP-pull transport."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from endpoint_contracts import AgentCommandAckV1, AgentHelloV1, AgentResultV1
from pc_agent.transport.http_pull import (
    GatewayNoCommandAvailable,
    HttpPullGatewayTransport,
)


_DEVICE_ID = UUID("00000000-0000-4000-8000-000000000411")
_COMMAND_ID = UUID("00000000-0000-4000-8000-000000000412")


def _hello() -> AgentHelloV1:
    return AgentHelloV1(
        schema_version="agent_hello_v1",
        device_id=_DEVICE_ID,
        agent_instance_id=UUID("00000000-0000-4000-8000-000000000413"),
        agent_version="1.0.0",
        launcher_version="1.0.0",
        platform="linux_amd64",
        boot_id="boot-411",
        capabilities=["context.baseline.collect"],
        last_result_sequence=0,
        last_policy_revision=0,
    )


def _command_payload() -> dict[str, object]:
    created_at = datetime(2026, 8, 1, tzinfo=UTC)
    return {
        "schema_version": "agent_command_v1",
        "command_id": str(_COMMAND_ID),
        "device_id": str(_DEVICE_ID),
        "capability": "context.baseline.collect",
        "parameters": {},
        "requested_by_service": "transport-test",
        "idempotency_key": "transport-command-411",
        "created_at": created_at.isoformat(),
        "deadline_at": (created_at + timedelta(minutes=1)).isoformat(),
    }


class _Response:
    def __init__(self, status: int, *, payload: object | None = None) -> None:
        self.status = status
        self._payload = payload

    async def __aenter__(self) -> "_Response":
        return self

    async def __aexit__(self, *_args: object) -> bool:
        return False

    async def json(self) -> object:
        assert self._payload is not None
        return self._payload

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise RuntimeError(f"unexpected HTTP {self.status}")


class _Session:
    def __init__(self, responses: list[_Response]) -> None:
        self._responses = responses
        self.requests: list[tuple[str, str, dict[str, object]]] = []
        self.closed = False

    async def __aenter__(self) -> "_Session":
        return self

    async def __aexit__(self, *_args: object) -> bool:
        self.closed = True
        return False

    def get(self, url: str, **kwargs: object) -> _Response:
        self.requests.append(("GET", url, kwargs))
        return self._responses.pop(0)

    def post(self, url: str, **kwargs: object) -> _Response:
        self.requests.append(("POST", url, kwargs))
        return self._responses.pop(0)


@pytest.mark.asyncio
async def test_http_pull_adapter_preserves_accepted_command_ack_and_result_routes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A route or verb change would break the currently accepted Gateway server."""
    from pc_agent.transport import http_pull

    session = _Session(
        [
            _Response(200, payload=_command_payload()),
            _Response(204),
            _Response(204),
        ]
    )
    tls_context = object()
    monkeypatch.setattr(http_pull.ssl, "create_default_context", lambda **_kwargs: tls_context)
    monkeypatch.setattr(http_pull.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(http_pull.aiohttp, "ClientSession", lambda **_kwargs: session)
    transport = HttpPullGatewayTransport(
        ca_file=tmp_path / "endpoint-ca.crt",
        credential="device-token",
        endpoint_origin="https://endpoint.sosnadmin.local",
    )

    await transport.connect(_hello())
    inbound = await transport.receive()
    command = inbound.root.payload
    ack = AgentCommandAckV1(
        schema_version="agent_command_ack_v1",
        command_id=_COMMAND_ID,
        device_id=_DEVICE_ID,
        status="acknowledged",
        acknowledged_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    result = AgentResultV1(
        schema_version="agent_result_v1",
        command_id=_COMMAND_ID,
        device_id=_DEVICE_ID,
        status="succeeded",
        completed_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    await transport.send_ack(ack)
    await transport.send_result(result)
    await transport.close()

    assert command.command_id == _COMMAND_ID
    assert session.closed is True
    assert [(method, url) for method, url, _kwargs in session.requests] == [
        ("GET", "https://endpoint.sosnadmin.local/agent/v1/gateway/commands/next"),
        ("POST", f"https://endpoint.sosnadmin.local/agent/v1/gateway/commands/{_COMMAND_ID}/ack"),
        ("POST", f"https://endpoint.sosnadmin.local/agent/v1/gateway/commands/{_COMMAND_ID}/results"),
    ]
    assert session.requests[0][2] == {
        "headers": {"Authorization": "Bearer device-token"},
        "ssl": tls_context,
    }


@pytest.mark.asyncio
async def test_http_pull_adapter_treats_empty_pull_as_no_inbound_message(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A 204 is an idle poll, not a fabricated Gateway command."""
    from pc_agent.transport import http_pull

    session = _Session([_Response(204)])
    monkeypatch.setattr(http_pull.ssl, "create_default_context", lambda **_kwargs: object())
    monkeypatch.setattr(http_pull.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(http_pull.aiohttp, "ClientSession", lambda **_kwargs: session)
    transport = HttpPullGatewayTransport(
        ca_file=tmp_path / "endpoint-ca.crt",
        credential="device-token",
        endpoint_origin="https://endpoint.sosnadmin.local",
    )

    await transport.connect(_hello())
    with pytest.raises(GatewayNoCommandAvailable):
        await transport.receive()
    await transport.close()

    assert [(method, url) for method, url, _kwargs in session.requests] == [
        ("GET", "https://endpoint.sosnadmin.local/agent/v1/gateway/commands/next")
    ]
