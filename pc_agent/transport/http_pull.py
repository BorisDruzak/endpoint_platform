"""HTTPS pull adapter for the accepted Endpoint Gateway command routes."""

from __future__ import annotations

import asyncio
import inspect
import ssl
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import aiohttp

from endpoint_contracts.gateway_ws import CommandEnvelopeV1, GatewayCommandV1

from .base import (
    GatewayCredentialRejected,
    GatewayIdle,
    GatewayRetryableError,
    GatewayTerminalError,
    GatewayTransport,
)
from .protocol import (
    AgentCommandAckV1,
    AgentHeartbeatV1,
    AgentHelloV1,
    AgentResultV1,
    GatewayHelloV1,
    GatewayInboundV1,
)


DEFAULT_ENDPOINT_ORIGIN = "https://endpoint.sosnadmin.local"
DEFAULT_HTTP_PULL_HEARTBEAT_INTERVAL_SECONDS = 30
DEFAULT_GATEWAY_MAXIMUM_MESSAGE_BYTES = 1024 * 1024


class GatewayNoCommandAvailable(RuntimeError):
    """The HTTP pull endpoint returned 204 without an inbound command."""


async def reject_endpoint_redirect(
    _session: object,
    _trace_context: object,
    _params: object,
) -> None:
    """Stop any bearer-bearing Endpoint request before a redirect is followed."""
    raise GatewayTerminalError("Endpoint redirect is not permitted")


def require_gateway_response(response: aiohttp.ClientResponse) -> None:
    """Map only device-credential denial to the transport's terminal error."""
    if response.status in {401, 403}:
        raise GatewayCredentialRejected("Endpoint Gateway rejected device credential")
    response.raise_for_status()


def validate_endpoint_origin(origin: str) -> tuple[str, str]:
    """Accept only a complete HTTPS Endpoint origin, never a route or authority."""
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Gateway Endpoint origin must be an absolute HTTPS origin")
    return parsed.scheme, parsed.netloc


OnConnected = Callable[[aiohttp.ClientSession], Awaitable[None] | None]


class HttpPullGatewayTransport:
    """Adapt accepted HTTPS command polling to the neutral Gateway contract."""

    def __init__(
        self,
        *,
        ca_file,
        credential: str,
        endpoint_origin: str = DEFAULT_ENDPOINT_ORIGIN,
        on_connected: OnConnected | None = None,
    ) -> None:
        self._ca_file = ca_file
        self._credential = credential
        self._endpoint_origin = endpoint_origin
        self._on_connected = on_connected
        self._context: ssl.SSLContext | Any | None = None
        self._session_context: Any | None = None
        self._session: aiohttp.ClientSession | Any | None = None
        self._inbound_sequence = 0

    async def connect(self, hello: AgentHelloV1) -> GatewayHelloV1:
        """Open the TLS pull session; HTTP-pull has no controller hello endpoint."""
        validate_endpoint_origin(self._endpoint_origin)
        self._context = ssl.create_default_context(cafile=str(self._ca_file))
        connector = aiohttp.TCPConnector(ssl=self._context)
        trace = aiohttp.TraceConfig()
        trace.on_request_redirect.append(reject_endpoint_redirect)
        self._session_context = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=20),
            connector=connector,
            trace_configs=[trace],
        )
        self._session = await self._session_context.__aenter__()
        try:
            if self._on_connected is not None:
                outcome = self._on_connected(self._session)
                if inspect.isawaitable(outcome):
                    await outcome
        except BaseException:
            await self.close()
            raise
        return GatewayHelloV1(
            schema_version="gateway_hello_v1",
            session_id=uuid4(),
            heartbeat_interval_seconds=DEFAULT_HTTP_PULL_HEARTBEAT_INTERVAL_SECONDS,
            maximum_message_bytes=DEFAULT_GATEWAY_MAXIMUM_MESSAGE_BYTES,
            policy_revision=0,
            effective_capabilities=hello.capabilities,
            server_time=datetime.now(UTC),
        )

    async def receive(self) -> GatewayInboundV1:
        """Poll exactly the accepted next-command endpoint."""
        session = self._require_session()
        async with session.get(
            f"{self._endpoint_origin}/agent/v1/gateway/commands/next",
            headers=self._headers(),
            ssl=self._context,
        ) as response:
            if response.status == 204:
                raise GatewayNoCommandAvailable()
            require_gateway_response(response)
            command = GatewayCommandV1.model_validate(await response.json())
        self._inbound_sequence += 1
        return GatewayInboundV1(
            root=CommandEnvelopeV1(
                schema_version="gateway_ws_envelope_v1",
                sequence=self._inbound_sequence,
                kind="command",
                payload=command,
            )
        )

    async def send_ack(self, ack: AgentCommandAckV1) -> None:
        """Post an acknowledgement to the current command's accepted route."""
        session = self._require_session()
        async with session.post(
            f"{self._endpoint_origin}/agent/v1/gateway/commands/{ack.command_id}/ack",
            headers=self._headers(),
            json=ack.model_dump(mode="json"),
            ssl=self._context,
        ) as response:
            require_gateway_response(response)

    async def send_result(self, result: AgentResultV1) -> None:
        """Post a typed command result to the accepted result route."""
        session = self._require_session()
        async with session.post(
            f"{self._endpoint_origin}/agent/v1/gateway/commands/{result.command_id}/results",
            headers=self._headers(),
            json=result.model_dump(mode="json"),
            ssl=self._context,
        ) as response:
            require_gateway_response(response)

    async def send_heartbeat(self, heartbeat: AgentHeartbeatV1) -> None:
        """HTTP pull has no heartbeat route; polling itself remains presence evidence."""
        del heartbeat

    async def close(self) -> None:
        """Close the single-attempt session, including a failed connect callback."""
        if self._session_context is not None:
            session_context = self._session_context
            self._session_context = None
            self._session = None
            await session_context.__aexit__(None, None, None)

    def _require_session(self) -> aiohttp.ClientSession | Any:
        if self._session is None:
            raise RuntimeError("Gateway transport is not connected")
        return self._session

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._credential}"}


class ClassifiedGatewayTransport:
    """Translate an HTTP adapter's library failures at the transport boundary."""

    def __init__(self, transport: GatewayTransport) -> None:
        self._transport = transport

    async def connect(self, hello: AgentHelloV1) -> GatewayHelloV1:
        return await self._call(lambda: self._transport.connect(hello))

    async def receive(self) -> GatewayInboundV1:
        try:
            return await self._call(self._transport.receive)
        except GatewayNoCommandAvailable as error:
            raise GatewayIdle(5.0) from error

    async def send_ack(self, ack: AgentCommandAckV1) -> None:
        await self._call(lambda: self._transport.send_ack(ack))

    async def send_result(self, result: AgentResultV1) -> None:
        await self._call(lambda: self._transport.send_result(result))

    async def send_heartbeat(self, heartbeat: AgentHeartbeatV1) -> None:
        await self._call(lambda: self._transport.send_heartbeat(heartbeat))

    async def close(self) -> None:
        await self._call(self._transport.close)

    async def _call(self, operation):
        try:
            return await operation()
        except (
            GatewayCredentialRejected,
            GatewayRetryableError,
            GatewayTerminalError,
            GatewayNoCommandAvailable,
        ):
            raise
        except (
            aiohttp.ClientConnectorCertificateError,
            aiohttp.ClientConnectorSSLError,
        ) as error:
            raise GatewayTerminalError(type(error).__name__) from error
        except (aiohttp.ClientConnectionError, asyncio.TimeoutError) as error:
            raise GatewayRetryableError(type(error).__name__) from error
        except aiohttp.ClientResponseError as error:
            if 500 <= error.status <= 599:
                raise GatewayRetryableError(type(error).__name__) from error
            raise GatewayTerminalError(type(error).__name__) from error
        except SystemExit:
            raise
        except Exception as error:
            raise GatewayTerminalError(type(error).__name__) from error
