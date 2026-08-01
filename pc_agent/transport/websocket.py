"""TLS-only Endpoint Gateway WebSocket transport."""

from __future__ import annotations

import asyncio
import inspect
import json
import random
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp
from pydantic import ValidationError

from endpoint_contracts.gateway_ws import (
    AgentHelloEnvelopeV1,
    CommandAckEnvelopeV1,
    CommandResultEnvelopeV1,
    GatewayHelloEnvelopeV1,
    GatewayWsEnvelopeV1,
    HeartbeatEnvelopeV1,
)

from .backoff import bounded_exponential_backoff
from .base import (
    GatewayCredentialRejected,
    GatewayRetryableError,
    GatewayTerminalError,
    GatewayTransport,
)
from .http_pull import (
    DEFAULT_ENDPOINT_ORIGIN,
    reject_endpoint_redirect,
    validate_endpoint_origin,
)
from .protocol import (
    AgentCommandAckV1,
    AgentHeartbeatV1,
    AgentHelloV1,
    AgentResultV1,
    GatewayHelloV1,
    GatewayInboundV1,
)


GATEWAY_CONNECT_PATH = "/agent/v1/connect"
INITIAL_MAXIMUM_MESSAGE_BYTES = 1024 * 1024
OnConnected = Callable[[GatewayHelloV1], Awaitable[None] | None]


class GatewayTransportUnavailable(GatewayRetryableError):
    """The WSS channel was unavailable at the network/upgrade boundary."""


@dataclass(frozen=True, slots=True)
class WebSocketReconnectPolicy:
    """Bound and jitter the attempts made by one WSS transport instance."""

    maximum_attempts: int = 3
    base_delay: float = 1.0
    maximum_delay: float = 8.0
    jitter_ratio: float = 0.2

    def __post_init__(self) -> None:
        if self.maximum_attempts < 1:
            raise ValueError("maximum_attempts must be positive")
        if self.base_delay <= 0 or self.maximum_delay <= 0:
            raise ValueError("reconnect delays must be positive")
        if self.base_delay > self.maximum_delay:
            raise ValueError("reconnect base delay must not exceed the maximum")
        if not 0 <= self.jitter_ratio <= 1:
            raise ValueError("jitter_ratio must be between zero and one")

    def delay_after_failure(
        self,
        failure_index: int,
        *,
        random_value: float,
    ) -> float:
        exponential = bounded_exponential_backoff(
            failure_index,
            base_seconds=self.base_delay,
            maximum_seconds=self.maximum_delay,
        )
        factor = 1.0 + self.jitter_ratio * ((2.0 * random_value) - 1.0)
        return min(self.maximum_delay, exponential * factor)


def gateway_websocket_url(endpoint_origin: str) -> str:
    """Derive the one WSS route from a DNS-based HTTPS Endpoint origin."""
    _scheme, netloc = validate_endpoint_origin(endpoint_origin)
    host = urlsplit(endpoint_origin).hostname
    if host is None:
        raise ValueError("Gateway Endpoint origin must include a hostname")
    try:
        ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Gateway Endpoint origin must use its configured hostname")
    return f"wss://{netloc}{GATEWAY_CONNECT_PATH}"


class WebSocketGatewayTransport:
    """Exchange canonical Gateway envelopes over the configured WSS origin."""

    def __init__(
        self,
        *,
        ca_file: Path,
        credential: str,
        endpoint_origin: str = DEFAULT_ENDPOINT_ORIGIN,
        reconnect_policy: WebSocketReconnectPolicy | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        random_value: Callable[[], float] = random.random,
        on_connected: OnConnected | None = None,
    ) -> None:
        self._ca_file = Path(ca_file)
        self._credential = credential
        self._endpoint_origin = endpoint_origin
        self._reconnect_policy = reconnect_policy or WebSocketReconnectPolicy()
        self._sleep = sleep
        self._random_value = random_value
        self._on_connected = on_connected
        self._session = None
        self._socket = None
        self._maximum_message_bytes = INITIAL_MAXIMUM_MESSAGE_BYTES
        self._outgoing_sequence = 0

    async def connect(self, hello: AgentHelloV1) -> GatewayHelloV1:
        for attempt in range(self._reconnect_policy.maximum_attempts):
            try:
                return await self._connect_once(hello)
            except (GatewayCredentialRejected, GatewayTerminalError):
                raise
            except (
                aiohttp.ClientConnectorCertificateError,
                aiohttp.ClientConnectorSSLError,
                ssl.SSLError,
            ) as error:
                raise GatewayTerminalError(type(error).__name__) from error
            except aiohttp.WSServerHandshakeError as error:
                if error.status in {401, 403}:
                    raise GatewayCredentialRejected(
                        "Endpoint Gateway rejected device credential"
                    ) from error
                if error.status in {404, 500, 501, 502, 503, 504}:
                    await self._retry_unavailable(attempt, error)
                    continue
                raise GatewayTerminalError(type(error).__name__) from error
            except (
                aiohttp.ClientConnectionError,
                asyncio.TimeoutError,
                OSError,
            ) as error:
                await self._retry_unavailable(attempt, error)
        raise AssertionError("unreachable WSS reconnect state")

    async def _retry_unavailable(self, attempt: int, error: Exception) -> None:
        if attempt + 1 == self._reconnect_policy.maximum_attempts:
            raise GatewayTransportUnavailable(type(error).__name__) from error
        delay = self._reconnect_policy.delay_after_failure(
            attempt,
            random_value=self._random_value(),
        )
        await self._sleep(delay)

    async def _connect_once(self, hello: AgentHelloV1) -> GatewayHelloV1:
        websocket_url = gateway_websocket_url(self._endpoint_origin)
        context = ssl.create_default_context(cafile=str(self._ca_file))
        connector = aiohttp.TCPConnector(ssl=context)
        trace = aiohttp.TraceConfig()
        trace.on_request_redirect.append(reject_endpoint_redirect)
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=20),
            connector=connector,
            trace_configs=[trace],
        )
        try:
            self._socket = await self._session.ws_connect(
                websocket_url,
                headers={"Authorization": f"Bearer {self._credential}"},
                ssl=context,
                max_msg_size=INITIAL_MAXIMUM_MESSAGE_BYTES,
            )
            response = getattr(self._socket, "_response", None)
            if (
                response is None
                or tuple(getattr(response, "history", ()))
                or str(getattr(response, "url", "")) != websocket_url
            ):
                raise GatewayTerminalError(
                    "Gateway connection did not use the exact Endpoint URL"
                )
            envelope = AgentHelloEnvelopeV1(
                schema_version="gateway_ws_envelope_v1",
                sequence=0,
                kind="agent_hello",
                payload=hello,
            )
            await self._socket.send_json(envelope.model_dump(mode="json"))
            response = await self._socket.receive()
            if response.type is not aiohttp.WSMsgType.TEXT:
                raise GatewayTerminalError("Gateway hello must be a text message")
            encoded = response.data.encode("utf-8")
            if len(encoded) > INITIAL_MAXIMUM_MESSAGE_BYTES:
                raise GatewayTerminalError("Gateway hello exceeds the message limit")
            try:
                parsed = GatewayWsEnvelopeV1.model_validate_json(encoded).root
            except (ValidationError, ValueError) as error:
                raise GatewayTerminalError("invalid Gateway hello") from error
            if not isinstance(parsed, GatewayHelloEnvelopeV1) or parsed.sequence != 0:
                raise GatewayTerminalError("expected Gateway hello")
            self._maximum_message_bytes = parsed.payload.maximum_message_bytes
            self._outgoing_sequence = 0
            if self._on_connected is not None:
                outcome = self._on_connected(parsed.payload)
                if inspect.isawaitable(outcome):
                    await outcome
            return parsed.payload
        except BaseException:
            await self.close()
            raise

    async def receive(self) -> GatewayInboundV1:
        parsed = await self._receive_envelope()
        try:
            return GatewayInboundV1(root=parsed)
        except (ValidationError, ValueError) as error:
            raise GatewayTerminalError("invalid Gateway inbound message") from error

    async def send_ack(self, ack: AgentCommandAckV1) -> None:
        await self._send(
            CommandAckEnvelopeV1,
            kind="command_ack",
            payload=ack,
        )

    async def send_result(self, result: AgentResultV1) -> None:
        await self._send(
            CommandResultEnvelopeV1,
            kind="command_result",
            payload=result,
        )

    async def send_heartbeat(self, heartbeat: AgentHeartbeatV1) -> None:
        await self._send(
            HeartbeatEnvelopeV1,
            kind="heartbeat",
            payload=heartbeat,
        )

    async def _receive_envelope(self):
        socket = self._require_socket()
        try:
            response = await socket.receive()
        except (
            aiohttp.ClientConnectorCertificateError,
            aiohttp.ClientConnectorSSLError,
            ssl.SSLError,
        ) as error:
            raise GatewayTerminalError(type(error).__name__) from error
        except (
            aiohttp.ClientConnectionError,
            asyncio.TimeoutError,
            OSError,
        ) as error:
            raise GatewayTransportUnavailable(type(error).__name__) from error
        if response.type in {
            aiohttp.WSMsgType.CLOSE,
            aiohttp.WSMsgType.CLOSED,
            aiohttp.WSMsgType.CLOSING,
        }:
            close_code = response.data if isinstance(response.data, int) else None
            if close_code in {4401, 4403}:
                raise GatewayCredentialRejected("Endpoint Gateway rejected device")
            if close_code in {1000, 1001, 1011, 1012, 1013, 4000, 4001}:
                raise GatewayTransportUnavailable("Gateway WSS connection closed")
            raise GatewayTerminalError("Gateway WSS policy or protocol close")
        if response.type is not aiohttp.WSMsgType.TEXT:
            raise GatewayTerminalError("Gateway messages must use text frames")
        encoded = response.data.encode("utf-8")
        if len(encoded) > self._maximum_message_bytes:
            raise GatewayTerminalError("Gateway message exceeds the negotiated limit")
        try:
            return GatewayWsEnvelopeV1.model_validate_json(encoded).root
        except (ValidationError, ValueError) as error:
            raise GatewayTerminalError("invalid Gateway message") from error

    async def _send(self, envelope_type, *, kind: str, payload: object) -> None:
        socket = self._require_socket()
        envelope = envelope_type(
            schema_version="gateway_ws_envelope_v1",
            sequence=self._outgoing_sequence + 1,
            kind=kind,
            payload=payload,
        )
        body = envelope.model_dump(mode="json")
        if len(json.dumps(body).encode("utf-8")) > self._maximum_message_bytes:
            raise GatewayTerminalError(
                "Gateway message exceeds the negotiated limit"
            )
        self._outgoing_sequence += 1
        try:
            await socket.send_json(body)
        except (
            aiohttp.ClientConnectorCertificateError,
            aiohttp.ClientConnectorSSLError,
            ssl.SSLError,
        ) as error:
            raise GatewayTerminalError(type(error).__name__) from error
        except (
            aiohttp.ClientConnectionError,
            asyncio.TimeoutError,
            OSError,
        ) as error:
            raise GatewayTransportUnavailable(type(error).__name__) from error

    def _require_socket(self):
        if self._socket is None:
            raise GatewayTerminalError("Gateway WSS is not connected")
        return self._socket

    async def close(self) -> None:
        if self._socket is not None:
            socket = self._socket
            self._socket = None
            await socket.close()
        if self._session is not None:
            session = self._session
            self._session = None
            await session.close()


class MigrationFallbackGatewayTransport:
    """Select HTTP pull only for an explicit, same-origin WSS migration gap."""

    def __init__(
        self,
        *,
        primary: GatewayTransport,
        fallback: GatewayTransport,
        enabled: bool,
        endpoint_origin: str,
        fallback_origin: str,
    ) -> None:
        if not isinstance(enabled, bool):
            raise ValueError("migration fallback flag must be boolean")
        if enabled and (
            validate_endpoint_origin(endpoint_origin)
            != validate_endpoint_origin(fallback_origin)
        ):
            raise ValueError("migration fallback must use the same Endpoint origin")
        self._primary = primary
        self._fallback = fallback
        self._enabled = enabled
        self._active: GatewayTransport = primary
        self._hello: AgentHelloV1 | None = None

    async def connect(self, hello: AgentHelloV1) -> GatewayHelloV1:
        self._active = self._primary
        self._hello = hello
        try:
            return await self._primary.connect(hello)
        except GatewayTransportUnavailable as error:
            return await self._switch_to_fallback(error)

    async def receive(self) -> GatewayInboundV1:
        try:
            return await self._active.receive()
        except GatewayTransportUnavailable as error:
            await self._switch_to_fallback(error)
            return await self._active.receive()

    async def send_ack(self, ack: AgentCommandAckV1) -> None:
        try:
            await self._active.send_ack(ack)
        except GatewayTransportUnavailable as error:
            await self._switch_to_fallback(error)
            await self._active.send_ack(ack)

    async def send_result(self, result: AgentResultV1) -> None:
        try:
            await self._active.send_result(result)
        except GatewayTransportUnavailable as error:
            await self._switch_to_fallback(error)
            await self._active.send_result(result)

    async def send_heartbeat(self, heartbeat: AgentHeartbeatV1) -> None:
        try:
            await self._active.send_heartbeat(heartbeat)
        except GatewayTransportUnavailable as error:
            await self._switch_to_fallback(error)
            await self._active.send_heartbeat(heartbeat)

    async def close(self) -> None:
        await self._active.close()

    async def _switch_to_fallback(
        self,
        error: GatewayTransportUnavailable,
    ) -> GatewayHelloV1:
        if (
            not self._enabled
            or self._active is not self._primary
            or self._hello is None
        ):
            raise error
        try:
            await self._primary.close()
        except Exception:
            pass
        self._active = self._fallback
        return await self._fallback.connect(self._hello)
