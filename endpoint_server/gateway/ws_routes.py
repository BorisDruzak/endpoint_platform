"""Authenticated neutral Gateway WebSocket endpoint."""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Mapping

from fastapi import APIRouter, HTTPException, WebSocket
from starlette.websockets import WebSocketDisconnect

from endpoint_contracts import AgentHelloV1, GatewayErrorV1, GatewayHelloV1
from endpoint_contracts.gateway_ws import (
    AgentHelloEnvelopeV1,
    CommandAckEnvelopeV1,
    CommandResultEnvelopeV1,
    ErrorEnvelopeV1,
    GatewayHelloEnvelopeV1,
    HeartbeatEnvelopeV1,
)
from endpoint_server.network import observed_client_address
from endpoint_server.operations.capabilities import (
    NETWORK_PRIMITIVE_CAPABILITIES,
    network_primitives_enabled,
)
from endpoint_server.updates.agent_routes import DevicePrincipal, _authenticate_device

from .command_service import CommandService, CommandStateRejected
from .connection_registry import (
    GatewayConnection,
    RegistryCapacityExceeded,
)
from .presence_service import GatewayPresence, PresenceRejected, PresenceService
from .protocol import (
    GatewayProtocolError,
    receive_agent_envelope,
    send_envelope,
)


router = APIRouter(tags=["agent-gateway-wss"])
logger = logging.getLogger(__name__)
HEARTBEAT_INTERVAL_SECONDS = 30
MAXIMUM_MESSAGE_BYTES = 64 * 1024
_HEARTBEAT_TIMEOUT_SECONDS = HEARTBEAT_INTERVAL_SECONDS * 3
_SUPPORTED_CAPABILITIES = frozenset(
    {
        "agent.status.read",
        "gateway.echo",
        "context.baseline.collect",
        "context.health.collect",
        "context.network.collect",
        "context.diagnostic.collect",
        *NETWORK_PRIMITIVE_CAPABILITIES,
    }
)


class GatewayHandshakeRejected(ValueError):
    def __init__(self, close_code: int) -> None:
        super().__init__("gateway handshake rejected")
        self.close_code = close_code


@dataclass(frozen=True, slots=True)
class GatewayAuthentication:
    principal: DevicePrincipal
    source_address: IPv4Address | IPv6Address


def assert_single_gateway_worker(
    environment: Mapping[str, str] | None = None,
) -> None:
    """Fail startup when a known launcher requests process-local fan-out."""
    values = os.environ if environment is None else environment
    for name in ("ENDPOINT_API_WORKERS", "WEB_CONCURRENCY", "UVICORN_WORKERS"):
        raw = values.get(name)
        if raw is None or not raw.strip():
            continue
        try:
            workers = int(raw)
        except ValueError as error:
            raise RuntimeError(
                "Gateway WSS requires exactly one API worker"
            ) from error
        if workers != 1:
            raise RuntimeError("Gateway WSS requires exactly one API worker")


def _require_secure_transport(websocket: WebSocket) -> None:
    if websocket.client is None:
        raise GatewayHandshakeRejected(4401)
    try:
        peer = ip_address(websocket.client.host)
    except ValueError as error:
        raise GatewayHandshakeRejected(4401) from error
    trusted_proxy = any(
        peer in network
        for network in websocket.app.state.settings.trusted_proxy_cidrs
    )
    if trusted_proxy:
        forwarded = websocket.headers.getlist("x-forwarded-proto")
        if len(forwarded) != 1 or forwarded[0].lower() != "https":
            raise GatewayHandshakeRejected(4401)
    elif websocket.scope.get("scheme") != "wss":
        raise GatewayHandshakeRejected(4401)


async def authenticate_gateway_websocket(
    websocket: WebSocket,
) -> GatewayAuthentication:
    """Reuse the HTTPS device bearer verifier after enforcing WSS metadata."""
    _require_secure_transport(websocket)
    try:
        source_address = observed_client_address(websocket)
        async with websocket.app.state.session_provider() as session:
            principal = await _authenticate_device(session, websocket)
    except (HTTPException, ValueError) as error:
        raise GatewayHandshakeRejected(4401) from error
    return GatewayAuthentication(
        principal=principal,
        source_address=source_address,
    )


def validate_agent_hello(
    authenticated: GatewayAuthentication,
    hello: AgentHelloV1,
) -> None:
    if hello.device_id != authenticated.principal.device.id:
        raise GatewayHandshakeRejected(4403)


async def _send_safe_error(websocket: WebSocket, code: str) -> None:
    envelope = ErrorEnvelopeV1(
        schema_version="gateway_ws_envelope_v1",
        kind="error",
        sequence=0,
        payload=GatewayErrorV1(
            schema_version="gateway_error_v1",
            code=code,
            message="Gateway message rejected",
            retryable=False,
        ),
    )
    try:
        await send_envelope(websocket, envelope)
    except Exception:
        pass


@router.websocket("/agent/v1/connect")
async def connect_agent(websocket: WebSocket) -> None:
    try:
        authenticated = await authenticate_gateway_websocket(websocket)
    except GatewayHandshakeRejected as rejection:
        await websocket.close(code=rejection.close_code)
        return

    await websocket.accept()
    presence: GatewayPresence | None = None
    close_reason = "disconnected"
    device_id = authenticated.principal.device.id
    presence_service = PresenceService(websocket.app.state.session_provider)
    command_service = CommandService(websocket.app.state.session_provider)
    try:
        first = await asyncio.wait_for(
            receive_agent_envelope(
                websocket,
                maximum_message_bytes=MAXIMUM_MESSAGE_BYTES,
            ),
            timeout=_HEARTBEAT_TIMEOUT_SECONDS,
        )
        if not isinstance(first, AgentHelloEnvelopeV1):
            raise GatewayProtocolError(1008, "agent_hello_required")
        validate_agent_hello(authenticated, first.payload)
        presence = await presence_service.open_session(
            device_id=device_id,
            hello=first.payload,
            source_address=str(authenticated.source_address),
        )
        effective_capabilities = [
            capability
            for capability in first.payload.capabilities
            if capability in _SUPPORTED_CAPABILITIES
            and (
                capability not in NETWORK_PRIMITIVE_CAPABILITIES
                or network_primitives_enabled(websocket.app.state.settings)
            )
        ]
        await websocket.app.state.gateway_connection_registry.register(
            GatewayConnection(
                device_id=device_id,
                session_id=presence.session_id,
                websocket=websocket,
                agent_version=first.payload.agent_version,
                platform=first.payload.platform,
                effective_capabilities=frozenset(effective_capabilities),
            )
        )
        await send_envelope(
            websocket,
            GatewayHelloEnvelopeV1(
                schema_version="gateway_ws_envelope_v1",
                kind="gateway_hello",
                sequence=0,
                payload=GatewayHelloV1(
                    schema_version="gateway_hello_v1",
                    session_id=presence.session_id,
                    heartbeat_interval_seconds=HEARTBEAT_INTERVAL_SECONDS,
                    maximum_message_bytes=MAXIMUM_MESSAGE_BYTES,
                    policy_revision=0,
                    effective_capabilities=effective_capabilities,
                    server_time=datetime.now(UTC),
                ),
            ),
        )
        await command_service.deliver_next(
            device_id,
            presence.session_id,
            lambda envelope: send_envelope(websocket, envelope),
            allowed_capabilities=frozenset(effective_capabilities),
        )

        while True:
            envelope = await asyncio.wait_for(
                receive_agent_envelope(
                    websocket,
                    maximum_message_bytes=MAXIMUM_MESSAGE_BYTES,
                ),
                timeout=_HEARTBEAT_TIMEOUT_SECONDS,
            )
            if isinstance(envelope, HeartbeatEnvelopeV1):
                await presence_service.record_heartbeat(
                    device_id=device_id,
                    session_id=presence.session_id,
                    heartbeat=envelope.payload,
                )
            elif isinstance(envelope, CommandAckEnvelopeV1):
                await command_service.record_ack(
                    device_id=device_id,
                    session_id=presence.session_id,
                    acknowledgement=envelope.payload,
                )
            elif isinstance(envelope, CommandResultEnvelopeV1):
                acknowledgement = await command_service.record_result(
                    device_id=device_id,
                    device_instance_id=presence.device_instance_id,
                    session_id=presence.session_id,
                    result_sequence=envelope.sequence,
                    result=envelope.payload,
                )
                await send_envelope(websocket, acknowledgement)
            else:
                raise GatewayProtocolError(1008, "unexpected_message")
            await command_service.deliver_next(
                device_id,
                presence.session_id,
                lambda message: send_envelope(websocket, message),
                allowed_capabilities=frozenset(effective_capabilities),
            )
    except WebSocketDisconnect:
        pass
    except TimeoutError:
        close_reason = "heartbeat_timeout"
        await websocket.close(code=4000)
    except GatewayHandshakeRejected as rejection:
        close_reason = "identity_mismatch"
        await websocket.close(code=rejection.close_code)
    except GatewayProtocolError as error:
        close_reason = error.code
        await _send_safe_error(websocket, error.code)
        await websocket.close(code=error.close_code)
    except RegistryCapacityExceeded:
        close_reason = "registry_capacity"
        await websocket.close(code=1013)
    except (CommandStateRejected, PresenceRejected) as error:
        logger.warning("Gateway state rejected: %s: %s", type(error).__name__, error)
        close_reason = "state_rejected"
        await _send_safe_error(websocket, "state_rejected")
        await websocket.close(code=1008)
    except Exception:
        close_reason = "internal_error"
        await websocket.close(code=1011)
    finally:
        if presence is not None:
            await websocket.app.state.gateway_connection_registry.unregister(
                device_id,
                presence.session_id,
            )
            await presence_service.close_session(
                device_id=device_id,
                session_id=presence.session_id,
                reason=close_reason,
            )


__all__ = [
    "GatewayAuthentication",
    "GatewayHandshakeRejected",
    "assert_single_gateway_worker",
    "authenticate_gateway_websocket",
    "connect_agent",
    "router",
    "validate_agent_hello",
]
