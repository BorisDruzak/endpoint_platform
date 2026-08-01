"""Strict framing helpers for the neutral Gateway WebSocket protocol."""

from __future__ import annotations

from typing import TypeAlias

from pydantic import ValidationError

from endpoint_contracts.gateway_ws import (
    AgentHelloEnvelopeV1,
    CommandAckEnvelopeV1,
    CommandResultEnvelopeV1,
    GatewayWsEnvelopeV1,
    HeartbeatEnvelopeV1,
)


AgentEnvelope: TypeAlias = (
    AgentHelloEnvelopeV1
    | HeartbeatEnvelopeV1
    | CommandAckEnvelopeV1
    | CommandResultEnvelopeV1
)


class GatewayProtocolError(ValueError):
    """One safe client-visible protocol rejection."""

    def __init__(self, close_code: int, code: str) -> None:
        super().__init__(code)
        self.close_code = close_code
        self.code = code


def parse_agent_envelope(
    raw: str | bytes,
    *,
    maximum_message_bytes: int,
) -> AgentEnvelope:
    """Validate size, JSON shape, canonical contract, and client direction."""
    if maximum_message_bytes <= 0:
        raise ValueError("maximum_message_bytes must be positive")
    encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(encoded) > maximum_message_bytes:
        raise GatewayProtocolError(1009, "message_too_large")
    try:
        envelope = GatewayWsEnvelopeV1.model_validate_json(encoded).root
    except (UnicodeDecodeError, ValidationError, ValueError) as error:
        raise GatewayProtocolError(1008, "invalid_message") from error
    if not isinstance(
        envelope,
        (
            AgentHelloEnvelopeV1,
            HeartbeatEnvelopeV1,
            CommandAckEnvelopeV1,
            CommandResultEnvelopeV1,
        ),
    ):
        raise GatewayProtocolError(1008, "invalid_direction")
    return envelope


async def receive_agent_envelope(
    websocket: object,
    *,
    maximum_message_bytes: int,
) -> AgentEnvelope:
    message = await websocket.receive()  # type: ignore[attr-defined]
    if message["type"] == "websocket.disconnect":
        from starlette.websockets import WebSocketDisconnect

        raise WebSocketDisconnect(message.get("code", 1000))
    if message.get("bytes") is not None:
        raise GatewayProtocolError(1003, "text_messages_required")
    text = message.get("text")
    if not isinstance(text, str):
        raise GatewayProtocolError(1008, "invalid_message")
    return parse_agent_envelope(text, maximum_message_bytes=maximum_message_bytes)


async def send_envelope(websocket: object, envelope: object) -> None:
    await websocket.send_json(  # type: ignore[attr-defined]
        envelope.model_dump(mode="json")  # type: ignore[attr-defined]
    )


__all__ = [
    "AgentEnvelope",
    "GatewayProtocolError",
    "parse_agent_envelope",
    "receive_agent_envelope",
    "send_envelope",
]
