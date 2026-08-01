"""Bounded process-local registry for active Gateway WebSocket connections."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from uuid import UUID

from endpoint_contracts.gateway_ws import (
    ServerShutdownNoticeEnvelopeV1,
    ServerShutdownNoticeV1,
)


_SESSION_REPLACED_CLOSE_CODE = 4001


class RegistryCapacityExceeded(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class GatewayConnection:
    device_id: UUID
    session_id: UUID
    websocket: object


class ConnectionRegistry:
    """Own at most one active process-local connection per device."""

    def __init__(self, *, max_connections: int = 4096) -> None:
        if max_connections <= 0:
            raise ValueError("max_connections must be positive")
        self._max_connections = max_connections
        self._connections: dict[UUID, GatewayConnection] = {}
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def register(
        self, connection: GatewayConnection
    ) -> GatewayConnection | None:
        async with self._lock:
            previous = self._connections.get(connection.device_id)
            if previous is None and len(self._connections) >= self._max_connections:
                raise RegistryCapacityExceeded("gateway connection capacity reached")
            self._connections[connection.device_id] = connection
        if previous is not None and previous.session_id != connection.session_id:
            await self._replace(previous)
            return previous
        return None

    async def unregister(self, device_id: UUID, session_id: UUID) -> None:
        async with self._lock:
            current = self._connections.get(device_id)
            if current is not None and current.session_id == session_id:
                del self._connections[device_id]

    async def shutdown_all(self) -> None:
        async with self._lock:
            connections = tuple(self._connections.values())
            self._connections.clear()
        for connection in connections:
            await self._shutdown(connection, "server_shutdown", 1001)

    async def _replace(self, connection: GatewayConnection) -> None:
        await self._shutdown(
            connection,
            "session_replaced",
            _SESSION_REPLACED_CLOSE_CODE,
        )

    @staticmethod
    async def _shutdown(
        connection: GatewayConnection,
        reason: str,
        close_code: int,
    ) -> None:
        notice = ServerShutdownNoticeEnvelopeV1(
            schema_version="gateway_ws_envelope_v1",
            kind="server_shutdown_notice",
            sequence=0,
            payload=ServerShutdownNoticeV1(
                schema_version="server_shutdown_notice_v1",
                reason=reason,
                retry_after_seconds=0,
            ),
        )
        try:
            await connection.websocket.send_json(notice.model_dump(mode="json"))
        except Exception:
            pass
        try:
            await connection.websocket.close(code=close_code)
        except Exception:
            pass


__all__ = [
    "ConnectionRegistry",
    "GatewayConnection",
    "RegistryCapacityExceeded",
]
