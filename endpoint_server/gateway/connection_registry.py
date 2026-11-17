"""Bounded process-local registry for active Gateway WebSocket connections."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

from endpoint_contracts.gateway_ws import (
    ServerShutdownNoticeEnvelopeV1,
    ServerShutdownNoticeV1,
)


logger = logging.getLogger(__name__)
_SESSION_REPLACED_CLOSE_CODE = 4001
_NOTICE_TIMEOUT_SECONDS = 0.5
_CLOSE_TIMEOUT_SECONDS = 1.0


class RegistryCapacityExceeded(RuntimeError):
    pass


class GatewayWorkerLease:
    """Hold a deployment-scoped OS lock while one Gateway worker is alive."""

    def __init__(self, artifact_root: Path) -> None:
        self._path = artifact_root / ".gateway-wss-worker.lock"
        self._descriptor: int | None = None

    def acquire(self) -> None:
        if self._descriptor is not None:
            raise RuntimeError("Gateway WSS worker lease is already held")
        descriptor = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(descriptor)
            raise RuntimeError(
                "Gateway WSS requires exactly one API worker"
            ) from error
        self._descriptor = descriptor

    def release(self) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            return
        self._descriptor = None
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@dataclass(frozen=True, slots=True)
class GatewayConnection:
    device_id: UUID
    session_id: UUID
    websocket: object
    agent_version: str = ""
    platform: str = ""
    effective_capabilities: frozenset[str] = frozenset()
    protocol_features: frozenset[str] = frozenset()
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock, compare=False, repr=False)
    ready_for_dispatch: asyncio.Event = field(default_factory=asyncio.Event, compare=False, repr=False)
    session_closed_by_replacement: asyncio.Event = field(
        default_factory=asyncio.Event, compare=False, repr=False,
    )

    async def send(self, envelope: object) -> None:
        """Serialize control and command writes on one active WebSocket."""
        async with self.send_lock:
            await self.websocket.send_json(envelope.model_dump(mode="json"))  # type: ignore[attr-defined]


class ConnectionRegistry:
    """Own at most one active process-local connection per device."""

    def __init__(self, *, max_connections: int = 4096) -> None:
        if max_connections <= 0:
            raise ValueError("max_connections must be positive")
        self._max_connections = max_connections
        self._connections: dict[UUID, GatewayConnection] = {}
        self._lock = asyncio.Lock()
        self._dispatch_pending: dict[UUID, tuple[GatewayConnection, bool]] = {}
        self._dispatch_running: set[UUID] = set()
        self._dispatch_ready = asyncio.Event()
        # Bound opening bursts against the shared database pool.
        self.handshake_db_slots = asyncio.BoundedSemaphore(8)
        # Fixed-size stripes bound memory even during bursts of new device IDs.
        self._handshake_locks = tuple(asyncio.Lock() for _ in range(256))

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    def handshake_lock(self, device_id: UUID) -> asyncio.Lock:
        """Serialize the durable open and registry publication for a device."""
        return self._handshake_locks[device_id.int % len(self._handshake_locks)]

    async def require_capacity(self, device_id: UUID) -> None:
        async with self._lock:
            self._require_capacity(device_id)

    def _require_capacity(self, device_id: UUID) -> None:
        if device_id not in self._connections and len(self._connections) >= self._max_connections:
            raise RegistryCapacityExceeded("gateway connection capacity reached")

    async def publish(
        self, connection: GatewayConnection
    ) -> GatewayConnection | None:
        async with self._lock:
            previous = self._connections.get(connection.device_id)
            self._require_capacity(connection.device_id)
            self._connections[connection.device_id] = connection
            if previous is not None and previous is not connection:
                self._dispatch_pending.pop(connection.device_id, None)
        if previous is not None and previous.session_id != connection.session_id:
            return previous
        return None

    async def register(self, connection: GatewayConnection) -> GatewayConnection | None:
        previous = await self.publish(connection)
        if previous is not None:
            await self.close_replaced(previous)
        return previous

    async def unregister(self, device_id: UUID, session_id: UUID) -> None:
        async with self._lock:
            current = self._connections.get(device_id)
            if current is not None and current.session_id == session_id:
                del self._connections[device_id]
                self._dispatch_pending.pop(device_id, None)

    async def get(self, device_id: UUID) -> GatewayConnection | None:
        """Return a metadata snapshot for one active connection."""
        async with self._lock:
            return self._connections.get(device_id)

    async def connected(self) -> tuple[GatewayConnection, ...]:
        """Snapshot active connections for bounded operator projections."""
        async with self._lock:
            return tuple(self._connections.values())

    def dispatch_in_progress(self, device_id: UUID) -> bool:
        return device_id in self._dispatch_running

    async def request_dispatch(self, connection: GatewayConnection) -> None:
        """Coalesce activity into one pending request for its current owner."""
        device_id = connection.device_id
        async with self._lock:
            if self._connections.get(device_id) is connection and connection.ready_for_dispatch.is_set():
                self._dispatch_pending[device_id] = (connection, True)
                if device_id not in self._dispatch_running:
                    self._dispatch_ready.set()

    async def refresh_scheduled_dispatch(self, candidates: Iterable[GatewayConnection]) -> None:
        async with self._lock:
            scheduled = {
                owner.device_id: owner for owner in candidates
                if self._connections.get(owner.device_id) is owner and owner.ready_for_dispatch.is_set()
                and owner.device_id not in self._dispatch_running
            }
            # A periodic snapshot can remove obsolete scan results. A socket
            # request can also represent operator work, so keep it until served.
            self._dispatch_pending = {
                device_id: (owner, from_socket) for device_id, (owner, from_socket) in self._dispatch_pending.items()
                if from_socket or device_id in scheduled
            }
            for device_id, owner in scheduled.items():
                self._dispatch_pending.setdefault(device_id, (owner, False))
            if scheduled:
                self._dispatch_ready.set()

    async def next_dispatch(self) -> GatewayConnection:
        while True:
            await self._dispatch_ready.wait()
            async with self._lock:
                for device_id, (owner, _) in self._dispatch_pending.items():
                    if device_id not in self._dispatch_running:
                        del self._dispatch_pending[device_id]
                        self._dispatch_running.add(device_id)
                        return owner
                self._dispatch_ready.clear()

    async def finish_dispatch(self, device_id: UUID) -> None:
        async with self._lock:
            self._dispatch_running.remove(device_id)
            if device_id in self._dispatch_pending:
                self._dispatch_ready.set()

    async def shutdown_all(self) -> None:
        async with self._lock:
            connections = tuple(self._connections.values())
            self._connections.clear()
            self._dispatch_pending.clear()
        await asyncio.gather(*(
            self._shutdown(connection, "server_shutdown", 1001)
            for connection in connections
        ))

    async def close_replaced(self, connection: GatewayConnection) -> None:
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
            async with asyncio.timeout(_NOTICE_TIMEOUT_SECONDS):
                await connection.send(notice)
        except Exception as error:
            logger.warning(
                "Gateway socket cleanup reason=%s stage=notice error=%s session_id=%s",
                reason, type(error).__name__, connection.session_id,
            )
        try:
            async with asyncio.timeout(_CLOSE_TIMEOUT_SECONDS):
                await connection.websocket.close(code=close_code)
        except Exception as error:
            logger.warning(
                "Gateway socket cleanup reason=%s stage=close error=%s session_id=%s",
                reason, type(error).__name__, connection.session_id,
            )


__all__ = [
    "ConnectionRegistry",
    "GatewayConnection",
    "GatewayWorkerLease",
    "RegistryCapacityExceeded",
]
