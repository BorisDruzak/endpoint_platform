"""Replay durable SecurityEvents on WSS until a matching persisted ACK arrives."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from endpoint_contracts.security_events import (
    AgentSecurityEventBatchV1,
    SecurityEventAckV1,
    SecurityEventV1,
)

from .spool import SecurityEventSpool


class SecurityEventTransport(Protocol):
    async def send_security_event_batch(
        self, batch: AgentSecurityEventBatchV1
    ) -> None: ...


class SecurityEventRuntime:
    """One in-flight batch per WSS session, with stable event IDs on retry."""

    def __init__(
        self,
        spool: SecurityEventSpool,
        *,
        ack_timeout_seconds: float = 30.0,
    ) -> None:
        if ack_timeout_seconds <= 0:
            raise ValueError("ACK timeout must be positive")
        self._spool = spool
        self._ack_timeout_seconds = ack_timeout_seconds
        self._wake = asyncio.Event()
        self._acked = asyncio.Event()
        self._lock = asyncio.Lock()
        self._inflight: AgentSecurityEventBatchV1 | None = None
        self.acknowledged = asyncio.Event()

    async def open(self) -> None:
        await self._spool.open()

    async def record(self, event: SecurityEventV1, *, now: datetime | None = None) -> bool:
        accepted = await self._spool.enqueue(event, now=now or datetime.now(UTC))
        if accepted:
            self._wake.set()
        return accepted

    async def receive_ack(self, ack: SecurityEventAckV1) -> bool:
        async with self._lock:
            batch = self._inflight
            if batch is None or not await self._spool.acknowledge(batch, ack):
                return False
            self._acked.set()
            self.acknowledged.set()
            return True

    async def send_forever(
        self,
        transport: SecurityEventTransport,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        try:
            while True:
                batch = await self._spool.next_batch(now=now())
                if batch is None:
                    self._wake.clear()
                    try:
                        await asyncio.wait_for(self._wake.wait(), 5.0)
                    except TimeoutError:
                        pass
                    continue
                async with self._lock:
                    self._inflight = batch
                    self._acked.clear()
                while not self._acked.is_set():
                    await transport.send_security_event_batch(batch)
                    try:
                        await asyncio.wait_for(
                            self._acked.wait(), self._ack_timeout_seconds
                        )
                    except TimeoutError:
                        pass
                async with self._lock:
                    self._inflight = None
        finally:
            async with self._lock:
                self._inflight = None
                self._acked.clear()
