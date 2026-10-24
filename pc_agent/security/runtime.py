"""Replay durable SecurityEvents on WSS until a matching persisted ACK arrives."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from endpoint_contracts.security_events import (
    AgentSecurityEventBatchV1,
    SecurityEventAckV1,
    SecurityEventV1,
)
from endpoint_contracts.telemetry_results import TelemetryResultV1

from .spool import SecurityEventSpool, SecurityEventSpoolError

_LOG = logging.getLogger(__name__)


class SecurityEventTransport(Protocol):
    async def send_security_event_batch(
        self, batch: AgentSecurityEventBatchV1
    ) -> int: ...


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
        self._policy_ready = asyncio.Event()
        self._lock = asyncio.Lock()
        self._inflight: AgentSecurityEventBatchV1 | None = None
        self._inflight_sequences: set[int] = set()
        self._remaining: set[UUID] = set()
        self.acknowledged = asyncio.Event()
        self._opened = False
        self._spool_unavailable = False

    async def open(self) -> None:
        await self._spool.open()
        self._opened = True

    async def available(self) -> bool:
        """Check the actual spool read path before reporting it ready."""
        if self._spool_unavailable:
            return False
        try:
            await self._spool.stats()
        except (OSError, sqlite3.Error, SecurityEventSpoolError):
            return False
        return True

    def begin_connection(self) -> None:
        """Block replay until this WSS session has sent its policy ACK."""
        self._policy_ready.clear()

    def policy_ack_sent(self) -> None:
        self._policy_ready.set()

    async def record(self, event: SecurityEventV1, *, now: datetime | None = None) -> bool:
        accepted = await self._spool.enqueue(event, now=now or datetime.now(UTC))
        if accepted:
            self._wake.set()
        return accepted

    async def receive_ack(self, ack: SecurityEventAckV1) -> bool:
        async with self._lock:
            batch = self._inflight
            if batch is None:
                return False
            try:
                accepted = await self._spool.acknowledge(batch, ack)
            except (OSError, sqlite3.Error, SecurityEventSpoolError):
                self._spool_unavailable = True
                _LOG.warning('SecurityEvent spool acknowledgement unavailable')
                return False
            if not accepted:
                return False
            self._spool_unavailable = False
            self._acked.set()
            self.acknowledged.set()
            return True

    async def receive_result(self, result: TelemetryResultV1) -> bool:
        async with self._lock:
            batch = self._inflight
            if (
                batch is None
                or result.report_kind != "security_event_batch"
                or result.report_id != batch.batch_id
                or result.report_sequence not in self._inflight_sequences
                or not set(result.event_identifiers) <= self._remaining
            ):
                return False
            try:
                accepted = await self._spool.apply_result(batch, result)
            except (OSError, sqlite3.Error, SecurityEventSpoolError):
                self._spool_unavailable = True
                _LOG.warning("SecurityEvent spool disposition unavailable")
                return False
            if not accepted:
                return False
            self._spool_unavailable = False
            if result.disposition != "retry_later":
                self._remaining.difference_update(result.event_identifiers)
                if not self._remaining:
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
                await self._policy_ready.wait()
                try:
                    if not self._opened:
                        await self.open()
                    batch = await self._spool.next_batch(now=now())
                except (OSError, sqlite3.Error, SecurityEventSpoolError, ValueError):
                    if not self._spool_unavailable:
                        _LOG.warning('SecurityEvent spool delivery unavailable')
                    self._spool_unavailable = True
                    await asyncio.sleep(5)
                    continue
                self._spool_unavailable = False
                if batch is None:
                    self._wake.clear()
                    try:
                        await asyncio.wait_for(self._wake.wait(), 5.0)
                    except TimeoutError:
                        pass
                    continue
                async with self._lock:
                    self._inflight = batch
                    self._inflight_sequences.clear()
                    self._remaining = {event.event_identifier for event in batch.events}
                    self._acked.clear()
                while not self._acked.is_set():
                    # The receive loop must wait until the send's sequence is
                    # registered, even when a response races socket draining.
                    async with self._lock:
                        sequence = await transport.send_security_event_batch(batch)
                        if isinstance(sequence, int):
                            # Bound correlation memory over a prolonged outage.
                            self._inflight_sequences.add(sequence)
                            if len(self._inflight_sequences) > 128:
                                self._inflight_sequences.remove(min(self._inflight_sequences))
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
                self._inflight_sequences.clear()
                self._remaining.clear()
                self._acked.clear()
