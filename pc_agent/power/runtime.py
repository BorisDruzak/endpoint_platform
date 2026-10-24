"""Collect offline and replay only on negotiated WSS, independently of policy."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from endpoint_contracts.power_events import POWER_EVENTS_FEATURE

_LOG = logging.getLogger(__name__)


class PowerEventRuntime:
    def __init__(
        self,
        spool,
        source,
        *,
        poll_seconds=5,
        ack_timeout_seconds=30,
        collect_timeout=10,
    ):
        self.spool, self.source = spool, source
        self.poll_seconds, self.ack_timeout_seconds, self.collect_timeout = (
            poll_seconds,
            ack_timeout_seconds,
            collect_timeout,
        )
        self._opened = False
        self._open_lock = asyncio.Lock()
        self._acked = asyncio.Event()
        self._wake = asyncio.Event()
        self._inflight = None
        self._ack_lock = asyncio.Lock()
        self._read_task = None

    async def _open(self):
        async with self._open_lock:
            if not self._opened:
                await self.spool.open()
                self._opened = True

    async def record(self, event):
        await self._open()
        await self.spool.record(event, now=datetime.now(UTC))
        self._wake.set()

    async def collect_once(self, *, now=None):
        now = now or datetime.now(UTC)
        try:
            await self._open()
            checkpoint = await self.spool.checkpoint()
            if self._read_task is None:
                self._read_task = asyncio.create_task(
                    self.source.read_page(checkpoint, now=now)
                )
            async with asyncio.timeout(self.collect_timeout):
                # A timed-out native worker is retained rather than spawning
                # another possibly blocked OS call every poll.
                page = await asyncio.shield(self._read_task)
            self._read_task = None
            await self.spool.commit_page(page, now=now)
            self._wake.set()
            return bool(page.events)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - owning optional native boundary; cancellation propagates
            if self._read_task is not None and self._read_task.done():
                self._read_task = None
            # This owner handles optional source/queue faults only. Transport
            # exceptions are never caught by collection or disposition code.
            _LOG.warning("native power collection unavailable")
            try:
                await self.spool.set_unavailable(source=self.source.source, now=now)
                self._wake.set()
            except Exception:  # noqa: BLE001 - owning optional native boundary; cancellation propagates
                _LOG.warning("native power diagnostics persistence unavailable")
            return False

    async def collect_forever(self):
        try:
            while True:
                has_events = await self.collect_once()
                await asyncio.sleep(0.05 if has_events else self.poll_seconds)
        finally:
            if self._read_task is not None:
                self._read_task.cancel()
                await asyncio.gather(self._read_task, return_exceptions=True)
                self._read_task = None

    async def notifications_forever(self):
        while True:
            try:
                await self.source.notifications(self.record)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - owning optional native boundary; cancellation propagates
                _LOG.warning("native power notifications unavailable")
            await asyncio.sleep(5)

    async def receive_ack(self, ack):
        async with self._ack_lock:
            if self._inflight is None:
                return False
            try:
                matched = await self.spool.acknowledge(self._inflight, ack)
            except Exception:  # noqa: BLE001 - owning optional native boundary; cancellation propagates
                _LOG.warning("native power acknowledgement unavailable")
                return False
            if matched:
                self._last_results = ack.results
                self._acked.set()
            return matched

    async def send_forever(self, transport, *, now=lambda: datetime.now(UTC)):
        try:
            while True:
                if POWER_EVENTS_FEATURE not in transport.protocol_features:
                    await asyncio.sleep(5)
                    continue
                try:
                    await self._open()
                    batch = await self.spool.next_batch(now=now())
                except Exception:  # noqa: BLE001 - owning optional native boundary; cancellation propagates
                    _LOG.warning("native power queue delivery unavailable")
                    await asyncio.sleep(5)
                    continue
                if batch is None:
                    await asyncio.sleep(1)
                    continue
                async with self._ack_lock:
                    self._inflight = batch
                    self._acked.clear()
                while not self._acked.is_set():
                    # Real transport/auth/framing failures propagate normally.
                    await transport.send_power_event_batch(batch)
                    try:
                        await asyncio.wait_for(
                            self._acked.wait(), self.ack_timeout_seconds
                        )
                    except TimeoutError:
                        pass
                async with self._ack_lock:
                    self._inflight = None
                # retry_later remains durable, but never spins a hot poison loop.
                if any(
                    r.disposition == "retry_later"
                    for r in getattr(self, "_last_results", ())
                ):
                    await asyncio.sleep(5)
                elif not batch.events:
                    self._wake.clear()
                    try:
                        await asyncio.wait_for(self._wake.wait(), 30)
                    except TimeoutError:
                        pass
        finally:
            async with self._ack_lock:
                self._inflight = None
