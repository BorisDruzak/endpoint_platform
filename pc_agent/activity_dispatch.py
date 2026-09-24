"""Bounded in-memory handoff from the Windows sensor pipe to Gateway WSS."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Awaitable, Callable
from threading import Lock
from typing import Protocol

from endpoint_contracts.activity import ActivityObservationV1


class ActivityQueueFull(RuntimeError):
    """The local activity handoff cannot accept another observation."""


class ActivitySender(Protocol):
    async def send_activity_observation(self, observation: ActivityObservationV1) -> None: ...


class ActivityDispatch:
    """Keep queued observations across WSS reconnect without unbounded growth."""

    def __init__(self, *, max_pending: int = 256) -> None:
        if not 1 <= max_pending <= 1024:
            raise ValueError("invalid activity queue bound")
        self._max_pending = max_pending
        self._pending: deque[ActivityObservationV1] = deque()
        self._lock = Lock()

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def enqueue(self, observation: ActivityObservationV1) -> None:
        if not isinstance(observation, ActivityObservationV1):
            raise TypeError("activity handoff requires a typed observation")
        with self._lock:
            if len(self._pending) >= self._max_pending:
                raise ActivityQueueFull("activity queue is full")
            self._pending.append(observation)

    async def flush_one(self, transport: ActivitySender) -> bool:
        with self._lock:
            if not self._pending:
                return False
            observation = self._pending[0]
        await transport.send_activity_observation(observation)
        with self._lock:
            if self._pending and self._pending[0].observation_id == observation.observation_id:
                self._pending.popleft()
        return True

    async def send_forever(
        self,
        transport: ActivitySender,
        *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        while True:
            if not await self.flush_one(transport):
                await sleep(0.25)
