"""Service-owned HTTPS recovery; never owns or waits for a WSS connection."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

import aiohttp

from pc_agent.runtime.lifecycle import UpdatePending
from pc_agent.update_schedule import UPDATE_POLL_INTERVAL_SEC

logger = logging.getLogger(__name__)


class WindowsRecoveryUpdateSupervisor:
    """One immediate check and bounded periodic retries for the service lifetime."""

    def __init__(
        self, *, check: Callable[[], Awaitable[str]],
        report: Callable[[], Awaitable[bool]], trigger: Callable[[], None],
        publish: Callable[[str], None] = lambda _state: None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._check = check
        self._report = report
        self._trigger = trigger
        self._publish = publish
        self._sleep = sleep

    async def run(self) -> None:
        while True:
            self._publish("checking")
            logger.debug("recovery_update_check_started")
            try:
                # The HTTP sessions already bound each request to 20 seconds;
                # bound the entire report/discovery/download attempt as well.
                async with asyncio.timeout(120):
                    await self._report()
                    result = await self._check()
            except (aiohttp.ClientError, TimeoutError):
                result = "unavailable"
            if result in {"pending", "scheduled"}:
                self._publish("pending")
                try:
                    await asyncio.to_thread(self._trigger)
                except Exception:
                    logger.warning("recovery_update_pending_trigger_unavailable")
                else:
                    logger.info("recovery_update_pending")
                    # A typed signal is observed by the root before it shuts
                    # down the socket, sensors and executor. No task exits the process.
                    raise UpdatePending()
            elif result == "idle":
                self._publish("up_to_date")
                logger.debug("recovery_update_check_idle")
            else:
                self._publish("failed" if result == "download_rejected" else "unknown")
                logger.debug("recovery_update_check_unavailable")
            await self._sleep(UPDATE_POLL_INTERVAL_SEC)
