"""Service-owned HTTPS recovery; never owns or waits for a WSS connection."""
from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable

import aiohttp

from pc_agent.transport.base import GatewayCredentialRejected, GatewayTerminalError
from pc_agent.update_schedule import UPDATE_POLL_INTERVAL_SEC

logger = logging.getLogger(__name__)


class WindowsRecoveryUpdateSupervisor:
    """One immediate check and bounded periodic retries for the service lifetime."""

    def __init__(
        self, *, check: Callable[[], Awaitable[str]],
        report: Callable[[], Awaitable[bool]], trigger: Callable[[], None],
        publish: Callable[[str], None] = lambda _state: None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        random_sample: Callable[[], float] = random.random,
    ) -> None:
        self._check = check
        self._report = report
        self._trigger = trigger
        self._publish = publish
        self._sleep = sleep
        self._random_sample = random_sample

    async def run(self) -> None:
        network_delay = 5.0
        scm_delay = 2.0
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
            except (GatewayCredentialRejected, GatewayTerminalError):
                raise
            except Exception:
                # Unsafe local journals/paths disable only the update lane.
                # Never expose their contents or take down healthy WSS.
                logger.warning("recovery_update_local_state_failed")
                result = "local_state_failed"
            delay = min(300.0, network_delay * self._jitter())
            network_delay = min(300.0, network_delay * 2)
            if result in {"pending", "scheduled"}:
                self._publish("pending")
                try:
                    await asyncio.to_thread(self._trigger)
                except Exception:
                    logger.warning("recovery_update_pending_trigger_unavailable")
                    delay = min(30.0, scm_delay * self._jitter())
                    scm_delay = min(30.0, scm_delay * 2)
                else:
                    logger.info("recovery_update_pending")
                    # SCM start is not acceptance. Keep this core/WSS alive:
                    # only the worker may stop it after verified staging and
                    # durable preparation. Disk rejection needs a live retry owner.
                    delay = 30.0 * self._jitter()
            elif result == "idle":
                network_delay = 5.0
                scm_delay = 2.0
                delay = UPDATE_POLL_INTERVAL_SEC * self._jitter()
                self._publish("up_to_date")
                logger.debug("recovery_update_check_idle")
            else:
                self._publish("failed" if result in {"download_rejected", "local_state_failed", "disk_insufficient"} else "unknown")
                logger.debug("recovery_update_check_unavailable")
            await self._sleep(delay)

    def _jitter(self) -> float:
        return min(1.2, max(0.8, 0.8 + 0.4 * self._random_sample()))
