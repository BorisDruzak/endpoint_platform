"""Service-owned HTTPS recovery; never owns or waits for a WSS connection."""
from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import Awaitable, Callable

import aiohttp

from pc_agent.enrollment_identity import canonical_enrollment_device_id
from pc_agent.transport.base import GatewayCredentialRejected, GatewayTerminalError
from pc_agent.update_schedule import UPDATE_POLL_INTERVAL_SEC

from .online_update_runtime import WindowsOnlineUpdateResult

logger = logging.getLogger(__name__)


def deterministic_delay(device_id: str, purpose: str, attempt: int, base_seconds: float) -> float:
    """Stable UUID/purpose/attempt spread, with absolute recovery retry caps."""
    if not isinstance(device_id, str):
        raise ValueError("Recovery scheduling requires a canonical device UUID")
    canonical_enrollment_device_id(device_id)
    digest = hashlib.sha256(f"{device_id}:{purpose}:{attempt}".encode("ascii")).digest()
    fraction = int.from_bytes(digest[:8], "big") / (1 << 64)
    if purpose == "initial":
        return base_seconds * fraction
    delay = base_seconds * (0.8 + 0.4 * fraction)
    if purpose == "network":
        return min(300.0, delay)
    if purpose in {"scm", "pending"}:
        return min(30.0, delay)
    return delay


class WindowsRecoveryUpdateSupervisor:
    """One device-spread recovery lane for the root service lifetime."""

    def __init__(
        self, *, device_id: str, check: Callable[[], Awaitable[WindowsOnlineUpdateResult]],
        report: Callable[[], Awaitable[bool]], trigger: Callable[[], None],
        publish: Callable[[str], None] = lambda _state: None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        # Fail before producing a task or making any request; never fall back to
        # hardware/user identity or repeatedly reload the enrollment record.
        deterministic_delay(device_id, "initial", 0, 15.0)
        self._device_id = device_id
        self._check = check
        self._report = report
        self._trigger = trigger
        self._publish = publish
        self._sleep = sleep

    async def run(self) -> None:
        network_attempt = scm_attempt = healthy_attempt = pending_attempt = 0
        await self._sleep(deterministic_delay(self._device_id, "initial", 0, 15.0))
        while True:
            self._publish("checking")
            logger.debug("recovery_update_check_started")
            try:
                # Each HTTP request is bounded to 20s; bound report/discovery/
                # download as a whole while preserving parent cancellation.
                async with asyncio.timeout(120):
                    await self._report()
                    result = await self._check()
            except (aiohttp.ClientError, TimeoutError):
                result = WindowsOnlineUpdateResult("unavailable")
            except (GatewayCredentialRejected, GatewayTerminalError):
                raise
            except Exception:
                # An unexpected local exception has not completed safely even
                # if an earlier request succeeded. Preserve conservative retry.
                logger.warning("recovery_update_local_state_failed")
                result = WindowsOnlineUpdateResult("local_state_failed")
            if result.authenticated_check:
                network_attempt = 0
            delay = deterministic_delay(self._device_id, "network", network_attempt,
                min(300.0, 5.0 * 2 ** min(network_attempt, 6)))
            if not result.authenticated_check:
                network_attempt += 1
            if result.status in {"pending", "scheduled", "recovery_pending"}:
                self._publish("pending")
                try:
                    await asyncio.to_thread(self._trigger)
                except Exception:
                    logger.warning("recovery_update_pending_trigger_unavailable")
                    delay = deterministic_delay(self._device_id, "scm", scm_attempt,
                        min(30.0, 2.0 * 2 ** min(scm_attempt, 4)))
                    scm_attempt += 1
                else:
                    scm_attempt = 0
                    logger.info("recovery_update_pending")
                    # SCM start is not acceptance. Keep core/WSS alive until
                    # verified staging and durable offline-worker preparation.
                    delay = deterministic_delay(self._device_id, "pending", pending_attempt, 30.0)
                    pending_attempt += 1
            elif result.status == "idle" and result.authenticated_check:
                delay = deterministic_delay(self._device_id, "healthy", healthy_attempt, UPDATE_POLL_INTERVAL_SEC)
                healthy_attempt += 1
                self._publish("up_to_date")
                logger.debug("recovery_update_check_idle")
            else:
                self._publish("failed" if result.status in {"download_rejected", "local_state_failed", "disk_insufficient"} else "unknown")
                logger.debug("recovery_update_check_unavailable")
            await self._sleep(delay)
