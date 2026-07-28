"""Background-worker entry point reserved for future server jobs."""

from __future__ import annotations

import asyncio

from endpoint_server.config import Settings


async def run_worker(settings: Settings) -> None:
    """Wait safely for cancellation until the worker gains scheduled jobs."""
    del settings
    await asyncio.Event().wait()
