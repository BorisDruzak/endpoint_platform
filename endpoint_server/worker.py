"""Background worker for bounded server maintenance jobs."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any
from uuid import uuid4

from endpoint_server.config import Settings
from endpoint_server.context.retention import retain_context_snapshots
from endpoint_server.context.scheduler import schedule_due_collections
from endpoint_server.db.session import SessionProvider, create_session_provider
from endpoint_server.enrollment.delivery import cleanup_expired_retry_envelopes


async def _run_transactional_job(
    provider: SessionProvider,
    job: Callable[[Any], Awaitable[object]],
) -> None:
    """Commit one maintenance job or roll it back without stopping siblings."""
    try:
        async with provider() as session:
            try:
                await job(session)
                await session.commit()
            except Exception:
                await session.rollback()
    except Exception:
        # The worker is intentionally quiet: no database URLs, credentials or
        # collector payloads may escape a background maintenance failure.
        pass


async def run_worker(
    settings: Settings,
    session_provider: SessionProvider | None = None,
    *,
    cleanup_interval_seconds: float = 60.0,
    context_schedule_interval_seconds: float = 60.0,
    context_retention_interval_seconds: float = 3600.0,
) -> None:
    """Run bounded maintenance jobs with independent transaction failure domains."""
    if (
        cleanup_interval_seconds <= 0
        or context_schedule_interval_seconds <= 0
        or context_retention_interval_seconds <= 0
    ):
        raise ValueError("worker intervals must be positive")
    owns_provider = session_provider is None
    provider = session_provider or create_session_provider(settings.database_url)
    loop = asyncio.get_running_loop()
    last_schedule = loop.time()
    last_retention = loop.time()
    try:
        while True:
            await _run_transactional_job(
                provider,
                lambda session: cleanup_expired_retry_envelopes(
                    session, request_id=f"server_{uuid4().hex}"
                ),
            )
            elapsed = loop.time()
            if elapsed - last_schedule >= context_schedule_interval_seconds:
                await _run_transactional_job(provider, schedule_due_collections)
                last_schedule = elapsed
            if elapsed - last_retention >= context_retention_interval_seconds:
                await _run_transactional_job(provider, retain_context_snapshots)
                last_retention = elapsed
            await asyncio.sleep(cleanup_interval_seconds)
    finally:
        if owns_provider:
            await provider.close()
