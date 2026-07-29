"""Background worker for bounded server maintenance jobs."""

from __future__ import annotations

import asyncio
from uuid import uuid4

from endpoint_server.config import Settings
from endpoint_server.db.session import SessionProvider, create_session_provider
from endpoint_server.enrollment.delivery import cleanup_expired_retry_envelopes


async def run_worker(
    settings: Settings,
    session_provider: SessionProvider | None = None,
    *,
    cleanup_interval_seconds: float = 60.0,
) -> None:
    """Run one transactional expired-envelope cleanup batch per interval."""
    if cleanup_interval_seconds <= 0:
        raise ValueError("cleanup interval must be positive")
    owns_provider = session_provider is None
    provider = session_provider or create_session_provider(settings.database_url)
    try:
        while True:
            try:
                async with provider() as session:
                    try:
                        await cleanup_expired_retry_envelopes(
                            session,
                            request_id=f"server_{uuid4().hex}",
                        )
                        await session.commit()
                    except Exception:
                        await session.rollback()
            except Exception:
                pass
            await asyncio.sleep(cleanup_interval_seconds)
    finally:
        if owns_provider:
            await provider.close()
