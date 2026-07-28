"""Async SQLAlchemy session provider construction."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine


SessionProvider = Callable[[], AbstractAsyncContextManager[AsyncSession]]


class AsyncSessionProvider:
    """Own one engine and produce request-scoped asynchronous sessions."""

    def __init__(self, database_url: str) -> None:
        self.engine: AsyncEngine = create_async_engine(database_url, pool_pre_ping=True)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

    @asynccontextmanager
    async def __call__(self) -> AsyncIterator[AsyncSession]:
        async with self.session_factory() as session:
            yield session

    async def close(self) -> None:
        """Release pooled connections during application shutdown."""
        await self.engine.dispose()


def create_session_provider(database_url: str) -> AsyncSessionProvider:
    """Create the application's default request-scoped session provider."""
    return AsyncSessionProvider(database_url)
