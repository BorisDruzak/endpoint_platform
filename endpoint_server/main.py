"""FastAPI application factory for the Endpoint Platform server."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI

from endpoint_server.auth.admin_sessions import router as admin_auth_router
from endpoint_server.config import Settings
from endpoint_server.db.session import SessionProvider, create_session_provider
from endpoint_server.health.routes import router as health_router


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield
    close = getattr(app.state.session_provider, "close", None)
    if close is not None:
        await close()


def create_app(
    settings: Settings, session_provider: SessionProvider | None = None
) -> FastAPI:
    """Create the server application with an injectable session provider."""
    app = FastAPI(title="Endpoint Platform", version="0.0.0", lifespan=_lifespan)
    app.state.settings = settings
    app.state.session_provider = session_provider or create_session_provider(settings.database_url)
    app.include_router(health_router)
    app.include_router(admin_auth_router)
    return app
