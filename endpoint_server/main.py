"""FastAPI application factory for the Endpoint Platform server."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError

from endpoint_server.auth.admin_sessions import router as admin_auth_router
from endpoint_server.auth.validation import redacting_validation_exception_handler
from endpoint_server.config import Settings
from endpoint_server.context.routes import router as context_router
from endpoint_server.db.session import SessionProvider, create_session_provider
from endpoint_server.enrollment.agent_routes import router as enrollment_agent_router
from endpoint_server.enrollment.admin_routes import router as enrollment_admin_router
from endpoint_server.enrollment.provisioning_routes import (
    router as provisioning_router,
)
from endpoint_server.provisioning.admin_routes import (
    router as provisioning_admin_router,
)
from endpoint_server.health.routes import router as health_router
from endpoint_server.gateway.routes import router as gateway_router
from endpoint_server.updates.admin_routes import router as updates_admin_router
from endpoint_server.updates.agent_routes import router as updates_agent_router


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
    app.state.session_provider = session_provider or create_session_provider(
        settings.database_url
    )
    app.add_exception_handler(
        RequestValidationError,
        redacting_validation_exception_handler,
    )
    app.include_router(health_router)
    app.include_router(admin_auth_router)
    app.include_router(enrollment_admin_router)
    app.include_router(enrollment_agent_router)
    app.include_router(gateway_router)
    app.include_router(provisioning_router)
    app.include_router(provisioning_admin_router)
    app.include_router(updates_admin_router)
    app.include_router(updates_agent_router)
    app.include_router(context_router)
    return app
