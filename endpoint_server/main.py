"""FastAPI application factory for the Endpoint Platform server."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint

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
from endpoint_server.http.correlation import (
    is_operation_api_request,
    is_safe_correlation_id,
)
from endpoint_server.operations.routes import router as operations_router
from endpoint_server.modules.routes import router as modules_router
from endpoint_server.gateway.routes import router as gateway_router
from endpoint_server.gateway.connection_registry import (
    ConnectionRegistry,
    GatewayWorkerLease,
)
from endpoint_server.gateway.ws_routes import (
    assert_single_gateway_worker,
    router as gateway_ws_router,
)
from endpoint_server.updates.admin_routes import router as updates_admin_router
from endpoint_server.updates.agent_routes import router as updates_agent_router


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.gateway_worker_lease.acquire()
    try:
        yield
    finally:
        try:
            await app.state.gateway_connection_registry.shutdown_all()
            close = getattr(app.state.session_provider, "close", None)
            if close is not None:
                await close()
        finally:
            app.state.gateway_worker_lease.release()


def create_app(
    settings: Settings, session_provider: SessionProvider | None = None
) -> FastAPI:
    """Create the server application with an injectable session provider."""
    assert_single_gateway_worker()
    app = FastAPI(title="Endpoint Platform", version="0.0.0", lifespan=_lifespan)
    app.state.settings = settings
    app.state.session_provider = session_provider or create_session_provider(
        settings.database_url
    )
    app.state.gateway_connection_registry = ConnectionRegistry()
    app.state.gateway_worker_lease = GatewayWorkerLease(settings.artifact_root)
    app.add_exception_handler(
        RequestValidationError,
        redacting_validation_exception_handler,
    )

    @app.middleware("http")
    async def echo_operation_correlation(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Keep the service tracing header out of JSON success and error bodies."""
        correlation_id = request.headers.get("X-Correlation-ID")
        if (
            is_operation_api_request(request.method, request.url.path)
            and correlation_id is not None
            and not is_safe_correlation_id(correlation_id)
        ):
            return JSONResponse(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                content={"detail": {"code": "endpoint_operation_invalid_correlation_id"}},
            )

        response = await call_next(request)
        if (
            is_operation_api_request(request.method, request.url.path)
            and correlation_id is not None
            and is_safe_correlation_id(correlation_id)
        ):
            response.headers["X-Correlation-ID"] = correlation_id
        return response

    app.include_router(health_router)
    app.include_router(admin_auth_router)
    app.include_router(enrollment_admin_router)
    app.include_router(enrollment_agent_router)
    app.include_router(gateway_router)
    app.include_router(gateway_ws_router)
    app.include_router(provisioning_router)
    app.include_router(provisioning_admin_router)
    app.include_router(updates_admin_router)
    app.include_router(updates_agent_router)
    app.include_router(context_router)
    if settings.endpoint_operations_api_enabled:
        app.include_router(operations_router)
    if settings.endpoint_module_platform_enabled:
        app.include_router(modules_router)
    return app
