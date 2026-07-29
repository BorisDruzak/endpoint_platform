"""Database-backed service-health route."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from endpoint_server.db.session import SessionProvider


router = APIRouter()


def get_session_provider(request: Request) -> SessionProvider:
    """Return the request's injected session provider without opening a session."""
    return request.app.state.session_provider


@router.get("/healthz")
async def healthz(
    session_provider: Annotated[SessionProvider, Depends(get_session_provider)],
) -> JSONResponse:
    """Report service availability without exposing database errors."""
    try:
        async with session_provider() as session:
            await session.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unavailable",
                "service": "endpoint-platform",
                "database": "unavailable",
                "version": "0.0.0",
            },
        )

    return JSONResponse(
        content={
            "status": "ok",
            "service": "endpoint-platform",
            "database": "ok",
            "version": "0.0.0",
        }
    )
