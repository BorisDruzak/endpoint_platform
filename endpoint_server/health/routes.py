"""Database-backed service-health route."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


router = APIRouter()


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Yield the request's injected database session."""
    async with request.app.state.session_provider() as session:
        yield session


@router.get("/healthz")
async def healthz(session: Annotated[AsyncSession, Depends(get_session)]) -> JSONResponse:
    """Report service availability without exposing database errors."""
    try:
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
