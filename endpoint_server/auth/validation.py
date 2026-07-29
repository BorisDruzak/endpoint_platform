"""Credential-safe FastAPI request validation responses."""

from __future__ import annotations

from fastapi import Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse


async def redacting_validation_exception_handler(
    request: Request, error: RequestValidationError
) -> JSONResponse:
    """Return validation details without reflecting attacker-controlled input."""
    del request
    redacted_errors = [
        {key: value for key, value in item.items() if key != "input"}
        for item in error.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": jsonable_encoder(redacted_errors)},
    )
