"""Session-protected Console shell and safe browser bootstrap."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from endpoint_server.auth.admin_sessions import (
    ADMIN_SESSION_COOKIE,
    AdminPrincipal,
    normalize_admin_scopes,
    require_admin,
)
from endpoint_server.auth.csrf import csrf_token_for_session


ASSET_ROOT = Path(__file__).resolve().parents[2] / "webapp" / "dist"
router = APIRouter(tags=["admin-console"])
_INDEX_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    ),
}


class ConsoleSessionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    username: str
    scopes: list[str]
    csrf_token: str


def install_console_assets(app: FastAPI) -> None:
    """Register only public, built assets; page and API routes remain protected."""
    app.mount(
        "/admin/assets",
        StaticFiles(directory=ASSET_ROOT / "assets", check_dir=False),
        name="admin-console-assets",
    )


def _index() -> FileResponse:
    path = ASSET_ROOT / "index.html"
    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Console bundle is not installed",
        )
    return FileResponse(path, media_type="text/html", headers=_INDEX_HEADERS)


@router.get("/api/admin/console/session", response_model=ConsoleSessionResponse)
async def console_session(
    request: Request,
    response: Response,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> ConsoleSessionResponse:
    """Return the interactive user's safe identity and session-bound CSRF token."""
    session_token = request.cookies.get(ADMIN_SESSION_COOKIE, "")
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    try:
        scopes = normalize_admin_scopes(principal.user.scopes)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN) from error
    return ConsoleSessionResponse(
        username=principal.user.username,
        scopes=scopes,
        csrf_token=csrf_token_for_session(
            session_token, request.app.state.settings.session_secret
        ),
    )


@router.get("/admin/login", include_in_schema=False)
async def console_login_page() -> FileResponse:
    return _index()


@router.get("/admin", include_in_schema=False)
async def console_dashboard_page(
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> FileResponse:
    return _index()


@router.get("/admin/{path:path}", include_in_schema=False)
async def console_deep_link_page(
    path: str,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> FileResponse:
    if path.startswith("assets/"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return _index()
