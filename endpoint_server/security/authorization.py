"""Explicit DLP authority; technical administration never implies DLP access."""

from typing import Annotated

from fastapi import Depends, HTTPException

from endpoint_server.auth.admin_sessions import AdminPrincipal, normalize_admin_scopes, require_admin


async def require_dlp_admin(
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> AdminPrincipal:
    try:
        scopes = normalize_admin_scopes(principal.user.scopes)
    except (TypeError, ValueError):
        raise HTTPException(status_code=403, detail="DLP read permission required") from None
    if principal.user.scopes != scopes or "dlp:read" not in scopes:
        raise HTTPException(status_code=403, detail="DLP read permission required")
    return principal
